//! Turning an upload into the picture auth stores: decoded under limits, upright,
//! cropped to a square, and encoded again as a JPEG. Auth never keeps or serves
//! the uploaded bytes, so a stored picture carries no metadata, such as a photo's
//! location, and is always an image auth produced.

use super::PictureError;
use image::{
    DynamicImage, ExtendedColorType, ImageDecoder, ImageError, ImageFormat, ImageReader, Limits,
    RgbImage, codecs::jpeg::JpegEncoder, imageops::FilterType,
};
use serde::Deserialize;
use std::io::Cursor;
use tokio::sync::{Semaphore, SemaphorePermit};

/// The largest upload accepted: a phone's photo fits.
pub(crate) const MAX_UPLOAD_BYTES: usize = 10 * 1024 * 1024;
/// The largest width or height an upload may declare.
const MAX_SIDE: u32 = 8192;
/// The most pixels an upload may declare, checked from its header before it is
/// decoded: a phone's 12- or 24-megapixel photo fits.
const MAX_PIXELS: u64 = 24_000_000;
/// What decoding one upload may allocate: its decoded image, checked before it is
/// decoded, and, separately, the decoder's own buffers. An RGBA image of
/// [`MAX_PIXELS`] fits; a 16-bit one does not.
const MAX_ALLOC: u64 = 96 * 1024 * 1024;
/// The stored picture's width and height.
pub(crate) const SIDE: u32 = 512;
/// The largest stored picture, which the column's check also enforces.
const MAX_STORED_BYTES: usize = 128 * 1024;
/// The JPEG qualities tried in turn, until one fits [`MAX_STORED_BYTES`]. Most
/// photos fit the first, at around 50 KiB.
const QUALITIES: [u8; 3] = [85, 75, 65];

/// Uploads admitted at once on this replica: one, which holds the [`DecodeTurn`]
/// from before any of its bytes are read until it is decoded. Decoding allocates
/// up to [`MAX_ALLOC`] for the image and as much for the decoder, and turning a
/// photo upright and cropping it copy it once each, so the replica holds at most
/// one upload of [`MAX_UPLOAD_BYTES`] and about 400 MiB to decode it. Nothing
/// waits for the turn: uploads are rare, so one that finds it taken is refused.
/// The request's deadline bounds how long a slowly sent upload holds it.
static DECODING: Semaphore = Semaphore::const_new(1);

/// This replica's turn to take an upload and decode it, of which [`DECODING`] has
/// one. An upload takes it before reading any of its bytes, and
/// [`Jpeg::encode`] needs it, so no upload is buffered while another is.
pub(crate) struct DecodeTurn {
    /// Gives the turn back when dropped.
    _permit: SemaphorePermit<'static>,
}

impl DecodeTurn {
    /// Takes the turn, without waiting.
    ///
    /// # Errors
    ///
    /// [`PictureError::Busy`] while another upload holds it.
    pub(crate) fn take() -> Result<Self, PictureError> {
        Ok(Self {
            _permit: DECODING.try_acquire()?,
        })
    }
}

/// The square of an upload to keep, in the upload's pixels once upright: its
/// top-left corner and its side, as the owner chose it. A square that leaves the
/// image is moved and shrunk until it fits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct Crop {
    /// Its left edge.
    pub(crate) x: u32,
    /// Its top edge.
    pub(crate) y: u32,
    /// Its side.
    pub(crate) size: u32,
}

impl Crop {
    /// The largest square centred in an image `width` by `height`, which an
    /// upload keeps when its owner chose none.
    const fn centred(width: u32, height: u32) -> Self {
        let size = if width < height { width } else { height };
        Self {
            x: (width - size) / 2,
            y: (height - size) / 2,
            size,
        }
    }

    /// This square moved and shrunk into an image `width` by `height`.
    fn within(self, width: u32, height: u32) -> Self {
        let size = self.size.clamp(1, width.min(height));
        Self {
            x: self.x.min(width - size),
            y: self.y.min(height - size),
            size,
        }
    }
}

/// The square to keep as an upload names it, all three of its numbers or none:
/// the API's query (`?x=…&y=…&size=…`) or the profile page's fields.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct CropFields {
    /// The left edge.
    pub(crate) x: Option<u32>,
    /// The top edge.
    pub(crate) y: Option<u32>,
    /// The side.
    pub(crate) size: Option<u32>,
}

impl CropFields {
    /// The square, or `None` when none of its numbers is given.
    ///
    /// # Errors
    ///
    /// [`PictureError::PartialCrop`] when only some are.
    pub(crate) fn crop(self) -> Result<Option<Crop>, PictureError> {
        match (self.x, self.y, self.size) {
            (Some(x), Some(y), Some(size)) => Ok(Some(Crop { x, y, size })),
            (None, None, None) => Ok(None),
            _ => Err(PictureError::PartialCrop),
        }
    }
}

/// A picture as auth stores and serves it: a [`SIDE`]-pixel square JPEG of at
/// most [`MAX_STORED_BYTES`], which only [`Self::encode`] makes.
pub(crate) struct Jpeg(Vec<u8>);

impl Jpeg {
    /// Encodes `upload`, a PNG, JPEG or GIF (its first frame), recognised by its
    /// content, keeping its `crop`, or its centred square, on the blocking pool,
    /// in the `turn` it was read in. The blocking task holds the turn, so a request
    /// that is cancelled meanwhile gives it back only once its decoding is done.
    pub(crate) async fn encode(
        turn: DecodeTurn,
        upload: Vec<u8>,
        crop: Option<Crop>,
    ) -> Result<Self, PictureError> {
        if upload.len() > MAX_UPLOAD_BYTES {
            return Err(PictureError::TooLarge);
        }
        tokio::task::spawn_blocking(move || {
            let encoded = Self::from_upload(&upload, crop);
            drop(turn);
            encoded
        })
        .await?
    }

    /// The stored bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decodes `upload`, makes it upright, crops it to `crop`, or its centred
    /// square, scales that to [`SIDE`] pixels and encodes it.
    ///
    /// WebP is refused: its decoder decodes a frame larger than the canvas its
    /// header declares before it checks the two match, so the limits here would
    /// not bound it.
    fn from_upload(upload: &[u8], crop: Option<Crop>) -> Result<Self, PictureError> {
        let mut reader = ImageReader::new(Cursor::new(upload))
            .with_guessed_format()
            .map_err(|error| PictureError::Unreadable(error.into()))?;
        match reader.format() {
            Some(ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif) => {}
            _ => return Err(PictureError::Unsupported),
        }
        let mut limits = Limits::default();
        limits.max_image_width = Some(MAX_SIDE);
        limits.max_image_height = Some(MAX_SIDE);
        limits.max_alloc = Some(MAX_ALLOC);
        reader.limits(limits);
        let mut decoder = reader.into_decoder().map_err(PictureError::decoding)?;
        let (width, height) = decoder.dimensions();
        // `from_decoder` allocates the decoded image without charging the limits.
        // An image with a side of no pixels has no square to keep.
        if width == 0
            || height == 0
            || u64::from(width) * u64::from(height) > MAX_PIXELS
            || decoder.total_bytes() > MAX_ALLOC
        {
            return Err(PictureError::Dimensions);
        }
        let orientation = decoder.orientation().map_err(PictureError::decoding)?;
        let square = {
            let mut image = DynamicImage::from_decoder(decoder).map_err(PictureError::decoding)?;
            // Photos are often stored sideways, with a tag saying how to turn them,
            // which re-encoding drops.
            image.apply_orientation(orientation);
            // Cropped before it is scaled: scaling a long strip to fill the square
            // first would allocate an image as many times wider.
            let (width, height) = (image.width(), image.height());
            let Crop { x, y, size } = crop.map_or_else(
                || Crop::centred(width, height),
                |crop| crop.within(width, height),
            );
            image.crop_imm(x, y, size, size)
        };
        let square = square.resize_exact(SIDE, SIDE, FilterType::Lanczos3);
        Self::compress(&Self::flatten(&square))
    }

    /// `image` without transparency, which JPEG cannot store: transparent pixels
    /// show white, as on a page.
    fn flatten(image: &DynamicImage) -> RgbImage {
        if !image.color().has_alpha() {
            return image.to_rgb8();
        }
        let rgba = image.to_rgba8();
        RgbImage::from_fn(rgba.width(), rgba.height(), |x, y| {
            let [red, green, blue, alpha] = rgba.get_pixel(x, y).0;
            let over_white = |channel: u8| {
                let (channel, alpha) = (u16::from(channel), u16::from(alpha));
                // At most 255, so it fits a byte.
                u8::try_from((channel * alpha + 255 * (255 - alpha)) / 255).unwrap_or(u8::MAX)
            };
            image::Rgb([over_white(red), over_white(green), over_white(blue)])
        })
    }

    /// Encodes `image` at the best of [`QUALITIES`] that fits [`MAX_STORED_BYTES`].
    fn compress(image: &RgbImage) -> Result<Self, PictureError> {
        for quality in QUALITIES {
            let mut jpeg = Vec::new();
            JpegEncoder::new_with_quality(&mut jpeg, quality)
                .encode(
                    image,
                    image.width(),
                    image.height(),
                    ExtendedColorType::Rgb8,
                )
                .map_err(PictureError::Encoding)?;
            if jpeg.len() <= MAX_STORED_BYTES {
                return Ok(Self(jpeg));
            }
        }
        Err(PictureError::TooDetailed)
    }
}

impl PictureError {
    /// Why an upload could not be decoded: past a limit, or not a readable image.
    fn decoding(error: ImageError) -> Self {
        match error {
            ImageError::Limits(_) => Self::Dimensions,
            ImageError::Unsupported(_) => Self::Unsupported,
            error => Self::Unreadable(error),
        }
    }
}

#[cfg(test)]
mod tests;
