//! Turning an upload into the picture auth stores: decoded under limits, upright,
//! cropped to a square, and encoded again as a JPEG. Auth never keeps or serves
//! the uploaded bytes, so a stored picture carries no metadata, such as a photo's
//! location, and is always an image auth produced.

use super::PictureError;
use image::{
    DynamicImage, ExtendedColorType, ImageDecoder, ImageError, ImageFormat, ImageReader, Limits,
    RgbImage, codecs::jpeg::JpegEncoder, imageops::FilterType,
};
use std::io::Cursor;
use tokio::sync::Semaphore;

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

/// Uploads decoded at once on this replica: one. Decoding allocates up to
/// [`MAX_ALLOC`] for the image and as much for the decoder, and turning a photo
/// upright and cropping it copy it once each, so one upload takes about 400 MiB at
/// most; the rest wait their turn. Uploads are rare.
static DECODING: Semaphore = Semaphore::const_new(1);

/// A picture as auth stores and serves it: a [`SIDE`]-pixel square JPEG of at
/// most [`MAX_STORED_BYTES`], which only [`Self::encode`] makes.
pub(crate) struct Jpeg(Vec<u8>);

impl Jpeg {
    /// Encodes `upload`, a PNG, JPEG or GIF (its first frame), recognised by its
    /// content, on the blocking pool, waiting for a turn among [`DECODING`]. The
    /// blocking task holds the turn, so a request that is cancelled meanwhile
    /// gives it back only once its decoding is done.
    pub(crate) async fn encode(upload: Vec<u8>) -> Result<Self, PictureError> {
        if upload.len() > MAX_UPLOAD_BYTES {
            return Err(PictureError::TooLarge);
        }
        let turn = DECODING.acquire().await.map_err(PictureError::Busy)?;
        tokio::task::spawn_blocking(move || {
            let encoded = Self::from_upload(&upload);
            drop(turn);
            encoded
        })
        .await?
    }

    /// The stored bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decodes `upload`, makes it upright, crops it to its centred square, scales
    /// that to [`SIDE`] pixels and encodes it.
    ///
    /// WebP is refused: its decoder decodes a frame larger than the canvas its
    /// header declares before it checks the two match, so the limits here would
    /// not bound it.
    fn from_upload(upload: &[u8]) -> Result<Self, PictureError> {
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
        if u64::from(width) * u64::from(height) > MAX_PIXELS || decoder.total_bytes() > MAX_ALLOC {
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
            let side = image.width().min(image.height());
            image.crop_imm(
                (image.width() - side) / 2,
                (image.height() - side) / 2,
                side,
                side,
            )
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
