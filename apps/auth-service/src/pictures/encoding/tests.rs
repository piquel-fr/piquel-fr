//! What an upload becomes, and which uploads are refused.
use super::{Crop, Jpeg, MAX_STORED_BYTES, SIDE};
use crate::pictures::PictureError;
use image::{
    DynamicImage, GrayImage, ImageEncoder, ImageFormat, Rgb, RgbImage, Rgba, RgbaImage,
    codecs::jpeg::JpegEncoder,
};
use std::io::Cursor;

/// `image` written as `format`.
fn encoded(image: &DynamicImage, format: ImageFormat) -> Vec<u8> {
    let mut bytes = Cursor::new(Vec::new());
    image.write_to(&mut bytes, format).expect("encode fixture");
    bytes.into_inner()
}

/// The stored picture `upload` becomes, decoded back.
fn stored(upload: &[u8]) -> (Vec<u8>, RgbImage) {
    cropped(upload, None)
}

/// The stored picture `upload` becomes, keeping `crop`, decoded back.
fn cropped(upload: &[u8], crop: Option<Crop>) -> (Vec<u8>, RgbImage) {
    let jpeg = Jpeg::from_upload(upload, crop).expect("stored picture").0;
    let image = image::load_from_memory_with_format(&jpeg, ImageFormat::Jpeg)
        .expect("a JPEG")
        .to_rgb8();
    (jpeg, image)
}

/// Whether `pixel` is close to `expected`, as JPEG keeps colours.
fn near(pixel: Rgb<u8>, expected: [u8; 3]) -> bool {
    pixel
        .0
        .iter()
        .zip(expected)
        .all(|(&got, want)| got.abs_diff(want) < 24)
}

/// A wide transparent PNG becomes a square JPEG of the stored size, its centre
/// kept and its transparency white.
#[test]
fn a_transparent_png_becomes_a_white_backed_square() {
    // Transparent, with an opaque red block in the middle third.
    let image = RgbaImage::from_fn(1200, 600, |x, _| {
        if (400..800).contains(&x) {
            Rgba([255, 0, 0, 255])
        } else {
            Rgba([0, 0, 0, 0])
        }
    });
    let (jpeg, image) = stored(&encoded(&image.into(), ImageFormat::Png));
    assert!(jpeg.len() <= MAX_STORED_BYTES, "{} bytes", jpeg.len());
    assert_eq!(image.dimensions(), (SIDE, SIDE));
    assert!(near(*image.get_pixel(SIDE / 2, SIDE / 2), [255, 0, 0]));
    assert!(near(*image.get_pixel(5, SIDE / 2), [255, 255, 255]));
}

/// A photo stored sideways, with an EXIF tag saying to turn it, comes out upright,
/// and the stored picture carries no EXIF.
#[test]
fn a_rotated_photo_comes_out_upright_without_metadata() {
    // Left half red, right half blue, as stored; turned a quarter clockwise, red is
    // on top.
    let image = RgbImage::from_fn(400, 200, |x, _| {
        if x < 200 {
            Rgb([255, 0, 0])
        } else {
            Rgb([0, 0, 255])
        }
    });
    // A big-endian TIFF block with one entry: orientation (0x0112), a SHORT, 6.
    let exif = [
        b'M', b'M', 0, 42, 0, 0, 0, 8, 0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0,
    ];
    let mut upload = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut upload, 90);
    encoder.set_exif_metadata(exif.to_vec()).expect("EXIF");
    encoder
        .write_image(&image, 400, 200, image::ExtendedColorType::Rgb8)
        .expect("fixture");
    assert!(upload.windows(4).any(|window| window == b"Exif"));

    let (jpeg, image) = stored(&upload);
    assert!(near(*image.get_pixel(SIDE / 2, 10), [255, 0, 0]));
    assert!(near(*image.get_pixel(SIDE / 2, SIDE - 10), [0, 0, 255]));
    assert!(
        !jpeg.windows(4).any(|window| window == b"Exif"),
        "EXIF kept"
    );
}

/// The square the owner chose is the one kept, and one that leaves the image is
/// moved and shrunk until it fits.
#[test]
fn a_chosen_square_is_kept_and_fitted_into_the_image() {
    // Red, green, blue and white quarters, from the top left.
    let image = RgbImage::from_fn(400, 400, |x, y| match (x < 200, y < 200) {
        (true, true) => Rgb([255, 0, 0]),
        (false, true) => Rgb([0, 255, 0]),
        (true, false) => Rgb([0, 0, 255]),
        (false, false) => Rgb([255, 255, 255]),
    });
    let upload = encoded(&image.into(), ImageFormat::Png);
    let top_right = Crop {
        x: 200,
        y: 0,
        size: 200,
    };
    let (_, image) = cropped(&upload, Some(top_right));
    assert!(near(*image.get_pixel(SIDE / 2, SIDE / 2), [0, 255, 0]));

    let beyond = Crop {
        x: 1000,
        y: 1000,
        size: 10_000,
    };
    let (_, image) = cropped(&upload, Some(beyond));
    assert!(near(*image.get_pixel(10, 10), [255, 0, 0]));
    assert!(near(
        *image.get_pixel(SIDE - 10, SIDE - 10),
        [255, 255, 255]
    ));
}

/// Text, SVG, WebP and an empty upload are no picture; damaged bytes in a known
/// format are unreadable.
#[test]
fn what_is_not_a_raster_image_is_refused() {
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>"#;
    let webp = b"RIFF\x1a\0\0\0WEBPVP8X\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0";
    for upload in [&b"hello"[..], svg, webp, b""] {
        assert!(
            matches!(
                Jpeg::from_upload(upload, None),
                Err(PictureError::Unsupported)
            ),
            "{upload:?}"
        );
    }
    let mut damaged = encoded(&RgbImage::new(64, 64).into(), ImageFormat::Png);
    damaged.truncate(40);
    assert!(matches!(
        Jpeg::from_upload(&damaged, None),
        Err(PictureError::Unreadable(_))
    ));
}

/// An image too wide, of too many pixels, of no pixels on a side, or whose 16-bit
/// pixels would decode past the allocation limit, is refused from its header,
/// however small it compresses and whatever square it keeps: decoding it could
/// allocate without bound.
#[test]
fn an_out_of_bounds_image_is_refused_before_decoding() {
    let png = |image: DynamicImage| encoded(&image, ImageFormat::Png);
    // A GIF whose screen is 0 by 1 pixels, holding one 1 by 1 frame.
    let empty_gif = [
        &b"GIF89a"[..],
        &[0, 0, 1, 0, 0, 0, 0],
        &[0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0],
        &[2, 2, 0x4c, 0x01, 0, 0x3b],
    ]
    .concat();
    let square = Crop {
        x: 0,
        y: 0,
        size: 1,
    };
    let deep = image::ImageBuffer::<Rgba<u16>, _>::new(3600, 3600);
    for (case, upload, crop) in [
        ("too wide", png(GrayImage::new(9000, 1).into()), None),
        (
            "too many pixels",
            png(GrayImage::new(6000, 6000).into()),
            None,
        ),
        ("no pixels on a side", empty_gif.clone(), None),
        ("no pixels to crop", empty_gif, Some(square)),
        (
            "over the allocation limit",
            png(DynamicImage::ImageRgba16(deep)),
            None,
        ),
    ] {
        assert!(
            matches!(
                Jpeg::from_upload(&upload, crop),
                Err(PictureError::Dimensions)
            ),
            "{case}"
        );
    }
}

/// A long, thin strip is cropped before it is scaled, so it costs no more than its
/// own pixels.
#[test]
fn a_thin_strip_is_cropped_before_it_is_scaled() {
    let upload = encoded(&RgbImage::new(8000, 3).into(), ImageFormat::Png);
    let (_, image) = stored(&upload);
    assert_eq!(image.dimensions(), (SIDE, SIDE));
}

/// An upload over the size limit is refused before it is read.
#[tokio::test]
async fn an_oversize_upload_is_refused() {
    let upload = vec![0; super::MAX_UPLOAD_BYTES + 1];
    assert!(matches!(
        Jpeg::encode(upload, None).await,
        Err(PictureError::TooLarge)
    ));
}
