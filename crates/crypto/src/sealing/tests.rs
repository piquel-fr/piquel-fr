//! Sealed values open only with their own KEK and associated data.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// A sealed value fails to open with another KEK, swapped associated data or
/// any modified byte, and parsing accepts only 32 bytes of unpadded base64url.
#[test]
fn sealed_values_open_only_with_their_key_and_associated_data() {
    let kek = KeyEncryptionKey::generate().expect("KEK");
    let sealed = kek.seal(b"private key", b"kid-1rsa").expect("seal");
    assert_eq!(
        kek.open(&sealed, b"kid-1rsa").expect("open").as_slice(),
        b"private key"
    );
    let other = KeyEncryptionKey::generate().expect("other KEK");
    assert!(matches!(
        other.open(&sealed, b"kid-1rsa"),
        Err(CryptoError::Unsealable)
    ));
    assert!(matches!(
        kek.open(&sealed, b"kid-2rsa"),
        Err(CryptoError::Unsealable)
    ));
    for index in [0, NONCE_LEN, sealed.len() - 1] {
        let mut modified = sealed.clone();
        modified[index] ^= 1;
        assert!(kek.open(&modified, b"kid-1rsa").is_err(), "byte {index}");
    }
    assert!(kek.open(&sealed[..NONCE_LEN], b"kid-1rsa").is_err());

    let encoded = Secret::generate().expect("secret").encoded();
    assert!(KeyEncryptionKey::parse(&encoded).is_ok());
    for invalid in [format!("{encoded}="), "not base64!".to_owned()] {
        assert!(matches!(
            KeyEncryptionKey::parse(&invalid),
            Err(CryptoError::Encoding(_))
        ));
    }
    for bytes in [&[0; 31][..], &[0; 33]] {
        assert!(matches!(
            KeyEncryptionKey::parse(&URL_SAFE_NO_PAD.encode(bytes)),
            Err(CryptoError::SecretLength)
        ));
    }
    assert_eq!(format!("{kek:?}"), "KeyEncryptionKey(REDACTED)");
}
