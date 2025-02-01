//! Format-preserving Encryption
//!
//! Provides implementations of the NIST-specified FF1 and FF3-1 encryption
//! algorithms. Format-preserving encryption, in short, means that both the
//! plaintext and ciphertext will consist of the same alphabet of characters.
//!
//! If no alphabet is supplied, as is the case in the example below, a default
//! alphabet is used, consisting of the characters `0` through `9`, followed
//! by the letters `a` through `z`, and then by the letters `A` through `Z`.
//! The maximum radix supported by this default alphabet is 62, the number of
//! characters in the alphabet.
//!
//! # Example
//! ```rust
//! let ff1 = fpe::ff1::FF1::new(
//!     &[
//!         0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//!         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
//!     ],    // the encryption key
//!     None, // no tweak specified, use an empty one
//!     0, 0, // no minimum and maximum tweak size
//!     10,   // radix specifies the number of characters in the alphabet
//!     None  // use (the first 10 characters of) the default alphabet
//! ).unwrap();
//!
//! // these are from the first NIST-specified test for FF1
//! let pt = "0123456789";
//! let ct = "2433477484";
//!
//! let out = ff1.encrypt(pt, None).unwrap();
//! assert!(out == ct);
//!
//! let out = ff1.decrypt(&ct, None).unwrap();
//! assert!(out == pt);
//! ```

pub(crate) mod aes;
pub(crate) mod alphabet;
pub mod ff1;
pub mod ff3_1;
pub(crate) mod ffx;

/// Errors returned by the FPE library
pub mod error {

    /// Structure used by the library to convey errors
    #[derive(Debug)]
    pub struct Error {
        // compiler thinks "why" is unused because we
        // allow the Debug trait to format it for us.
        #[allow(dead_code)]
        why: String,
    }

    impl Error {
        pub fn new(why: &str) -> Self {
            Error {
                why: why.to_string(),
            }
        }
    }
}

/// Results returned by the FPE library
pub mod result {
    /// Short hand to return a result (or an FPE error)
    pub type Result<T> = std::result::Result<T, crate::error::Error>;
}
