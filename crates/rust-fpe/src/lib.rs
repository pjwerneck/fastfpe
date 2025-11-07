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
//! # Example (FF3-1)
//! ```rust
//! let ff3_1 = fpe::ff3_1::FF3_1::new(
//!     &[
//!         0xad, 0x41, 0xec, 0x5d, 0x23, 0x56, 0xde, 0xae,
//!         0x53, 0xae, 0x76, 0xf5, 0x0b, 0x4b, 0xa6, 0xd2,
//!     ],    // the encryption key
//!     // the default tweak (exactly 7 bytes for FF3-1)
//!     Some(&[0xcf, 0x29, 0xda, 0x1e, 0x18, 0xd9, 0x70]),
//!     10,   // radix specifies the number of characters in the alphabet
//!     None  // use (the first 10 characters of) the default alphabet
//! ).unwrap();
//!
//! let pt = "6520935496";
//! let ct = "4716569208";
//!
//! let out = ff3_1.encrypt(pt, None).unwrap();
//! assert!(out == ct);
//!
//! let out = ff3_1.decrypt(&ct, None).unwrap();
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

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{}", self.why)
        }
    }

    impl core::fmt::Debug for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Error").field("why", &self.why).finish()
        }
    }
}

/// Results returned by the FPE library
pub mod result {
    /// Short hand to return a result (or an FPE error)
    pub type Result<T> = std::result::Result<T, crate::error::Error>;
}
