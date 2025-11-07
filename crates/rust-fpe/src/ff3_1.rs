//! The FF3-1 algorithm
//!
//! The FF3-1 algorithm supports key sizes of 128, 192, and 256 bits.
//! The length of the tweak is specified by the algorithm as 56 bits.
//!
//! This implementation contains a "context" structure, called FF3_1,
//! that holds the encryption key, the default tweak, and some other
//! parameters related to the algorithm. Once, this structure has
//! been created, it can be used to encrypt and decrypt data
//!
//! # Example
//! ```rust
//! let ff3_1 = fpe::ff3_1::FF3_1::new(
//!     &[
//!         0xad, 0x41, 0xec, 0x5d, 0x23, 0x56, 0xde, 0xae,
//!         0x53, 0xae, 0x76, 0xf5, 0x0b, 0x4b, 0xa6, 0xd2,
//!     ],    // the encryption key
//!     // the default tweak
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

use crate::ffx;
use crate::result::Result;

use num_traits::Euclid;

/// The FF3_1 context structure
pub struct FF3_1 {
    ffx: ffx::FFX,
}

impl FF3_1 {
    /// Create a new FF3-1 context
    ///
    /// The supplied key may be any of the lengths supported by AES.
    ///
    /// The default tweak is optional. If supplied, it's length
    /// must be 7 bytes as per the algorithm specification. Those values
    /// are hardcoded within this function. Note that if the default
    /// tweak is not supplied, one must be supplied during the encrypt
    /// and decrypt operations
    ///
    /// The radix must be less than or equal to the number of characters
    /// in the supplied alphabet (or the default alphabet) if no alphabet
    /// is supplied to this function
    pub fn new(
        key: &[u8],
        opt_twk: Option<&[u8]>,
        radix: usize,
        opt_alpha: Option<&str>,
    ) -> Result<Self> {
        // key is reversed for ff3-1
        let mut k = key.to_vec();
        k.reverse();

        Ok(FF3_1 {
            ffx: ffx::FFX::new(
                &k,
                opt_twk,
                // maxlen for ff3-1:
                //   = 2 * log_radix(2**96)
                //   = 2 * log2(2**96) / log2(radix)
                //   = 2 * 96 / log2(radix)
                //   = 192 / log2(radix)
                (192f64 / (radix as f64).log2()).floor() as usize,
                // tweak size is fixed for ff3-1
                7,
                7,
                radix,
                opt_alpha,
            )?,
        })
    }

    // the code wants to work with individual characters or letters.
    // this isn't possible with utf8, so the caller is expected to
    // convert Strings to sequences of chars
    fn cipher_chars(
        &self,
        inp: &[char],
        opt_twk: Option<&[u8]>,
        which: ffx::CipherType,
    ) -> Result<Vec<char>> {
        let ffx = &self.ffx;
        let radix = ffx.get_radix();

        let n = inp.len();
        ffx.validate_text_length(n)?;

        // (step 1)
        let v = n / 2;
        let u = n - v;

        // (step 2)
        let mut a = inp[..u].to_vec();
        let mut b = inp[u..].to_vec();

        let t = ffx.get_tweak(&opt_twk);
        ffx.validate_tweak_length(t.len())?;

        // (step 3)
        // tl and tr are tw[0] and tw[1]
        let mut tw: [[u8; 4]; 2] = [[0; 4]; 2];
        tw[0][..3].copy_from_slice(&t[..3]);
        tw[0][3] = t[3] & 0xf0;
        tw[1][..3].copy_from_slice(&t[4..]);
        tw[1][3] = (t[3] & 0x0f) << 4;

        // later on radix**m where m is either u or v is needed.
        // just calculate them both here. note that u either equals
        // v or is one more than v. (step 4v, partial)
        let mut mv: num_bigint::BigInt = radix.into();
        mv = mv.pow(v as u32);
        let mut mu = mv.clone();
        if v != u {
            mu *= radix;
        }

        // the algorithm calls for the strings A and B to be reversed
        // at various points for certain operations, and it otherwise
        // maintains them in the original form. however, if they are
        // reversed before the algorithm starts, there is no need to
        // reverse them *during* the algorithm. furthermore, because
        // this implementation elides step 6vi, there is no need for
        // reversal at all during the algorithm.
        a.reverse();
        b.reverse();

        // without the need for reversal, the strings can be converted
        // to their numerical representations for the duration of the
        // algorithm
        let mut na = ffx.chars_to_bignum(&a)?;
        let mut nb = ffx.chars_to_bignum(&b)?;

        // during decryption, the algorithm runs in "reverse".
        // swap these values so that during decryption we start
        // with the last ones used during the encryption
        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut na, &mut nb);
            std::mem::swap(&mut mu, &mut mv);

            let (t0, t1) = tw.split_at_mut(1);
            std::mem::swap(&mut t0[0], &mut t1[0]);
        }

        for i in 0..8 {
            let mut p: [[u8; 16]; 2] = [[0; 16]; 2];

            // (step 4i, 4ii)
            p[0][..4].copy_from_slice(&tw[((i + 1) as u8 % 2) as usize]);
            match which {
                ffx::CipherType::Encrypt => p[0][3] ^= i,
                ffx::CipherType::Decrypt => p[0][3] ^= 7 - i,
            }

            // the num_bigint library doesn't provide left padding,
            // but it does support little endian output which allows
            // us to do right-padding and then reverse the bytes
            let (_, mut v) = nb.to_bytes_le();
            v.resize(12, 0);
            v.reverse();
            p[0][4..16].copy_from_slice(&v);

            // the ciph() operation does not support encryption in
            // place, so the output is stored in a separate array,
            // which is only used once, immediately after the operation
            // (step 4iii)
            p[0].reverse();
            {
                let (p0, p1) = p.split_at_mut(1);
                ffx.ciph(&p0[0], &mut p1[0])?;
            }
            p[1].reverse();

            // (step 4iv)
            let y = num_bigint::BigInt::from_bytes_be(
                num_bigint::Sign::Plus,
                &p[1],
            );

            // (step 4v)
            match which {
                ffx::CipherType::Encrypt => na += y,
                ffx::CipherType::Decrypt => na -= y,
            }
            na = na.rem_euclid(&mu);
            // (step 4i, partial)
            std::mem::swap(&mut mu, &mut mv);

            // (step 4vii, 4viii; step 4vi is skipped)
            std::mem::swap(&mut na, &mut nb);
        }

        // during decryption, the halves are reversed. put em back
        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut na, &mut nb);
        }

        // convert A and B back from their numerical representations
        b = ffx.bignum_to_chars(&nb, Some(v))?;
        a = ffx.bignum_to_chars(&na, Some(u))?;

        // restore the ordering of the strings
        b.reverse();
        a.reverse();

        // (step 5)
        Ok([a, b].concat())
    }

    // common function to convert the input String to a sequence
    // of chars before the cipher operation and back again after
    fn cipher_string(
        &self,
        inp_s: &str,
        opt_t: Option<&[u8]>,
        which: ffx::CipherType,
    ) -> Result<String> {
        let mut inp_c = Vec::<char>::new();
        inp_s.chars().for_each(|c| inp_c.push(c));

        let out_c = self.cipher_chars(&inp_c, opt_t, which)?;
        Ok(String::from_iter(out_c))
    }

    /// Encrypt a string
    ///
    /// If the tweak is not None, then the specified tweak will be used
    /// instead of the default specified by the context structure.
    pub fn encrypt(&self, pt: &str, twk: Option<&[u8]>) -> Result<String> {
        self.cipher_string(pt, twk, ffx::CipherType::Encrypt)
    }

    /// Decrypt a string
    ///
    /// If the tweak is not None, then the specified tweak will be used
    /// instead of the default specified by the context structure. The
    /// tweak used must match that used during encryption.
    pub fn decrypt(&self, ct: &str, twk: Option<&[u8]>) -> Result<String> {
        self.cipher_string(ct, twk, ffx::CipherType::Decrypt)
    }
}

fn cipher(
    key: &[u8],
    twk: Option<&[u8]>,
    txt: &str,
    radix: usize,
    alpha: Option<&str>,
    op: fn(&FF3_1, &str, Option<&[u8]>) -> Result<String>,
) -> Result<String> {
    let ff3_1 = FF3_1::new(key, None, radix, alpha)?;
    return op(&ff3_1, txt, twk);
}

pub fn encrypt(
    key: &[u8],
    twk: Option<&[u8]>,
    pt: &str,
    radix: usize,
    alpha: Option<&str>,
) -> Result<String> {
    return cipher(key, twk, pt, radix, alpha, FF3_1::encrypt);
}

pub fn decrypt(
    key: &[u8],
    twk: Option<&[u8]>,
    ct: &str,
    radix: usize,
    alpha: Option<&str>,
) -> Result<String> {
    return cipher(key, twk, ct, radix, alpha, FF3_1::decrypt);
}

#[cfg(test)]
mod tests {
    use super::FF3_1;
    use crate::result::Result;

    fn parse_hex(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16).unwrap();
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
            out.push(((hi << 4) | lo) as u8);
        }
        out
    }

    #[test]
    fn test_kat_docstring() -> Result<()> {
        // Example from the module docstring
        let key = parse_hex("ad41ec5d2356deae53ae76f50b4ba6d2");
        let tweak = parse_hex("cf29da1e18d970");
        let ff = FF3_1::new(&key, Some(&tweak), 10, None)?;

        let pt = "6520935496";
        let ct = ff.encrypt(pt, None)?;
        assert_eq!(ct, "4716569208");
        Ok(())
    }

    #[test]
    fn test_key_sizes_roundtrip() -> Result<()> {
        let tweak = [0u8; 7];
        let alphabet = Some("0123456789");
        let plaintext = "123456789012";

        let keys = vec![vec![0u8; 16], vec![1u8; 24], vec![2u8; 32]];
        for k in keys {
            let ff = FF3_1::new(&k, Some(&tweak), 10, alphabet)?;
            let ct = ff.encrypt(plaintext, None)?;
            let dt = ff.decrypt(&ct, None)?;
            assert_eq!(dt, plaintext);
        }

        Ok(())
    }

    #[test]
    fn test_tweak_invalid_length() {
        let key = vec![0u8; 16];
        let bad_tweak = vec![0u8; 8];
        let res = FF3_1::new(&key, Some(&bad_tweak), 10, None);
        assert!(res.is_err());
    }

    #[test]
    fn test_alphabet_duplicates() {
        let key = vec![0u8; 16];
        let tweak = [0u8; 7];
        // alphabet with duplicates should error
        let res = FF3_1::new(&key, Some(&tweak), 10, Some("1123456789"));
        assert!(res.is_err());
    }
}
