//! The FF1 algorithm
//!
//! The FF1 algorithm supports key sizes of 128, 192, and 256 bits.
//! The (maximum possible) length of the tweak is supplied by the
//! caller and is essentially unbounded.
//!
//! This implementation contains a "context" structure, called FF1,
//! that holds the encryption key, the default tweak, and some other
//! parameters related to the algorithm. Once, this structure has
//! been created, it can be used to encrypt and decrypt data

use crate::ffx;
use crate::result::Result;

use byteorder::ByteOrder;
use num_traits::Euclid;

/// The FF1 context structure
pub struct FF1 {
    ffx: ffx::FFX,
}

impl FF1 {
    /// Create a new FF1 context
    ///
    /// The supplied key may be any of the lengths supported by AES.
    ///
    /// The default tweak is optional. If supplied, it's length
    /// must satisfy the constraints set by the `mintwk` and `maxtwk`
    /// parameters. `mintwk` and `maxtwk` may both be set to 0 to
    /// leave the tweak length unbounded.
    ///
    /// The radix must be less than or equal to the number of characters
    /// in the supplied alphabet (or the default alphabet) if no alphabet
    /// is supplied to this function
    pub fn new(
        key: &[u8],
        opt_t: Option<&[u8]>,
        mintwk: usize,
        maxtwk: usize,
        radix: usize,
        opt_alpha: Option<&str>,
    ) -> Result<Self> {
        Ok(FF1 {
            ffx: ffx::FFX::new(
                key,
                opt_t,
                // the maximum input length allowed by the
                // algorithm specification is 2**32 - 1
                (1 << 32) - 1,
                mintwk,
                maxtwk,
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
        opt_t: Option<&[u8]>,
        which: ffx::CipherType,
    ) -> Result<Vec<char>> {
        let ffx = &self.ffx;
        let radix = ffx.get_radix();
        let blksz = ffx.get_cipher_block_size();

        let t = ffx.get_tweak(&opt_t);
        ffx.validate_tweak_length(t.len())?;

        let n = inp.len();
        ffx.validate_text_length(n)?;

        // (step 1)
        let u = n / 2;
        let v = n - u;

        // the algorithm, as specified, calls for "A" and "B", the
        // strings representing the two halves of the input to be
        // converted back and forth between strings and numbers. as
        // it turns out, those strings can be represented as numbers
        // for the duration of the algorithm and only converted back
        // to strings at the end. (step 2)
        let mut na = ffx.chars_to_bignum(&inp[..u])?;
        let mut nb = ffx.chars_to_bignum(&inp[u..])?;

        // the input string gets broken in half, and `b` is the
        // number of bytes required to represent the latter half
        // as a number converted from the specified radix. (step 3)
        let b =
            ((((radix as f64).log2() * (v as f64)).ceil() as usize) + 7) / 8;
        // d is the number of bytes extracted from the aes output
        // to be used as the number `y` in the algorithm (step 4)
        let d = 4 * ((b + 3) / 4) + 4;

        // p serves as the input to one of the aes operations, the
        // output of which eventually becomes `y`. The algorithm
        // also mentions a `q` slice which is populated by the tweak
        // and the latter half of the input (converted to a number).
        // this `q` is also contained as part of `p` as the two are
        // supposed to be concatenated before being input to the aes
        // operation. `p` is the first 16 bytes, and `q` is the rest.
        let mut p = Vec::<u8>::new();
        p.resize(16 + ((t.len() + 1 + b + (blksz - 1)) / blksz) * blksz, 0);

        // `r` is the output from the aes operations
        let mut r = Vec::<u8>::new();
        r.resize(((d + (blksz - 1)) / blksz) * blksz, 0);

        // p is initialized once and remains unchanged after the values
        // to be put in p are specified by the algorithm (step 5)
        p[0] = 1;
        p[1] = 2;
        // note that the radix is written starting at index 2, but
        // the algorithm only calls for the low order 3 bytes to be
        // written starting at index 3. hence, index 2 is immediately
        // overwritten with the correct value after this operation
        byteorder::BigEndian::write_u32(&mut p[2..6], radix as u32);
        p[2] = 1;
        p[6] = 10;
        p[7] = u as u8;
        byteorder::BigEndian::write_u32(&mut p[8..12], n as u32);
        byteorder::BigEndian::write_u32(&mut p[12..16], t.len() as u32);

        // the first "tweak length" bytes of q contain the tweak.
        // some number of bytes, used to pad q to a multiple of the
        // block size, follow and are to be filled with 0's. the rest
        // of q changes during the algorithm. (step 6i, partial)
        {
            // changes to q are scoped so that multiple mutable
            // references to p don't exist
            let q = &mut p[16..];
            q[0..t.len()].copy_from_slice(t);
            // the rest of q is already full of 0's
            // due to initialization of p
        }

        // later on radix**m where m is either u or v is needed.
        // just calculate them both here. note that u either equals
        // v or is one less than v. (step 6v, 6vi, partial)
        let mut mu: num_bigint::BigInt = radix.into();
        mu = mu.pow(u as u32);
        let mut mv = mu.clone();
        if u != v {
            mv *= radix;
        }

        // during decryption, the algorithm runs in "reverse".
        // swap these values so that during decryption we start
        // with the last ones used during the encryption
        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut na, &mut nb);
            std::mem::swap(&mut mu, &mut mv);
        }

        for i in 0..10 {
            // fill in the non-static portions of q (step 6i, partial)
            {
                // changes to q are scoped to avoid conflict with p.
                // use of q_len as opposed to q.len() also
                // avoids the borrow checker's wrath
                let q = &mut p[16..];
                let q_len = q.len();

                match which {
                    ffx::CipherType::Encrypt => q[q_len - b - 1] = i,
                    ffx::CipherType::Decrypt => q[q_len - b - 1] = 9 - i,
                }

                // the num_bigint library doesn't provide left padding,
                // but it does support little endian output which allows
                // us to do right-padding and then reverse the bytes
                let (_, mut v) = nb.to_bytes_le();
                v.resize(b, 0);
                v.reverse();
                q[q_len - b..].copy_from_slice(&v);
            }

            // (step 6ii)
            ffx.prf(&p, &mut r[..blksz])?;

            // (step 6iii)
            // this step is a little bit tricky, or at least the way
            // it is implemented is. this step calls for the output of
            // `prf()` to be concatenated with successive calls to `ciph()`
            // on that same output xor'd with a counter, something like this:
            // output || ciph(output^1) || ciph(output^2) || ...
            //
            // this code saves the bytes that would be modified by the xor,
            // updates the output with the xor, and then performs the ciph()
            // operation, placing each output in successive blocks following
            // the output. the original output in the first block is then
            // restored to its original value.
            //
            // the saving and restoration of the original value could be
            // moved outside of this loop, but in practice the input needs
            // to be very large to cause this loop to execute. therefore,
            // the operation happens inside the loop where it's unlikely
            // to be executed at all.
            for j in 1..r.len() / blksz {
                let (s, d) = r.split_at_mut(blksz);
                let l = (j - 1) * blksz;

                let w = byteorder::BigEndian::read_u32(&s[blksz - 4..]);
                byteorder::BigEndian::write_u32(
                    &mut s[blksz - 4..],
                    w ^ j as u32,
                );
                ffx.ciph(s, &mut d[l..l + blksz])?;
                byteorder::BigEndian::write_u32(&mut s[blksz - 4..], w);
            }

            // (step 6iv)
            let y = num_bigint::BigInt::from_bytes_be(
                num_bigint::Sign::Plus,
                &r[..d],
            );

            // (step 6vi, partial)
            match which {
                ffx::CipherType::Encrypt => na += y,
                ffx::CipherType::Decrypt => na -= y,
            }
            na = na.rem_euclid(&mu);
            // (step 6v, partial)
            std::mem::swap(&mut mu, &mut mv);

            // (step 6viii, 6ix. step 6vii is not necessary)
            std::mem::swap(&mut na, &mut nb);
        }

        // during decryption, the halves are reversed. put em back
        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut na, &mut nb);
        }

        // (step 7)
        Ok([
            ffx.bignum_to_chars(&na, Some(u))?,
            ffx.bignum_to_chars(&nb, Some(v))?,
        ]
        .concat())
    }

    // common function to convert the input String to a sequence
    // of chars before the cipher operation and back again after
    fn cipher_string(
        &self,
        inp_s: &str,
        opt_t: Option<&[u8]>,
        which: ffx::CipherType,
    ) -> Result<String> {
        let mut inp_c = Vec::<char>::with_capacity(inp_s.chars().count());
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
    op: fn(&FF1, &str, Option<&[u8]>) -> Result<String>,
) -> Result<String> {
    let ff1 = FF1::new(key, None, 0, 0, radix, alpha)?;
    return op(&ff1, txt, twk);
}

pub fn encrypt(
    key: &[u8],
    twk: Option<&[u8]>,
    pt: &str,
    radix: usize,
    alpha: Option<&str>,
) -> Result<String> {
    return cipher(key, twk, pt, radix, alpha, FF1::encrypt);
}

pub fn decrypt(
    key: &[u8],
    twk: Option<&[u8]>,
    ct: &str,
    radix: usize,
    alpha: Option<&str>,
) -> Result<String> {
    return cipher(key, twk, ct, radix, alpha, FF1::decrypt);
}

#[cfg(test)]
mod tests {}
