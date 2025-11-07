use crate::aes;
use crate::alphabet;
use crate::error::Error;
use crate::result::Result;

pub enum CipherType {
    Encrypt,
    Decrypt,
}

struct SizeLimits {
    min: usize,
    max: usize,
}

struct FFXSizeLimits {
    twk: SizeLimits,
    txt: SizeLimits,
}

pub struct FFX {
    cipher: aes::Cipher,
    twk: Vec<u8>,
    len: FFXSizeLimits,
    alpha: alphabet::Alphabet,
}

impl FFX {
    pub fn new(
        key: &[u8],
        opt_twk: Option<&[u8]>,
        maxtxt: usize,
        mintwk: usize,
        maxtwk: usize,
        radix: usize,
        opt_alpha: Option<&str>,
    ) -> Result<Self> {
        if radix < 2 {
            return Err(Error::new(&format!(
                "invalid radix; must be at least 2, got {}",
                radix
            )));
        }

        let alpha = alphabet::Alphabet::new(opt_alpha, Some(radix))?;

        // the minimum required length for both ff1 and ff3-1 is given
        // by the inequality: radix**minlen >= 1_000_000
        //
        // therefore:
        //  minlen = ceil(log_radix(1_000_000))
        //         = ceil(log_10(1_000_000) / log_10(radix))
        //         = ceil(6 / log_10(radix))
        let mintxt = (6f64 / (radix as f64).log10()).ceil() as usize;
        if mintxt < 2 || mintxt > maxtxt {
            return Err(Error::new(&format!(
                "unsupported combination of radix and maximum text length; min required length is {}, max allowed is {}",
                mintxt, maxtxt
            )));
        }

        if mintwk > maxtwk {
            return Err(Error::new(
                "minimum tweak length must be less than maximum",
            ));
        }

        let twk: Vec<u8>;
        match opt_twk {
            None => twk = Vec::new(),
            Some(t) => {
                if t.len() < mintwk || (maxtwk > 0 && t.len() > maxtwk) {
                    return Err(Error::new("invalid tweak length"));
                }

                twk = t.to_vec();
            }
        }

        Ok(FFX {
            cipher: aes::Cipher::new(key)?,

            twk: twk,

            len: FFXSizeLimits {
                twk: SizeLimits {
                    min: mintwk,
                    max: maxtwk,
                },
                txt: SizeLimits {
                    min: mintxt,
                    max: maxtxt,
                },
            },

            alpha: alpha,
        })
    }

    pub fn get_tweak<'a>(&'a self, opt_twk: &Option<&'a [u8]>) -> &'a [u8] {
        match opt_twk {
            None => &self.twk,
            Some(t) => t,
        }
    }

    pub fn get_radix(&self) -> usize {
        self.alpha.len()
    }

    #[allow(dead_code)]
    pub fn get_cipher_block_size(&self) -> usize {
        self.cipher.block_size()
    }

    pub fn validate_text_length(&self, n: usize) -> Result<()> {
        if n < self.len.txt.min || n > self.len.txt.max {
            return Err(Error::new(&format!(
                "invalid text length; expected between {} and {} characters, got {}",
                self.len.txt.min, self.len.txt.max, n
            )));
        }

        Ok(())
    }

    pub fn validate_tweak_length(&self, n: usize) -> Result<()> {
        if n < self.len.twk.min
            || (self.len.twk.max > 0 && n > self.len.twk.max)
        {
            if self.len.twk.max > 0 && self.len.twk.min == self.len.twk.max {
                return Err(Error::new(&format!(
                    "invalid tweak length; expected exactly {} bytes, got {}",
                    self.len.twk.min, n
                )));
            } else if self.len.twk.max > 0 {
                return Err(Error::new(&format!(
                    "invalid tweak length; expected between {} and {} bytes, got {}",
                    self.len.twk.min, self.len.twk.max, n
                )));
            } else {
                return Err(Error::new(&format!(
                    "invalid tweak length; expected at least {} bytes, got {}",
                    self.len.twk.min, n
                )));
            }
        }

        Ok(())
    }

    pub fn prf(&self, s: &[u8], d: &mut [u8]) -> Result<()> {
        let mut c = self.cipher.clone();
        let blksz = c.block_size();

        for i in 0..(s.len() / blksz) {
            let j = i * blksz;
            c.encrypt_block(&s[j..(j + blksz)], d);
        }

        Ok(())
    }

    pub fn ciph(&self, s: &[u8], d: &mut [u8]) -> Result<()> {
        self.prf(&s[0..16], d)
    }

    pub fn chars_to_bignum(
        &self,
        chars: &[char],
    ) -> Result<num_bigint::BigInt> {
        let radix = self.alpha.len();
        let mut digits = Vec::<u8>::with_capacity(chars.len());

        for c in chars {
            digits.push(self.alpha.ltr(*c)? as u8);
        }

        Ok(num_bigint::BigInt::from_radix_be(
            num_bigint::Sign::Plus,
            &digits,
            radix as u32,
        )
        .unwrap())
    }

    pub fn bignum_to_chars(
        &self,
        n: &num_bigint::BigInt,
        opt_len: Option<usize>,
    ) -> Result<Vec<char>> {
        let (_, digits) = n.to_radix_le(self.alpha.len() as u32);
        let mut chars = Vec::<char>::with_capacity(digits.len());

        for d in digits {
            chars.push(self.alpha.pos(d as usize)?);
        }

        match opt_len {
            None => (),
            Some(len) => {
                if chars.len() < len {
                    chars.resize(len, self.alpha.pos(0)?);
                }
            }
        }

        chars.reverse();
        Ok(chars)
    }
}

#[cfg(test)]
mod tests {
    use super::FFX;
    use crate::result::Result;

    use std::str::FromStr;

    #[test]
    fn test_cipher_reuse() -> Result<()> {
        let exp = [
            102, 233, 75, 212, 239, 138, 44, 59, 136, 76, 250, 89, 202, 52, 43,
            46,
        ];
        let ffx = FFX::new(&[0; 16], None, 1024, 0, 0, 10, None)?;

        let mut d1: [u8; 16] = [0; 16];
        let mut d2: [u8; 16] = [0; 16];
        let s: [u8; 16] = [0; 16];

        ffx.ciph(&s, &mut d1)?;
        ffx.ciph(&s, &mut d2)?;

        assert!(d1 == d2);
        assert!(d1 == exp);

        Ok(())
    }

    #[test]
    fn test_bignum_conversion() -> Result<()> {
        let ffx = FFX::new(&[0; 16], None, 1024, 0, 0, 10, None)?;

        let n_str = "9037450980398204379409345039453045723049";
        let n = num_bigint::BigInt::from_str(n_str).unwrap();
        let s = n.to_str_radix(10);
        assert!(s == n_str);

        let c = ffx.bignum_to_chars(&n, None)?;
        assert!(String::from_iter(c.clone()) == n_str);

        let r = ffx.chars_to_bignum(&c)?;
        assert!(n == r);

        Ok(())
    }
}
