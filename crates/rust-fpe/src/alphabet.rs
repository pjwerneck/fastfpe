use crate::error::Error;
use crate::result::Result;

const DEFAULT_ALPHABET: &str =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

struct Letter {
    val: char,
    pos: usize,
}

pub struct Alphabet {
    by_pos: Vec<char>,
    by_ltr: Vec<Letter>,
}

impl Alphabet {
    pub fn new(
        opt_s: Option<&str>,
        opt_lim: Option<usize>,
    ) -> Result<Alphabet> {
        let s = match opt_s {
            Some(s) => s,
            None => DEFAULT_ALPHABET,
        };
        let lim = match opt_lim {
            Some(l) => l,
            None => 0,
        };

        let mut by_pos = Vec::<char>::new();
        s.chars().for_each(|c| {
            if lim == 0 || by_pos.len() < lim {
                by_pos.push(c)
            }
        });

        if lim > 0 && lim > by_pos.len() {
            return Err(Error::new("not enough letters in alphabet"));
        }

        let mut by_ltr = Vec::<Letter>::with_capacity(by_pos.len());
        for c in &by_pos {
            by_ltr.push(Letter {
                val: *c,
                pos: by_ltr.len(),
            });
        }
        by_ltr.sort_by_key(|l| l.val);

        for i in 1..by_ltr.len() {
            if by_ltr[i].val == by_ltr[i - 1].val {
                return Err(Error::new("duplicate letter(s) in alphabet"));
            }
        }

        Ok(Alphabet {
            by_ltr: by_ltr,
            by_pos: by_pos,
        })
    }

    pub fn len(&self) -> usize {
        self.by_pos.len()
    }

    pub fn ltr(&self, c: char) -> Result<usize> {
        match self.by_ltr.binary_search_by_key(&c, |l| l.val) {
            Ok(i) => Ok(self.by_ltr[i].pos),
            Err(_) => {
                Err(Error::new(&format!("'{}' not found in alphabet", c)))
            }
        }
    }

    pub fn pos(&self, i: usize) -> Result<char> {
        if i >= self.len() {
            return Err(Error::new(&format!("no letter at position {}", i)));
        }

        Ok(self.by_pos[i])
    }
}

#[cfg(test)]
mod tests {
    use super::Alphabet;
    use crate::result::Result;

    #[test]
    fn limited_alphabet() -> Result<()> {
        let alpha = Alphabet::new(None, Some(10))?;
        assert!(alpha.len() == 10);
        Ok(())
    }

    #[test]
    fn unlimited_alphabet() -> Result<()> {
        let alpha = Alphabet::new(None, None)?;
        assert!(
            alpha.len() == super::DEFAULT_ALPHABET.len(),
            "expected {}, actual {}",
            super::DEFAULT_ALPHABET.len(),
            alpha.len()
        );
        Ok(())
    }

    #[test]
    fn alphabet_too_small() -> Result<()> {
        let res = Alphabet::new(Some("123"), Some(10));
        assert!(res.is_err());
        Ok(())
    }

    #[test]
    fn letter_not_found() -> Result<()> {
        let alpha = Alphabet::new(None, None)?;
        let res = alpha.ltr('!' as char);
        assert!(res.is_err());
        Ok(())
    }

    #[test]
    fn pos_not_found() -> Result<()> {
        let alpha = Alphabet::new(None, None)?;
        let res = alpha.pos(alpha.len() + 1);
        assert!(res.is_err());
        Ok(())
    }
}
