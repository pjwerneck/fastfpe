use crate::error::Error;
use crate::result::Result;

use aes;
use cbc;

use aes::cipher::BlockEncryptMut;
use aes::cipher::BlockSizeUser;
use aes::cipher::KeyIvInit;

#[derive(Clone)]
enum CbcType {
    Aes128(cbc::Encryptor<aes::Aes128>),
    Aes192(cbc::Encryptor<aes::Aes192>),
    Aes256(cbc::Encryptor<aes::Aes256>),
}

#[derive(Clone)]
pub struct Cipher {
    enc: CbcType,
    blksz: usize,
}

macro_rules! construct_cipher {
    ($type:ident, $key:expr, $iv:expr) => {
        Cipher {
            blksz: aes::$type::block_size(),
            enc: CbcType::$type(cbc::Encryptor::<aes::$type>::new(
                $key.into(),
                $iv.into(),
            )),
        }
    };
}

impl Cipher {
    pub fn new(key: &[u8]) -> Result<Cipher> {
        const IV: &[u8] = &[0u8; 16];

        Ok(match key.len() {
            16 => construct_cipher!(Aes128, key, IV),
            24 => construct_cipher!(Aes192, key, IV),
            32 => construct_cipher!(Aes256, key, IV),
            _ => return Err(Error::new("invalid key length")),
        })
    }

    pub fn encrypt_block(&mut self, src: &[u8], dst: &mut [u8]) {
        match &mut self.enc {
            CbcType::Aes128(e) => {
                e.encrypt_block_b2b_mut(src.into(), dst.into())
            }
            CbcType::Aes192(e) => {
                e.encrypt_block_b2b_mut(src.into(), dst.into())
            }
            CbcType::Aes256(e) => {
                e.encrypt_block_b2b_mut(src.into(), dst.into())
            }
        }
    }

    pub fn block_size(&self) -> usize {
        self.blksz
    }
}
