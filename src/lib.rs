use aead::{consts::U16, generic_array::GenericArray, Key, KeyInit, KeySizeUser};
use cipher::{BlockCipher, BlockEncrypt, BlockSizeUser};
use ghash::{universal_hash::UniversalHash, GHash};

mod ctr;

use ctr::Ctr;

pub struct AesGcm<Aes>
where
    Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    /// Encryption cipher
    ctr: Ctr<Aes>,

    /// GHASH authenticator
    ghash: GHash,

    len: usize,

    aad_len: usize,
}

impl<Aes> KeySizeUser for AesGcm<Aes>
where
    Aes: KeySizeUser + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    type KeySize = Aes::KeySize;
}

impl<Aes> KeyInit for AesGcm<Aes>
where
    Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    fn new(key: &Key<Self>) -> Self {
        let cipher = Aes::new(key);
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);

        let ghash = GHash::new(&ghash_key);
        let ctr = Ctr::new(cipher);
        Self {
            ctr,
            ghash,
            len: 0,
            aad_len: 0,
        }
    }
}

impl<Aes> AesGcm<Aes>
where
    Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    pub fn set_aad(&mut self, aad: &[u8]) {
        self.aad_len = aad.len();
        self.ghash.update_padded(aad);
    }

    pub fn init(&mut self, nonce: &[u8; 12]) {
        self.ctr.init(nonce);
    }

    pub fn encrypt(&mut self, block: &mut [u8]) {
        let mut blocks = block.chunks_exact_mut(16);
        for block in &mut blocks {
            self.ctr.encrypt_block_inner(block.into());
        }

        let tail = blocks.into_remainder();

        if !tail.is_empty() {
            let mut padded_block = [0; 16];
            padded_block[..tail.len()].copy_from_slice(tail);
            self.ctr.encrypt_block_inner(&mut padded_block);

            tail.copy_from_slice(&padded_block[..tail.len()]);
        }

        self.ghash.update_padded(block);
        self.len += block.len()
    }

    pub fn decrypt(&mut self, block: &mut [u8]) {
        self.ghash.update_padded(block);

        let mut blocks = block.chunks_exact_mut(16);
        for block in &mut blocks {
            self.ctr.encrypt_block_inner(block.into());
        }

        let tail = blocks.into_remainder();

        if !tail.is_empty() {
            let mut padded_block = [0; 16];
            padded_block[..tail.len()].copy_from_slice(tail);
            self.ctr.encrypt_block_inner(&mut padded_block);

            tail.copy_from_slice(&padded_block[..tail.len()]);
        }

        self.len += block.len()
    }

    pub fn finish(mut self) -> GenericArray<u8, U16> {
        let associated_data_bits: u64 = (self.aad_len as u64) * 8;
        let buffer_bits: u64 = (self.len as u64) * 8;

        let mut block = GenericArray::from([0u8; 16]);
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        self.ghash.update(&[block]);

        let mut tag = self.ghash.finalize();
        tag.as_mut_slice()
            .iter_mut()
            .zip(self.ctr.j0_ct)
            .for_each(|(a, b)| *a ^= b);

        tag
    }
}
