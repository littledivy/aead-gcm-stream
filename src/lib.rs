use aead::{
  consts::U16, generic_array::GenericArray, Key, KeyInit, KeySizeUser,
};
use cipher::{BlockCipher, BlockEncrypt, BlockSizeUser};
use ctr::Ctr32BE;
use ghash::{universal_hash::UniversalHash, GHash};

#[derive(Clone)]
struct GcmGhash<const TAG_SIZE: usize> {
  ghash: GHash,
  ghash_pad: [u8; TAG_SIZE],
  msg_buf: [u8; TAG_SIZE],
  msg_buf_offset: usize,
  ad_len: usize,
  msg_len: usize,
}

impl<const TAG_SIZE: usize> GcmGhash<TAG_SIZE> {
  fn new(h: &[u8], ghash_pad: [u8; TAG_SIZE]) -> Result<Self, ()> {
    let ghash = GHash::new(h.try_into().unwrap());

    Ok(Self {
      ghash,
      ghash_pad,
      msg_buf: [0u8; TAG_SIZE],
      msg_buf_offset: 0,
      ad_len: 0,
      msg_len: 0,
    })
  }

  fn set_aad(&mut self, aad: &[u8]) {
    self.ad_len = aad.len();
    self.ghash.update_padded(aad);
  }

  fn update(&mut self, msg: &[u8]) {
    if self.msg_buf_offset > 0 {
      let taking = std::cmp::min(msg.len(), TAG_SIZE - self.msg_buf_offset);
      self.msg_buf[self.msg_buf_offset..self.msg_buf_offset + taking]
        .copy_from_slice(&msg[..taking]);
      self.msg_buf_offset += taking;
      assert!(self.msg_buf_offset <= TAG_SIZE);

      self.msg_len += taking;

      if self.msg_buf_offset == TAG_SIZE {
        self
          .ghash
          .update(std::slice::from_ref(ghash::Block::from_slice(
            &self.msg_buf,
          )));
        self.msg_buf_offset = 0;
        return self.update(&msg[taking..]);
      } else {
        return;
      }
    }

    self.msg_len += msg.len();

    assert_eq!(self.msg_buf_offset, 0);
    let full_blocks = msg.len() / 16;
    let leftover = msg.len() - 16 * full_blocks;
    assert!(leftover < TAG_SIZE);
    if full_blocks > 0 {
      // Safety: Transmute [u8] to [[u8; 16]], like slice::as_chunks.
      // Then transmute [[u8; 16]] to [GenericArray<U16>], per repr(transparent).
      let blocks = unsafe {
        std::slice::from_raw_parts(
          msg[..16 * full_blocks].as_ptr().cast(),
          full_blocks,
        )
      };
      assert_eq!(
        std::mem::size_of_val(blocks) + leftover,
        std::mem::size_of_val(msg)
      );
      self.ghash.update(blocks);
    }

    self.msg_buf[0..leftover].copy_from_slice(&msg[full_blocks * 16..]);
    self.msg_buf_offset = leftover;
    assert!(self.msg_buf_offset < TAG_SIZE);
  }

  fn finalize(mut self) -> GenericArray<u8, U16> {
    if self.msg_buf_offset > 0 {
      self
        .ghash
        .update_padded(&self.msg_buf[..self.msg_buf_offset]);
    }

    let mut final_block = [0u8; 16];
    final_block[..8].copy_from_slice(&(8 * self.ad_len as u64).to_be_bytes());
    final_block[8..].copy_from_slice(&(8 * self.msg_len as u64).to_be_bytes());

    self.ghash.update(&[final_block.into()]);
    let mut hash = self.ghash.finalize();

    for (i, b) in hash.iter_mut().enumerate() {
      *b ^= self.ghash_pad[i];
    }

    hash
  }
}

pub struct AesGcm<Aes>
where
  Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
  /// Encryption cipher
  ctr: Ctr32BE<Aes>,

  /// GHASH authenticator
  ghash: GcmGhash<16>,
}

impl<Aes> KeySizeUser for AesGcm<Aes>
where
  Aes:
    KeySizeUser + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
  type KeySize = Aes::KeySize;
}

impl<Aes> AesGcm<Aes>
where
  Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
{
  pub fn new(key: &Key<Self>, nonce: &[u8]) -> Self {
    let cipher = Aes::new(key);
    let mut ghash_key = ghash::Key::default();
    cipher.encrypt_block(&mut ghash_key);

    use cipher::InnerIvInit;
    use cipher::StreamCipherSeek;

    let mut nonce_block = GenericArray::default();
    if nonce.len() == 12 {
      nonce_block[..nonce.len()].copy_from_slice(nonce);
    } else {
      let mut ghash = GHash::new(&ghash_key);
      ghash.update_padded(nonce);
      ghash.update_padded(&(8 * nonce.len() as u128).to_be_bytes());
      nonce_block.copy_from_slice(&ghash.finalize());
      for i in nonce_block.iter_mut().rev() {
        *i = i.wrapping_sub(1);
        if *i != 0xff {
          break;
        }
      }
    }
    let mut ctr = ctr::Ctr32BE::from_core(ctr::CtrCore::inner_iv_init(
      cipher,
      &nonce_block,
    ));
    ctr.seek(Aes::block_size());

    let mut pad = [0u8; 16];
    ctr.apply_keystream(&mut pad);

    let ghash = GcmGhash::new(&ghash_key, pad).unwrap();
    Self { ctr, ghash }
  }
}

use cipher::StreamCipher;

impl<Aes> AesGcm<Aes>
where
  Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
{
  pub fn set_aad(&mut self, aad: &[u8]) {
    self.ghash.set_aad(aad);
  }

  pub fn encrypt(&mut self, block: &mut [u8]) {
    self.ctr.apply_keystream(block);
    self.ghash.update(block);
  }

  pub fn decrypt(&mut self, block: &mut [u8]) {
    self.ghash.update(block);
    self.ctr.apply_keystream(block);
  }

  pub fn finish(self) -> GenericArray<u8, U16> {
    self.ghash.finalize()
  }
}
