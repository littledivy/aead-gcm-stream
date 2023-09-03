use aead::{consts::U16, generic_array::GenericArray, KeyInit};
use cipher::{BlockCipher, BlockEncrypt, BlockSizeUser};

pub(crate) struct Ctr<Aes> {
  /// Counter mode with a 32-bit big endian counter.
  j0: GenericArray<u8, U16>,
  pub(crate) j0_ct: GenericArray<u8, U16>,

  cipher: Aes,
}

impl<Aes> Ctr<Aes>
where
  Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
{
  pub(crate) fn new(cipher: Aes) -> Self {
    let j0 = GenericArray::from([0u8; 16]);
    let j0_ct = j0;
    Self { j0, j0_ct, cipher }
  }

  pub(crate) fn init(&mut self, nonce: &[u8]) {
    self.j0[..12].copy_from_slice(nonce);
    self.j0[15] = 1;

    self.j0_ct = self.j0.clone();
    self.cipher.encrypt_block(&mut self.j0_ct);
  }

  pub(crate) fn encrypt_block_inner(&mut self, block: &mut [u8]) {
    self.j0[15] = self.j0[15].wrapping_add(1);
    if self.j0[15] == 0 {
      self.j0[14] = self.j0[14].checked_add(1).unwrap();
    }
    let mut ek = self.j0;
    self.cipher.encrypt_block(&mut ek);

    block.iter_mut().zip(ek).for_each(|(a, b)| *a ^= b);
  }
}
