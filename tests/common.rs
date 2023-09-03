#[derive(Debug)]
pub struct TestVector<K: 'static> {
  pub key: &'static K,
  pub nonce: &'static [u8; 12],
  pub aad: &'static [u8],
  pub plaintext: &'static [u8],
  pub ciphertext: &'static [u8],
  pub tag: &'static [u8; 16],
}
