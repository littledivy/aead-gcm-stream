# aead-stream

Pure Rust implementaion of AES GCM cipher for data streams.

![image](https://github.com/littledivy/aead-stream/assets/34997667/938c39c1-aa0e-4858-8304-e3f67c1fd83a)

```rust
use aes_gcm_stream::AesGcm;
use aes::Aes128;

let mut cipher = AesGcm::<Aes128>::new(&key);
cipher.init(nonce);

cipher.encrypt(&mut data);

let tag = cipher.final();
```
