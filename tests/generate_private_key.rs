use const_rsa::generate_private_key;

const TEST_HELLO_WORLD_STRING: &[u8] = b"hello world";

#[test]
pub fn test_generate_private_key() {
    const PRIVATE_KEY: &[u8] = generate_private_key!(2048);

    use rsa::{pkcs1::DecodeRsaPrivateKey, Pkcs1v15Encrypt, RsaPrivateKey};

    let priv_key = RsaPrivateKey::from_pkcs1_der(PRIVATE_KEY).unwrap();
    let mut rng = rand::thread_rng();
    
    let encrypted = priv_key.to_public_key()
        .encrypt(&mut rng, Pkcs1v15Encrypt, TEST_HELLO_WORLD_STRING).unwrap();
    let decrypted = priv_key.decrypt(Pkcs1v15Encrypt, &encrypted).unwrap();
    
    assert_eq!(TEST_HELLO_WORLD_STRING, decrypted)
}