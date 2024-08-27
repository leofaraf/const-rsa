use proc_macro::{Literal, TokenStream, TokenTree};
use rsa::{pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use syn::{parse_macro_input, LitByteStr};

/// Creates RSA private key.
fn create_private_key(bits: usize) -> RsaPrivateKey {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    priv_key
}

const DEFAULT_2048_PRIVATE_KEY_BITS: usize = 2048;

/// Accepts token steam.
/// If token stream contains `usize`, then returns it's value, 
/// If not contains, then return `2048` bits.
fn bits_from_token_stream(_item: TokenStream) -> usize {
    match _item.into_iter().next() {
        Some(token) => match token {
            TokenTree::Literal(some) => some.to_string()
                .parse().unwrap_or(DEFAULT_2048_PRIVATE_KEY_BITS),
            _ => DEFAULT_2048_PRIVATE_KEY_BITS,
        },
        None => DEFAULT_2048_PRIVATE_KEY_BITS
    }
}

fn token_stream_string_from_bytes(bytes: &[u8]) -> String {
    format!("&[{}]", bytes
        .iter().map(|b| format!("{:}", b)).collect::<Vec<String>>()
        .join(", ")
    )
}

#[proc_macro]
/// Accepts token steam.
/// If token stream contains `usize`, then sets it as private key bits, 
/// If not contains, then sets `2048` as private key bits.
/// Returns pkcs1_der private key as bytes (`&[u8]`)
pub fn generate_private_key(_item: TokenStream) -> TokenStream {
    let bits = bits_from_token_stream(_item);
    let priv_key = create_private_key(bits);

    token_stream_string_from_bytes(
        priv_key.to_pkcs1_der().unwrap().as_bytes()
    ).parse().unwrap()
}

#[proc_macro]
pub fn encrypt_from_pkcs1_der(_item: TokenStream) -> TokenStream {
    todo!()
}

#[proc_macro]
pub fn encrypt_from_pkcs1_pem(_item: TokenStream) -> TokenStream {
    todo!()
}

#[proc_macro]
pub fn encrypt_from_pkcs1_der_private(_item: TokenStream) -> TokenStream {
    todo!()
}

#[proc_macro]
pub fn encrypt_from_pkcs1_pem_private(_item: TokenStream) -> TokenStream {
    todo!()
}

#[proc_macro]
pub fn decrypt_from_pkcs1_der_private(_item: TokenStream) -> TokenStream {
    todo!()
}

#[proc_macro]
pub fn decrypt_from_pkcs1_pem_private(_item: TokenStream) -> TokenStream {
    todo!()
}

#[cfg(test)]
pub mod tests {
    pub mod create_private_key {
        use crate::create_private_key;

        const TEST_HELLO_WORLD_STRING: &[u8] = b"hello world";

        #[test]
        pub fn test_create_private_key() {
            use rsa::Pkcs1v15Encrypt;

            let priv_key = create_private_key(2048);
            let mut rng = rand::thread_rng();
            
            let encrypted = priv_key.to_public_key()
                .encrypt(&mut rng, Pkcs1v15Encrypt, TEST_HELLO_WORLD_STRING).unwrap();
            let decrypted = priv_key.decrypt(Pkcs1v15Encrypt, &encrypted).unwrap();
            
            assert_eq!(TEST_HELLO_WORLD_STRING, decrypted)
        }
    }
}