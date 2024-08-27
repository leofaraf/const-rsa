use proc_macro::{Literal, TokenStream, TokenTree};
use rsa::{pkcs1::EncodeRsaPrivateKey, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};


fn create_private_key(bits: usize) -> RsaPrivateKey {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    priv_key
}

const DEFAULT_2048_PRIVATE_KEY_BITS: usize = 2048;

/// Accepts token steam
/// If token stream contains `usize`, then returns it's value, 
/// If not contains, then return `2048` bits
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

#[proc_macro]
pub fn generate_private_key(_item: TokenStream) -> TokenStream {
    let bits = bits_from_token_stream(_item);
    let priv_key = create_private_key(bits);

    format!("&[{}]",
    priv_key.to_pkcs1_der().unwrap().as_bytes()
    .iter().map(|b| format!("{:}", b)).collect::<Vec<String>>()
    .join(", ")
    )
    .parse().unwrap()
}

#[cfg(test)]
pub mod tests {
    pub mod bits_from_token_stream {
        use crate::{
            bits_from_token_stream,
            DEFAULT_2048_PRIVATE_KEY_BITS
        };

        const INCORRECT_TOKEN_STREAM: &str = "incorrect value";
        const TEST_BYTES_COUNT: usize = 1488;

        #[cfg(test)]
        pub fn test_bits_from_correct_token_stream() {
            let bits = bits_from_token_stream(TEST_BYTES_COUNT.to_string().parse().unwrap());
            assert_eq!(TEST_BYTES_COUNT, bits)
        }

        #[cfg(test)]
        pub fn test_bits_from_incorrect_token_stream() {
            let bits = bits_from_token_stream(INCORRECT_TOKEN_STREAM.parse().unwrap());
            assert_eq!(DEFAULT_2048_PRIVATE_KEY_BITS, bits)
        }
    }
}