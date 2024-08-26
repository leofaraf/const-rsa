use proc_macro::TokenStream;
use rsa::{pkcs1::EncodeRsaPrivateKey, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

#[proc_macro]
pub fn generate_private_key(_item: TokenStream) -> TokenStream {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    
    format!("&[{}]",
    priv_key.to_pkcs1_der().unwrap().as_bytes()
    .iter().map(|b| format!("{:}", b)).collect::<Vec<String>>()
    .join(", ")
    )
    .parse().unwrap()
}