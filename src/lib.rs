use base64::{prelude::BASE64_STANDARD, Engine};
use proc_macro::{TokenStream, TokenTree};
use proc_macro2::{Ident, Literal, Span};
use rand::{thread_rng, Rng};
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use syn::{parse::{Parse, ParseStream}, parse_macro_input, token::{Bracket, In}, Error, Expr, ExprArray, ExprTuple, Lit, LitByteStr, LitStr, Result, Token};

/// Creates RSA private key.
fn create_private_key(bits: usize) -> RsaPrivateKey {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    priv_key
}

const DEFAULT_2048_PRIVATE_KEY_BITS: usize = 2048;

fn bytes_from_token_stream(_item: TokenStream) -> &'static [u8] {
    todo!()
}

fn string_from_token_stream(_item: TokenStream) -> String {
    todo!()
}

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

#[derive(Debug)]
struct Input {
    pub rsa_key: String,
    pub nested_array: Vec<(String, String)>,
}

// Function to extract string literals from expressions
fn extract_string_literal(expr: &Expr) -> Option<String> {
    if let Expr::Lit(expr_lit) = expr {
        if let Lit::Str(lit_str) = &expr_lit.lit {
            return Some(lit_str.value());
        }
    }
    None
}

impl Parse for Input {
    fn parse(input: ParseStream) -> Result<Self> {
        // Parse the RSA key
        let rsa_key: LitStr = input.parse()?;

        let _comma: Token![,] = input.parse()?;

        let expr: ExprArray = input.parse()?;

        let mut result = Vec::new();

        // Iterate over each tuple in the array
        for elem in expr.elems.iter() {
            if let Expr::Tuple(tuple) = elem {
                if tuple.elems.len() == 2 {
                    let key_expr = &tuple.elems[0];
                    let value_expr = &tuple.elems[1];

                    let key_str = extract_string_literal(key_expr);
                    let value_str = extract_string_literal(value_expr);

                    if let (Some(key), Some(value)) = (key_str, value_str) {
                        result.push((key, value));
                    } else {
                        return Err(Error::new_spanned(
                            tuple,
                            "Expected string literals for both key and value",
                        ));
                    }
                } else {
                    return Err(Error::new_spanned(
                        tuple,
                        "Expected a tuple of 2 elements for key-value pair",
                    ));
                }
            } else {
                return Err(Error::new_spanned(elem, "Expected a tuple expression"));
            }
        }

        Ok(Input {
            nested_array: result,
            rsa_key: rsa_key.value(),
        })
    }
}



#[proc_macro]
pub fn generate_encrypted_strings(_item: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(_item as Input);

    let rsa = parsed.rsa_key.clone();
    let mut results = vec![];

    let priv_key = match RsaPrivateKey::from_pkcs1_pem(&parsed.rsa_key) {
        Ok(priv_key) => priv_key,
        Err(_) => return quote::quote! {
            compile_error!("first arg should be PEM RSA private key")
        }.into()
    };

    let pub_key = priv_key.to_public_key();
    let mut rng = thread_rng();
    
    for item in parsed.nested_array {
        let encryped_string = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, item.1.as_bytes()).unwrap();

        let span = Span::call_site();
        let function_name = Ident::new(&format!("get_{}", item.0), span);
        let bytes = BASE64_STANDARD.encode(encryped_string);

        results.push(
            quote::quote! {
                pub fn #function_name() -> String {
                    let priv_key = RsaPrivateKey::from_pkcs1_pem(#rsa).unwrap();
                    let decrypted = BASE64_STANDARD.decode(#bytes).unwrap();
                    let bytes = priv_key.decrypt(Pkcs1v15Encrypt, &decrypted).unwrap();

                    String::from_utf8(bytes).unwrap()
                }
            }
        )
    }

    println!("{}", format!("{}", results[0]));

    quote::quote! {
        #(#results)*
    }.into()
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
    let input = parse_macro_input!(_item as LitStr);

    "&[]".parse().unwrap()
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
