use const_rsa::{encrypt_from_pkcs1_pem_private, generate_encrypted_strings};

use base64::{prelude::BASE64_STANDARD, Engine};
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

generate_encrypted_strings!("-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsYJznyquOBgD/fdaeNIbeZnyH0odNWRMNgqTL+A8K/YJ0ucB
E9LT4felmblD89ZPSHbvv4r1D0LoA9mRtAjCN31KjFqvpqx9suA+jQMKcEu7PsVy
6SnmleGLp6OQ2jH9t2Z8a3Hs7xVzyBhymtffRoHQ50jaokLSTkiMnfKP1rPos7Nk
Kbu8aXemFC73kkZUwlOBEalCr78SEEgTCCjOmMd2qk09wbqg//MwBol3ceJYvvAO
m2AW85wGfjbbZyrHZqwHDHvOpVCcMl4eVSqAA2E9VSjs6lpew4c82fdSkHBRvaFK
nYacQofBHmK1GPasXtXzVMN1ydAfacNuVrt5VwIDAQABAoIBAAXawRh7TmKwPBV4
voWknF5e2vL4PU1hAPh5UdBu610h0MIhd1IhjnZx9gbDav/UTiocLh0Zpqp5sPBL
kTgoX8t3uOk3JnrvTngDWFzLQGFixgq0dW1GQgIofbQqO2FO68jMOwdKKx/Zi8eK
MuFzhDwtlOfD6d4XKRuG3ghpkx/oIgW911S9NSBscvw6Kd+HItE8kZ2aN5w1DRCz
k5wujSf/sjKRIpl4f8ci/v4Rkaqcb5wwBksM/EO5Jda8MiFP3E9vM0mcdEh0BYqA
aUIKHMzIlOMIqUVBdwo57qsDCP+VL2odBtf3pIQRc4nVBoADad4WKEfvTQIgA2mk
4vF8+H0CgYEA5wK3BPZhhQUnRwGzaGnCzBzS3nHyPWm9ne+rOUwXCQpFIOjzyqkC
jaarywShN+CruYmv4HBaRU211QA18QjGdgT15VFYhUxkCeVfBEnyObP7dUaqPnfG
uXto5DGfHJ3UaDma4Ost0GjxwO+/x6GSqsFFykr2ZAMhTawoCDhdmasCgYEAxLYn
ajSmkH/mjzIWZxqn2lLJyYKKSSV5z9ONmDVyjaYYbgDpCKtFsifbx6g+YgLIGDw4
9UAhb7xabmHe8LRCXxXaDQbojf38+cCJZ5DzIHtpIwCDgFOT6B3H5n3ccZD+7NsV
Kc0OTUacQ+Tm/Ta8E+nzmm4bXNBziZglTr4HawUCgYBZ+tW86hbsECjPYJs4BVHp
3SRJnsqDH0fLV8oyxC+IxuZMPlCPVKt47z2lE0WUlT9uQnIuErUmn3E+6RkZrJhY
6e+5hajcKvggXqZW7lKaJT/B22d+c3sFTkt57tYR+Gv+uMlZ6GDs96OKyhfCM24E
csmzVOWJ6So0reTd5s6WhwKBgGe99S2C1PFSMsMEVGJN4YY3sSnwCYQoGoTrejpy
vZZMqYeiPUQQJ7KcaMF0TmocM3DsmdFl3/xwpnSecxgYyQQinxvNr+nqsHb6/rw6
6q4Px9Po2nFcIp4AzsMVT6QpJvi9Vfz0ov1IJvN7jgKu0iPid1HTjeS2HqjLL6nG
eF0NAoGBAJGzZ4BX35JqHPBdQJrx0vLvWkfVRJ4ildO8VcmjNE4H4T0W1cK7N9OR
HQ1a0uMPajq0WykJTQwHH8Xp3bmdf8tV9/ersst8/ZaZw8I2cVs5LB7ITGg50R7c
F1eoz1rhDByXDbnvO8PIUV27BSIXlKHEW1Urlo7WU9lYPCcjf9FD
-----END RSA PRIVATE KEY-----", 
    [
        ("decryped_hello", "hello"),
        ("decryped_world", "world"),
    ]
);

#[test]
fn test_hello() {
    assert_eq!(get_decryped_hello(), "hello")
}

#[test]
fn test_world() {
    assert_eq!(get_decryped_world(), "world")
}