extern crate crypto;

use ring;
use ring::{agreement, rand, digest};
use ring::rand::{SystemRandom, SecureRandom};
use self::crypto::{aes, blockmodes};
use self::crypto::buffer::{RefWriteBuffer, RefReadBuffer, WriteBuffer};
// Updated imports for ring 0.17+
use ring::hmac::{self, Key as HmacKey, Tag as HmacTag};
use ring::hkdf::{self, HKDF_SHA256, KeyType};

// Define a type alias to simplify Result type
type Result<T> = std::result::Result<T, Error>;

use crate::MediaType;
use crate::errors::*;

pub(crate) fn generate_keypair() -> (agreement::EphemeralPrivateKey, Vec<u8>) {
    let rng = rand::SystemRandom::new();

    let my_private_key =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();

    // In the updated ring API, compute_public_key() returns a PublicKey
    let public_key = my_private_key.compute_public_key().unwrap();
    let my_public_key = public_key.as_ref().to_vec();

    (my_private_key, my_public_key)
}

pub(crate) fn calculate_secret_keys(secret: &[u8], private_key: agreement::EphemeralPrivateKey) -> Result<([u8; 32], [u8; 32])> {
    // Create an UnparsedPublicKey from the raw bytes
    let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, &secret[..32]);

    // Use the new API for agreement and explicitly annotate the type
    let secret_key_vec: Vec<u8> = agreement::agree_ephemeral(
        private_key,
        &peer_public_key,
        |key_material| Vec::from(key_material)
    ).map_err(|_| Error::from_kind(ErrorKind::Msg("Key agreement failed".to_string())))?;
    
    let mut secret_key_expanded = [0u8; 80];

    let salt = hkdf::Salt::new(HKDF_SHA256, &[0u8; 32]);
    let prk = salt.extract(&secret_key_vec);
    
    // Use empty slice for info
    let info: &[&[u8]] = &[];
    let okm = prk.expand(info, HKDF_SHA256)
        .map_err(|_| Error::from_kind(ErrorKind::Msg("HKDF expand failed".to_string())))?;
    
    // Fill the output buffer
    okm.fill(&mut secret_key_expanded)
        .map_err(|_| Error::from_kind(ErrorKind::Msg("HKDF fill failed".to_string())))?;

    let signature = [&secret[..32], &secret[64..]].concat();

    let key = hmac::Key::new(hmac::HMAC_SHA256, &secret_key_expanded[32..64]);
    hmac::verify(&key, &signature, &secret[32..64])
        .map_err(|_| Error::from_kind(ErrorKind::Msg("Invalid mac".to_string())))?;

    let mut buffer = [0u8; 64];

    aes_decrypt(&secret_key_expanded[..32], &secret_key_expanded[64..], &secret[64..144], &mut buffer);

    let mut enc = [0; 32];
    let mut mac = [0; 32];

    enc.copy_from_slice(&buffer[..32]);
    mac.copy_from_slice(&buffer[32..]);


    Ok((enc, mac))
}

pub fn verify_and_decrypt_message(enc: &[u8], mac: &[u8], message_encrypted: &[u8]) -> Result<Vec<u8>> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &mac);
    hmac::verify(&key, &message_encrypted[32..], &message_encrypted[..32])
        .map_err(|_| Error::from_kind(ErrorKind::Msg("Invalid mac".to_string())))?;

    let mut message = vec![0u8; message_encrypted.len() - 48];

    let size_without_padding = aes_decrypt(enc, &message_encrypted[32..48], &message_encrypted[48..], &mut message);
    message.truncate(size_without_padding);
    Ok(message)
}

pub(crate) fn sign_and_encrypt_message(enc: &[u8], mac: &[u8], message: &[u8]) -> Vec<u8> {
    let mut message_encrypted = vec![0u8; 32 + 16 + message.len() + 32];


    let mut iv = vec![0u8; 16];
    SystemRandom::new().fill(&mut iv).unwrap();

    let size_with_padding = aes_encrypt(enc, &iv, &message, &mut message_encrypted[48..]);
    message_encrypted.truncate(32 + 16 + size_with_padding);

    message_encrypted[32..48].clone_from_slice(&iv);

    let key = hmac::Key::new(hmac::HMAC_SHA256, &mac);
    let tag = hmac::sign(&key, &message_encrypted[32..]);

    message_encrypted[0..32].clone_from_slice(tag.as_ref());
    message_encrypted
}

pub(crate) fn sign_challenge(mac: &[u8], challenge: &[u8]) -> HmacTag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &mac);
    hmac::sign(&key, &challenge)
}

fn derive_media_keys(key: &[u8], media_type: MediaType) -> [u8; 112] {
    let mut media_key_expanded = [0u8; 112];
    // Use a consistent string length for all media types
    let info = match media_type {
        MediaType::Image => b"WhatsApp Image Keys".as_ref(),
        MediaType::Video => b"WhatsApp Video Keys".as_ref(),
        MediaType::Audio => b"WhatsApp Audio Keys".as_ref(),
        MediaType::Document => b"WhatsApp Document Keys".as_ref(),
    };
    let salt = hkdf::Salt::new(HKDF_SHA256, &[0u8; 32]);
    let prk = salt.extract(key);
    
    // Convert info bytes to required format for expand
    let info_slice: &[&[u8]] = &[info];
    
    let okm = prk.expand(info_slice, HKDF_SHA256).expect("HKDF expand failed");
    okm.fill(&mut media_key_expanded).expect("HKDF fill failed");
    media_key_expanded
}

pub fn sha256(file: &[u8]) -> Vec<u8> {
    let mut hash = Vec::with_capacity(32);
    hash.extend_from_slice(digest::digest(&digest::SHA256, file).as_ref());
    hash
}

pub fn encrypt_media_message(media_type: MediaType, file: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut media_key = vec![0u8; 32];
    SystemRandom::new().fill(&mut media_key).unwrap();
    let media_key_expanded = derive_media_keys(&media_key, media_type);

    let mut file_encrypted = vec![0u8; 10 + file.len() + 32];


    let mut cipher_key = Vec::with_capacity(32);
    cipher_key.extend_from_slice(&media_key_expanded[16..48]);

    let iv = &media_key_expanded[0..16];

    let size_with_padding = aes_encrypt(&cipher_key, iv, &file, &mut file_encrypted);
    file_encrypted.truncate(size_with_padding);

    let hmac_data = [iv, &file_encrypted].concat();

    let key = hmac::Key::new(hmac::HMAC_SHA256, &media_key_expanded[48..80]);
    let tag = hmac::sign(&key, &hmac_data);

    file_encrypted.extend_from_slice(&tag.as_ref()[0..10]);
    (file_encrypted, media_key)
}

pub fn decrypt_media_message(key: &[u8], media_type: MediaType, file_encrypted: &[u8]) -> Result<Vec<u8>> {
    let media_key_expanded = derive_media_keys(key, media_type);

    let mut file = vec![0u8; file_encrypted.len() - 10];

    let mut cipher_key = Vec::with_capacity(32);
    cipher_key.extend_from_slice(&media_key_expanded[16..48]);

    let size = file_encrypted.len();

    let hmac_data = [&media_key_expanded[0..16], &file_encrypted[..size - 10]].concat();

    let key = hmac::Key::new(hmac::HMAC_SHA256, &media_key_expanded[48..80]);
    let tag = hmac::sign(&key, &hmac_data);

    if file_encrypted[(size - 10)..] != tag.as_ref()[..10] {
        bail! {"Invalid mac"}
    }


    let size_without_padding = aes_decrypt(&cipher_key, &media_key_expanded[0..16], &file_encrypted[..size - 10], &mut file);
    file.truncate(size_without_padding);

    Ok(file)
}

pub(crate) fn aes_encrypt(key: &[u8], iv: &[u8], input: &[u8], output: &mut [u8]) -> usize {
    let mut aes_encrypt = aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut read_buffer = RefReadBuffer::new(input);

    let mut write_buffer = RefWriteBuffer::new(output);

    aes_encrypt.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
    write_buffer.position()
}

pub(crate) fn aes_decrypt(key: &[u8], iv: &[u8], input: &[u8], output: &mut [u8]) -> usize {
    let mut aes_decrypt = aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut read_buffer = RefReadBuffer::new(input);

    let mut write_buffer = RefWriteBuffer::new(output);

    aes_decrypt.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
    write_buffer.position()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use node_wire::Node;
    use std::io::stdin;


    #[test]
    #[ignore]
    fn decrypt_node_from_browser() {
        let enc = base64::decode("").unwrap();

        let mac = base64::decode("").unwrap();

        loop {
            let mut line = String::new();
            stdin().read_line(&mut line).unwrap();
            let len = line.len();
            line.truncate(len - 1);
            let msg = base64::decode(&line).unwrap();
            let pos = msg.iter().position(|x| x == &b',').unwrap() + 3;

            let dec_msg = verify_and_decrypt_message(&enc, &mac, &msg[pos..]).unwrap();

            let node = Node::deserialize(&dec_msg).unwrap();

            println!("{:?}", node);
        }
    }

    #[test]
    fn test_encrypt_decrypt_message() {
        let mut enc = vec![0u8; 32];
        SystemRandom::new().fill(&mut enc).unwrap();

        let mut mac = vec![0u8; 32];
        SystemRandom::new().fill(&mut mac).unwrap();

        let mut msg = vec![0u8; 30];
        SystemRandom::new().fill(&mut msg).unwrap();
        let enc_msg = sign_and_encrypt_message(&enc, &mac, &msg);

        let dec_msg = verify_and_decrypt_message(&enc, &mac, &enc_msg).unwrap();

        assert_eq!(msg, dec_msg);
    }

    #[test]
    fn test_encrypt_decrypt_media() {
        let mut msg = vec![0u8; 300];
        SystemRandom::new().fill(&mut msg).unwrap();

        let media_type = MediaType::Image;

        let (enc_msg, key) = encrypt_media_message(media_type, &msg);

        let dec_msg = decrypt_media_message(&key, media_type, &enc_msg).unwrap();

        assert_eq!(msg, dec_msg);
    }
}
