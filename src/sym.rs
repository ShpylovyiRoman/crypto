use aes_gcm::{
    aead::{AeadInPlace, NewAead},
    Aes256Gcm, Key as AesKey, Nonce, Tag,
};
use anyhow::anyhow;
use argon2::{Config, ThreadMode, Variant, Version};
use rand::Rng;

pub const AES_KEY_LEN: usize = 32;
const AES_NONCE_LEN: usize = 12;
const AES_TAG_LEN: usize = 16;

const ARGON_SALT: &[u8] = b"labs.security.kpi";
const ARGON_CONFIG: Config = Config {
    ad: &[],
    hash_length: AES_KEY_LEN as u32,
    lanes: 8,
    mem_cost: 1 << 16,
    secret: &[],
    thread_mode: ThreadMode::Sequential,
    time_cost: 4,
    variant: Variant::Argon2i,
    version: Version::Version13,
};

pub struct Cipher {
    cipher: Aes256Gcm,
}

#[derive(Clone)]
pub struct Key([u8; AES_KEY_LEN]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Key(<key>)")
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Key {
    pub fn random() -> Self {
        let mut this = Self([0; AES_KEY_LEN]);
        rand::thread_rng().fill(&mut this.0);
        this
    }

    pub fn from_slice(key: &[u8]) -> anyhow::Result<Self> {
        Ok(Self(key.try_into().map_err(|_| {
            anyhow!(
                "incorrect key length: {} but expected {}",
                key.len(),
                AES_KEY_LEN
            )
        })?))
    }

    pub fn from_pass(pass: &str) -> anyhow::Result<Self> {
        let key = argon2::hash_raw(pass.as_bytes(), ARGON_SALT, &ARGON_CONFIG)?;
        Ok(Self(key.try_into().expect("length is ok")))
    }
}

impl Cipher {
    pub fn new(key: &Key) -> Self {
        let key = AesKey::from_slice(key.as_ref());
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    pub fn encrypt(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut nonce = [0u8; AES_NONCE_LEN];
        rand::thread_rng().fill(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        // result = nonce || tag || ciphertext
        let mut result = vec![0u8; AES_NONCE_LEN + AES_TAG_LEN + msg.len()];
        let (nonce_buff, tag_data) = result.split_at_mut(AES_NONCE_LEN);
        let (tag_buff, data) = tag_data.split_at_mut(AES_TAG_LEN);
        nonce_buff.copy_from_slice(nonce);
        data.copy_from_slice(msg);

        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, &[], data)
            .map_err(|_| anyhow!("can't derive the tag"))?;

        tag_buff.copy_from_slice(&tag);

        Ok(result)
    }

    pub fn decrypt(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decryption = || anyhow!("decryption error");

        if msg.len() < AES_NONCE_LEN + AES_TAG_LEN {
            return Err(decryption());
        }

        let (nonce, tag_data) = msg.split_at(AES_NONCE_LEN);
        let (tag, data) = tag_data.split_at(AES_TAG_LEN);

        let nonce = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag);

        let mut buff = data.to_vec();
        self.cipher
            .decrypt_in_place_detached(nonce, &[], &mut buff, tag)
            .map_err(|_| decryption())?;

        Ok(buff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_dec() {
        let key = Key::random();
        let cipher = Cipher::new(&key);
        let msg = r#"
         _____________________________________________________________________________
        / Microsoft is not the answer.                                                \
        | Microsoft is the question.                                                  |
        | NO (or Linux) is the answer.                                                |
        \         -- Taken from a .signature from someone from the UK, source unknown /
          -----------------------------------------------------------------------------
           \
            \
                .--.
               |o_o |
               |:_/ |
              //   \ \
             (|     | )
            /'\_   _/`\
            \___)=(___/

        "#
        .as_bytes();

        let encrypted = cipher.encrypt(msg).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn enc_dec_empty() {
        let key = Key::random();
        let cipher = Cipher::new(&key);
        let msg = b"";

        let encrypted = cipher.encrypt(msg).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn enc_dec_pass() {
        let key =
            Key::from_pass("grudging-synthetic-guacamole-stratus-grumbling-urethane").unwrap();

        let cipher = Cipher::new(&key);

        let msg = b"happy new year";

        let encrypted = cipher.encrypt(msg).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }
}
