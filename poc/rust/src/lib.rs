//! Comparison only: the fixed local wrapping key is PUBLIC and NOT a managed KMS.
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAX_PLAINTEXT: usize = 65536;
const MOCK_KEK: [u8; 32] = [0x42; 32];
const KEY_ID: &str = "INSECURE-POC-LOCAL-KEY";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Context {
    pub tenant_id: String,
    pub record_id: String,
    pub purpose: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub algorithm: String,
    pub key_id: String,
    pub nonce: String,
    pub wrapped_key: String,
    pub ciphertext: String,
}

fn aad(ctx: &Context) -> Result<Vec<u8>, String> {
    for s in [&ctx.tenant_id, &ctx.record_id, &ctx.purpose] {
        if s.is_empty() || s.len() > 256 {
            return Err("invalid context".into());
        }
    }
    serde_json::to_vec(&(
        "strongroom-poc",
        1,
        &ctx.tenant_id,
        &ctx.record_id,
        &ctx.purpose,
    ))
    .map_err(|_| "invalid context".into())
}

fn seal(key: &[u8], nonce: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err("invalid key or nonce".into());
    }
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| "invalid key")?
        .encrypt(Nonce::from_slice(nonce), Payload { msg: data, aad })
        .map_err(|_| "encryption failed".into())
}

fn open(key: &[u8], nonce: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err("invalid key or nonce".into());
    }
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| "invalid key")?
        .decrypt(Nonce::from_slice(nonce), Payload { msg: data, aad })
        .map_err(|_| "authentication failed".into())
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    B64.decode(value).map_err(|_| "invalid base64url".into())
}

/// Entropy comes from the host CSPRNG: 32 byte DEK, 12 byte data IV, 12 byte wrapping IV.
/// Exposed only for this benchmark. A production public API must not accept caller entropy.
pub fn encrypt(plaintext: &str, ctx: &Context, entropy: &[u8]) -> Result<Envelope, String> {
    if plaintext.len() > MAX_PLAINTEXT || entropy.len() != 56 {
        return Err("invalid input size".into());
    }
    let aad = aad(ctx)?;
    let key = Zeroizing::new(entropy[..32].to_vec());
    let ciphertext = seal(&key, &entropy[32..44], plaintext.as_bytes(), &aad)?;
    let mut wrapped = entropy[44..56].to_vec();
    wrapped.extend(seal(&MOCK_KEK, &entropy[44..56], &key, &aad)?);
    Ok(Envelope {
        version: 1,
        algorithm: "A256GCM".into(),
        key_id: KEY_ID.into(),
        nonce: B64.encode(&entropy[32..44]),
        wrapped_key: B64.encode(wrapped),
        ciphertext: B64.encode(ciphertext),
    })
}

pub fn decrypt(env: &Envelope, ctx: &Context) -> Result<String, String> {
    if env.version != 1 || env.algorithm != "A256GCM" || env.key_id != KEY_ID {
        return Err("unsupported envelope".into());
    }
    if env.ciphertext.len() > 87403 {
        return Err("invalid ciphertext size".into());
    }
    let aad = aad(ctx)?;
    let nonce = decode(&env.nonce)?;
    let wrapped = decode(&env.wrapped_key)?;
    if wrapped.len() != 60 {
        return Err("invalid wrapped key".into());
    }
    let key = Zeroizing::new(open(&MOCK_KEK, &wrapped[..12], &wrapped[12..], &aad)?);
    let data = decode(&env.ciphertext)?;
    if data.len() < 16 || data.len() > MAX_PLAINTEXT + 16 {
        return Err("invalid ciphertext size".into());
    }
    let plaintext = open(&key, &nonce, &data, &aad)?;
    String::from_utf8(plaintext).map_err(|_| "invalid utf8".into())
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Command {
    Encrypt {
        plaintext: String,
        context: Context,
        entropy: String,
    },
    Decrypt {
        envelope: Envelope,
        context: Context,
    },
}

pub fn execute_json(input: &str) -> Result<String, String> {
    if input.len() > 524288 {
        return Err("request too large".into());
    }
    let command: Command = serde_json::from_str(input).map_err(|_| "invalid request")?;
    match command {
        Command::Encrypt {
            plaintext,
            context,
            entropy,
        } => {
            let entropy = Zeroizing::new(decode(&entropy)?);
            serde_json::to_string(&encrypt(&plaintext, &context, &entropy)?)
                .map_err(|_| "serialization failed".into())
        }
        Command::Decrypt { envelope, context } => {
            serde_json::to_string(&serde_json::json!({"plaintext": decrypt(&envelope, &context)?}))
                .map_err(|_| "serialization failed".into())
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn execute(input: &str) -> Result<String, wasm_bindgen::JsValue> {
    execute_json(input).map_err(|e| wasm_bindgen::JsValue::from_str(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nist_aes256_gcm_vector() {
        let encrypted = seal(&[0; 32], &[0; 12], &[0; 16], &[]).unwrap();
        let hex: String = encrypted.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
    }
    #[test]
    fn tampering_and_context_are_rejected() {
        let mut ctx = Context {
            tenant_id: "a".into(),
            record_id: "b".into(),
            purpose: "c".into(),
        };
        let env = encrypt("fake-api-key", &ctx, &[1; 56]).unwrap();
        assert_eq!(decrypt(&env, &ctx).unwrap(), "fake-api-key");
        ctx.tenant_id = "another".into();
        assert!(decrypt(&env, &ctx).is_err());
        ctx.tenant_id = "a".into();
        let mut changed = env.clone();
        changed.version = 2;
        assert!(decrypt(&changed, &ctx).is_err());
        let mut changed = env;
        let mut bytes = decode(&changed.ciphertext).unwrap();
        bytes[0] ^= 1;
        changed.ciphertext = B64.encode(bytes);
        assert!(decrypt(&changed, &ctx).is_err());
    }
}
