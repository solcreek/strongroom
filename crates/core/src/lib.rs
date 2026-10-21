//! Versioned envelope cryptography. KMS, authorization and entropy belong to the host.
//! The internal bridge handles plaintext DEKs; never expose it as a public endpoint.
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAX_PLAINTEXT: usize = 65_536;

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
    pub key: String,
    pub nonce: String,
    pub ciphertext: String,
    pub wrapped_key: String,
}

fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
    B64.decode(s).map_err(|_| "invalid base64url")
}

fn aad(key: &str, ctx: &Context) -> Result<Vec<u8>, &'static str> {
    if key.is_empty()
        || key.len() > 64
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err("invalid key reference");
    }
    for s in [&ctx.tenant_id, &ctx.record_id, &ctx.purpose] {
        if s.is_empty() || s.len() > 256 {
            return Err("invalid context");
        }
    }
    serde_json::to_vec(&(
        "strongroom",
        1,
        "A256GCM",
        key,
        &ctx.tenant_id,
        &ctx.record_id,
        &ctx.purpose,
    ))
    .map_err(|_| "invalid context")
}

fn crypt(
    encrypt: bool,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err("invalid key or nonce");
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid key")?;
    let payload = Payload { msg: data, aad };
    if encrypt {
        cipher.encrypt(Nonce::from_slice(nonce), payload)
    } else {
        cipher.decrypt(Nonce::from_slice(nonce), payload)
    }
    .map_err(|_| "authentication failed")
}

/// 44 host-generated CSPRNG bytes: fresh 32-byte DEK and 12-byte nonce.
/// Plaintext is bytes; whether they are text is the host's concern.
pub fn seal(
    plaintext: &[u8],
    ctx: &Context,
    key: &str,
    entropy: &[u8],
) -> Result<Envelope, &'static str> {
    if plaintext.len() > MAX_PLAINTEXT || entropy.len() != 44 {
        return Err("invalid input size");
    }
    let ciphertext = crypt(
        true,
        &entropy[..32],
        &entropy[32..],
        plaintext,
        &aad(key, ctx)?,
    )?;
    Ok(Envelope {
        version: 1,
        algorithm: "A256GCM".into(),
        key: key.into(),
        nonce: B64.encode(&entropy[32..]),
        ciphertext: B64.encode(ciphertext),
        wrapped_key: String::new(),
    })
}

pub fn inspect(env: &Envelope, ctx: &Context) -> Result<Vec<u8>, &'static str> {
    if env.version != 1 || env.algorithm != "A256GCM" {
        return Err("unsupported envelope");
    }
    if env.nonce.len() != 16 || decode(&env.nonce)?.len() != 12 || env.ciphertext.len() > 87403 {
        return Err("invalid envelope");
    }
    let size = decode(&env.ciphertext)?.len();
    if !(16..=MAX_PLAINTEXT + 16).contains(&size)
        || env.wrapped_key.is_empty()
        || env.wrapped_key.len() > 16384
    {
        return Err("invalid envelope");
    }
    aad(&env.key, ctx)
}

pub fn open(env: &Envelope, ctx: &Context, dek: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let aad = inspect(env, ctx)?;
    crypt(
        false,
        dek,
        &decode(&env.nonce)?,
        &decode(&env.ciphertext)?,
        &aad,
    )
    .map(Zeroizing::new)
}

// Plaintext crosses the bridge as base64url bytes in both directions.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Command {
    Seal {
        plaintext: String,
        context: Context,
        key: String,
        entropy: String,
    },
    Inspect {
        envelope: Envelope,
        context: Context,
    },
    Open {
        envelope: Envelope,
        context: Context,
        dek: String,
    },
}

pub fn execute_json(input: &str) -> Result<String, &'static str> {
    if input.len() > 524288 {
        return Err("request too large");
    }
    let value = match serde_json::from_str(input).map_err(|_| "invalid request")? {
        Command::Seal {
            plaintext,
            context,
            key,
            entropy,
        } => {
            let plaintext = Zeroizing::new(plaintext);
            let data = Zeroizing::new(decode(&plaintext)?);
            let entropy = Zeroizing::new(entropy);
            let bytes = Zeroizing::new(decode(&entropy)?);
            serde_json::json!({"envelope": seal(&data, &context, &key, &bytes)?, "aad": B64.encode(aad(&key, &context)?)})
        }
        Command::Inspect { envelope, context } => {
            serde_json::json!({"aad": B64.encode(inspect(&envelope, &context)?)})
        }
        Command::Open {
            envelope,
            context,
            dek,
        } => {
            let dek = Zeroizing::new(dek);
            let bytes = Zeroizing::new(decode(&dek)?);
            let data = open(&envelope, &context, &bytes)?;
            let encoded = Zeroizing::new(B64.encode(&*data));
            serde_json::json!({"plaintext": encoded.as_str()})
        }
    };
    serde_json::to_string(&value).map_err(|_| "serialization failed")
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn execute(input: &str) -> Result<String, wasm_bindgen::JsValue> {
    execute_json(input).map_err(wasm_bindgen::JsValue::from_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ctx() -> Context {
        Context {
            tenant_id: "t".into(),
            record_id: "r".into(),
            purpose: "api-key".into(),
        }
    }
    fn envelope(data: &[u8]) -> Envelope {
        let mut e = seal(data, &ctx(), "primary", &[7; 44]).unwrap();
        e.wrapped_key = "opaque-kms-key".into();
        e
    }
    #[test]
    fn nist_vector() {
        let out = crypt(true, &[0; 32], &[0; 12], &[0; 16], &[]).unwrap();
        assert_eq!(
            out.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
    }
    #[test]
    fn roundtrip_boundaries() {
        for data in [
            vec![],
            "秘密🔑".as_bytes().to_vec(),
            vec![0xff, 0x00, 0xfe],
            vec![b'x'; MAX_PLAINTEXT],
        ] {
            assert_eq!(*open(&envelope(&data), &ctx(), &[7; 32]).unwrap(), data);
        }
        assert!(seal(&[b'x'; MAX_PLAINTEXT + 1], &ctx(), "primary", &[7; 44]).is_err());
        assert!(seal(b"x", &ctx(), "primary", &[7; 43]).is_err());
    }
    #[test]
    fn every_binding_and_ciphertext_is_authenticated() {
        let e = envelope(b"secret");
        for field in 0..3 {
            let mut c = ctx();
            match field {
                0 => c.tenant_id.push('x'),
                1 => c.record_id.push('x'),
                _ => c.purpose.push('x'),
            }
            assert!(open(&e, &c, &[7; 32]).is_err());
        }
        for field in 0..5 {
            let mut changed = e.clone();
            match field {
                0 => changed.key.push('x'),
                1 => changed.version = 2,
                2 => changed.algorithm = "none".into(),
                3 => changed.nonce = B64.encode([8; 12]),
                _ => {
                    let mut b = decode(&changed.ciphertext).unwrap();
                    b[0] ^= 1;
                    changed.ciphertext = B64.encode(b);
                }
            }
            assert!(open(&changed, &ctx(), &[7; 32]).is_err());
        }
        assert!(open(&e, &ctx(), &[8; 32]).is_err());
        assert!(open(&e, &ctx(), &[7; 31]).is_err());
    }
    #[test]
    fn malformed_input_fails_closed() {
        for s in [
            "{}",
            "null",
            "{\"op\":\"seal\",\"extra\":true}",
            "{\"op\":\"decrypt\"}",
        ] {
            assert!(execute_json(s).is_err());
        }
        let bridge = |plaintext: &str| {
            let input = serde_json::json!({"op": "seal", "plaintext": plaintext, "context": ctx(), "key": "primary", "entropy": B64.encode([7; 44])});
            execute_json(&input.to_string())
        };
        assert!(bridge("AP8").is_ok());
        for plaintext in ["not base64!", "AP8="] {
            assert!(bridge(plaintext).is_err());
        }
        let mut e = envelope(b"s");
        e.nonce.push('=');
        assert!(inspect(&e, &ctx()).is_err());
        e = envelope(b"s");
        e.wrapped_key.clear();
        assert!(inspect(&e, &ctx()).is_err());
        let mut c = ctx();
        c.purpose.clear();
        assert!(inspect(&envelope(b"s"), &c).is_err());
        assert!(seal(b"s", &ctx(), "../key", &[7; 44]).is_err());
    }
}
