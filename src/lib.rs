use base62;
use base64;
use digest::{Digest, Mac};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use hmac::Hmac;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Sha256;
use std::io::{Read, Write};
pub use time::Duration; // re-export
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

#[cfg(feature = "python")]
mod python;

#[derive(Debug)]
pub enum SignatureError {
    MissingSeparator,
    FormatError,
    InvalidSignature,
    MissingTimestamp,
    TimestampFormatError,
    SignatureExpired,
    ObjectFormatError,
}

pub trait Signer {
    fn sign(&self, value: String) -> String;

    fn unsign(&self, signed_value: String) -> Result<String, SignatureError>;

    fn sign_object<T>(&self, obj: T, compress: bool) -> String
    where
        T: Serialize;

    fn unsign_object<T>(&self, signed_object: String) -> Result<T, SignatureError>
    where
        T: DeserializeOwned;
}

pub trait TimedSigner: Signer {
    fn unsign_with_age(
        &self,
        signed_value: String,
        max_age: Duration,
    ) -> Result<String, SignatureError>;

    fn unsign_object_with_age<T>(
        &self,
        signed_value: String,
        max_age: Duration,
    ) -> Result<T, SignatureError>
    where
        T: DeserializeOwned;
}

pub struct BaseSigner {
    key: Vec<u8>,
}

impl BaseSigner {
    pub fn new(key: &[u8], salt: &[u8]) -> Self {
        // https://github.com/django/django/blob/ca04659b4b3f042c1bc7e557c25ed91e3c56c745/django/core/signing.py#L160
        let mut new_salt = Vec::with_capacity(salt.len() + 6);
        new_salt.extend_from_slice(salt);
        new_salt.extend(b"signer");

        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&new_salt[..]);
        inner_hasher.update(key);

        Self {
            key: inner_hasher.finalize().to_vec(),
        }
    }
    fn get_mac_with_value(&self, value: &[u8]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.key[..]).unwrap();
        mac.update(value);
        mac
    }
    fn encoded_signature(&self, value: &[u8]) -> String {
        let mac = self.get_mac_with_value(value);
        base64::encode_config(mac.finalize().into_bytes(), base64::URL_SAFE_NO_PAD)
    }

    pub fn decode_object<T>(&self, value: String) -> Result<T, SignatureError>
    where
        T: DeserializeOwned,
    {
        let (decompress, encoded_value) = match value.strip_prefix(".") {
            Some(remainder) => (true, remainder.as_bytes()),
            None => (false, value.as_bytes()),
        };
        let mut decoded_value =
            base64::decode_config(encoded_value, base64::URL_SAFE_NO_PAD).unwrap();
        if decompress {
            let mut decoder = ZlibDecoder::new(&decoded_value[..]);
            let mut unpacked = String::new();
            decoder.read_to_string(&mut unpacked).unwrap();
            decoded_value = unpacked.into();
        }
        match serde_json::from_slice(&decoded_value[..]) {
            Ok(obj) => Ok(obj),
            Err(_) => Err(SignatureError::ObjectFormatError),
        }
    }

    pub fn encode_object<T>(&self, obj: T, compress: bool) -> String
    where
        T: Serialize,
    {
        let mut value = serde_json::to_vec(&obj).unwrap();
        let mut is_compressed = false;
        if compress {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write(&value[..]).unwrap();
            let compressed = encoder.finish().unwrap();
            if compressed.len() < value.len() - 1 {
                value = compressed;
                is_compressed = true;
            }
        }
        let mut value = base64::encode_config(value, base64::URL_SAFE_NO_PAD);
        if is_compressed {
            value.insert(0, '.');
        }
        value
    }
}

impl Signer for BaseSigner {
    fn sign(&self, value: String) -> String {
        format!("{}:{}", value, self.encoded_signature(value.as_bytes()))
    }
    fn unsign(&self, signed_value: String) -> Result<String, SignatureError> {
        if let Some((value, sig)) = signed_value.rsplit_once(":") {
            if let Ok(decoded_sig) = base64::decode_config(sig, base64::URL_SAFE_NO_PAD) {
                let mac = self.get_mac_with_value(value.as_bytes());
                if let Ok(_) = mac.verify_slice(&decoded_sig[..]) {
                    Ok(value.to_string())
                } else {
                    Err(SignatureError::InvalidSignature)
                }
            } else {
                Err(SignatureError::FormatError)
            }
        } else {
            Err(SignatureError::MissingSeparator)
        }
    }

    fn sign_object<T>(&self, obj: T, compress: bool) -> String
    where
        T: Serialize,
    {
        let value = self.encode_object(obj, compress);
        self.sign(value)
    }
    fn unsign_object<T>(&self, signed_object: String) -> Result<T, SignatureError>
    where
        T: DeserializeOwned,
    {
        let unsigned = self.unsign(signed_object);
        match unsigned {
            Ok(value) => self.decode_object(value),
            Err(e) => Err(e),
        }
    }
}

pub struct TimestampSigner {
    inner: BaseSigner,
}

impl TimestampSigner {
    pub fn new(key: &[u8], salt: &[u8]) -> Self {
        Self {
            inner: BaseSigner::new(key, salt),
        }
    }
}

impl Signer for TimestampSigner {
    fn sign(&self, value: String) -> String {
        let timestamp = OffsetDateTime::now_utc().unix_timestamp() as u64;
        let value = format!("{}:{}", value, base62::encode(timestamp));
        self.inner.sign(value)
    }
    fn unsign(&self, signed_value: String) -> Result<String, SignatureError> {
        let unsigned = self.inner.unsign(signed_value);
        match unsigned {
            Err(e) => Err(e),
            Ok(timestamped_value) => {
                if let Some((value, _)) = timestamped_value.rsplit_once(":") {
                    Ok(value.to_string())
                } else {
                    Err(SignatureError::MissingTimestamp)
                }
            }
        }
    }

    fn sign_object<T>(&self, obj: T, compress: bool) -> String
    where
        T: Serialize,
    {
        let value = self.inner.encode_object(obj, compress);
        self.sign(value)
    }

    fn unsign_object<T>(&self, signed_object: String) -> Result<T, SignatureError>
    where
        T: DeserializeOwned,
    {
        match self.unsign(signed_object) {
            Ok(value) => self.inner.decode_object(value),
            Err(e) => Err(e),
        }
    }
}

impl TimedSigner for TimestampSigner {
    fn unsign_with_age(
        &self,
        signed_value: String,
        max_age: Duration,
    ) -> Result<String, SignatureError> {
        let unsigned = self.inner.unsign(signed_value);
        match unsigned {
            Err(e) => Err(e),
            Ok(timestamped_value) => {
                if let Some((value, timestamp)) = timestamped_value.rsplit_once(":") {
                    if let Ok(timestamp) = base62::decode(timestamp) {
                        if let Ok(timestamp) = OffsetDateTime::from_unix_timestamp(timestamp as i64)
                        {
                            let distance = OffsetDateTime::now_utc() - timestamp;
                            if distance <= max_age {
                                Ok(value.to_string())
                            } else {
                                Err(SignatureError::SignatureExpired)
                            }
                        } else {
                            Err(SignatureError::TimestampFormatError)
                        }
                    } else {
                        Err(SignatureError::TimestampFormatError)
                    }
                } else {
                    Err(SignatureError::MissingTimestamp)
                }
            }
        }
    }

    fn unsign_object_with_age<T>(
        &self,
        signed_value: String,
        max_age: Duration,
    ) -> Result<T, SignatureError>
    where
        T: DeserializeOwned,
    {
        match self.unsign_with_age(signed_value, max_age) {
            Ok(value) => self.inner.decode_object(value),
            Err(e) => Err(e),
        }
    }
}

pub fn dumps<T>(obj: T, key: &[u8], salt: &[u8], compress: bool) -> String
where
    T: Serialize,
{
    let signer = TimestampSigner::new(key, salt);
    signer.sign_object(obj, compress)
}

pub fn loads<T>(
    signed_value: String,
    key: &[u8],
    salt: &[u8],
    max_age: Duration,
) -> Result<T, SignatureError>
where
    T: DeserializeOwned,
{
    let signer = TimestampSigner::new(key, salt);
    signer.unsign_object_with_age(signed_value, max_age)
}
