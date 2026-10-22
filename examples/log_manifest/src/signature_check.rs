//! Signature (COSE authentication block) reporting and optional verification.
use std::fmt;
use std::path::Path;

use cose::algs;
use cose::keys::CoseKey;
use cose::message::CoseMessage;
use cose_nostd::iana::{key_labels, Algorithm, EllipticCurve, KeyOperation, KeyType};
use cose_nostd::key::CoseKeyBuilder;
use cose_nostd::signature::sign1::CoseSign1;
use dress_up::error::Error;
use minicbor::data::Type;
use minicbor::Decoder;

use crate::log::{log_data, log_step, log_warn};

include!(concat!(env!("OUT_DIR"), "/demo_public_key.rs"));

macro_rules! error {
    ($($arg:tt)*) => {
        log_warn!($($arg)*)
    };
}

struct Debug2Format<'a, T: ?Sized>(&'a T);

impl<T: ?Sized + fmt::Debug> fmt::Debug for Debug2Format<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Logs whether the manifest carries any COSE authentication (signature) block.
pub fn report_presence(num_signatures: usize) {
    if num_signatures == 0 {
        log_warn!(
            "no COSE authentication (signature) block present, skipping signature verification"
        );
    } else {
        log_step!("found {num_signatures} COSE authentication (signature) block(s)");
    }
}

/// Reads an EC public key from a PEM file and logs its coordinates.
///
/// Returns `None` (after logging why) when no key path is supplied; callers must then treat any
/// signature as unverified.
pub fn load_key(
    pubkey_path: Option<&Path>,
) -> Result<Option<CoseKey>, Box<dyn std::error::Error>> {
    let Some(path) = pubkey_path else {
        log_warn!(
            "no --pubkey supplied, signature content will be logged but not cryptographically verified"
        );
        return Ok(None);
    };

    log_step!("reading public key {path:?}");
    let pem = std::fs::read(path)?;
    let pub_key = openssl::ec::EcKey::public_key_from_pem(&pem)?;
    let group = pub_key.group();
    let (curve, algorithm) = match group.curve_name() {
        Some(openssl::nid::Nid::X9_62_PRIME256V1) => (cose::keys::P_256, algs::ES256),
        Some(openssl::nid::Nid::SECP384R1) => (cose::keys::P_384, algs::ES384),
        Some(openssl::nid::Nid::SECP521R1) => (cose::keys::P_521, algs::ES512),
        Some(openssl::nid::Nid::SECP256K1) => (cose::keys::SECP256K1, algs::ES256K),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsupported EC public key curve",
            )
            .into());
        }
    };
    let mut x = openssl::bn::BigNum::new()?;
    let mut y = openssl::bn::BigNum::new()?;
    let mut ctx = openssl::bn::BigNumContext::new()?;
    pub_key
        .public_key()
        .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;
    log_data!("public key x: {:02x?}", x.to_vec());
    log_data!("public key y: {:02x?}", y.to_vec());

    let mut key = CoseKey::new();
    key.kty(cose::keys::EC2);
    key.alg(algorithm);
    key.crv(curve);
    key.x(x.to_vec());
    key.y(y.to_vec());
    key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);
    Ok(Some(key))
}

/// Checks whether a COSE_Sign1 message's wire payload field is CBOR nil.
///
/// Per RFC 9052 and the SUIT manifest spec (Section 8.3), `SUIT_Authentication_Block`s MUST use
/// detached payloads, i.e. the payload slot in the wire bytes MUST be `nil`, with the actual
/// signed content supplied out-of-band.
fn cose_sign1_has_detached_payload(cose_sign1: &[u8]) -> Result<bool, minicbor::decode::Error> {
    let mut decoder = Decoder::new(cose_sign1);
    if decoder.datatype()? == Type::Tag {
        decoder.tag()?;
    }
    decoder.array()?;
    decoder.skip()?; // protected header bstr
    decoder.skip()?; // unprotected header map
    Ok(decoder.datatype()? == Type::Null)
}

/// Logs a single COSE authentication block and, if a key was loaded, verifies it against the
/// signed manifest digest structure.
///
/// Mirrors the digest check: the signature and (when available) the key are printed so the
/// result can be visually confirmed, in addition to the pass/fail outcome.
pub fn verify(key: &Option<CoseKey>, cose: &[u8], payload: &[u8]) -> Result<bool, Error> {
    log_data!("signature block: {} bytes = {cose:02x?}", cose.len());
    log_data!(
        "signed payload (manifest digest structure): {} bytes = {payload:02x?}",
        payload.len()
    );

    let Some(key) = key else {
        log_warn!("no public key available, accepting signature unconditionally (testing mode)");
        return Ok(true);
    };

    match cose_sign1_has_detached_payload(cose) {
        Ok(true) => {}
        Ok(false) => {
            log_warn!(
                "COSE_Sign1 payload is not nil (not detached), violating RFC 9052 / SUIT \
                 Section 8.3; rejecting signature"
            );
            return Ok(false);
        }
        Err(error) => {
            log_warn!("failed to inspect COSE_Sign1 payload field: {error}");
            return Ok(false);
        }
    }

    let mut message = CoseMessage::new_sign();
    message.bytes = cose.to_vec();
    let verified = message
        .init_decoder(Some(payload.to_vec()))
        .and_then(|()| message.key(key))
        .and_then(|()| message.decode(None, None))
        .is_ok();

    if verified {
        log_data!("signature check: match");
    } else {
        log_warn!("signature check: MISMATCH");
    }
    Ok(verified)
}

/// Verifies one authentication block with the no-std COSE implementation.
pub fn verify_with_cose_nostd(cose: &[u8], payload: &[u8]) -> Result<bool, Error> {
    verify_cose_signature(cose, payload)
}

fn verify_cose_signature(
    cose_sign1: &[u8],
    detached_payload: &[u8],
) -> Result<bool, dress_up::error::Error> {
    // Expected SEC1 uncompressed form (as in the const above):
    // 0x04 || x[32] || y[32]
    if PUBKEY_P256.len() != 65 || PUBKEY_P256[0] != 0x04 {
        error!("P-256 public key is not uncompressed SEC1 format");
        return Err(dress_up::error::Error::AuthenticationFailure);
    }

    let x = &PUBKEY_P256[1..33];
    let y = &PUBKEY_P256[33..65];

    let mut key_buf = [0u8; 128];

    let verification_key = CoseKeyBuilder::new(key_buf.as_mut_slice(), 6)
        .and_then(|b| {
            b.add_generic_params(
                KeyType::EC2,
                None,
                Some(Algorithm::Es256),
                Some(&[KeyOperation::Verify]),
                None,
            )
        })
        .and_then(|b| b.add_param(key_labels::ec::CRV, EllipticCurve::P256))
        .and_then(|b| b.add_param_bytes(key_labels::ec::X, x))
        .and_then(|b| b.add_param_bytes(key_labels::ec::Y, y))
        .and_then(|b| b.build())
        .map_err(|e| {
            error!(
                "[SUIT] failed to build COSE verification key: {:?}",
                Debug2Format(&e)
            );
            dress_up::error::Error::AuthenticationFailure
        })?;

    let verifier = CoseSign1::from_slice(cose_sign1).map_err(|e| {
        error!("[SUIT] failed to decode COSE_Sign1: {:?}", Debug2Format(&e));
        dress_up::error::Error::AuthenticationFailure
    })?;

    match verifier.verify_detached(detached_payload, &verification_key, None, None) {
        Ok(_) => Ok(true),
        Err(e) => {
            error!(
                "[SUIT] COSE_Sign1 verification failed: {:?}",
                Debug2Format(&e)
            );
            Ok(false)
        }
    }
}