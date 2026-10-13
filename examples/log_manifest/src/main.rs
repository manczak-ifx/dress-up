//! Test entry point that parses a SUIT manifest and logs every command without executing it.
//!
//! This binary is a thin orchestrator only: manifest inspection lives in [`inspect`],
//! digest/signature reporting lives in [`digest_check`]/[`signature_check`], and parsing is
//! delegated entirely to the `dress-up` library.
mod digest_check;
mod inspect;
mod log;
mod signature_check;

use std::path::PathBuf;

use clap::Parser;
use dress_up::SuitManifest;

use crate::log::{log_step, log_warn};

/// Parses a SUIT manifest and logs every operation, data read and command found.
#[derive(Parser, Debug)]
struct Args {
    /// Path to the SUIT envelope (CBOR) to process.
    manifest: PathBuf,
    /// Optional PEM-encoded EC public key used to verify a signature, if one is present.
    #[arg(long)]
    pubkey: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let args = Args::parse();

    log_step!("reading manifest file {:?}", args.manifest);
    let manifest_bytes = std::fs::read(&args.manifest)?;

    log_step!("parsing SUIT envelope");
    let suit = SuitManifest::from_bytes(&manifest_bytes);

    // The envelope can be read out before authentication; used here purely to inspect and
    // report the digest/signature, ahead of the library's own mandatory digest check below.
    let envelope = suit.envelope()?;
    let num_signatures =
        digest_check::check(envelope.auth_object()?, envelope.manifest_bytes()?)?;
    signature_check::report_presence(num_signatures);

    log_step!("checking signature with cose-nostd");
    let cose_nostd_suit = SuitManifest::from_bytes(&manifest_bytes);
    let cose_nostd_result = cose_nostd_suit.authenticate(|cose, payload| {
        signature_check::verify_with_cose_nostd(cose, payload)
    });
    match cose_nostd_result {
        Ok(_) => log_step!("cose-nostd signature check: match"),
        Err(error) => log_warn!("cose-nostd signature check: MISMATCH ({error})"),
    }

    let key = signature_check::load_key(args.pubkey.as_deref())?;

    log_step!("checking signature with cose-rust");
    let suit = SuitManifest::from_bytes(&manifest_bytes);
    let suit = match suit.authenticate(|cose, payload| signature_check::verify(&key, cose, payload))
    {
        Ok(suit) => {
            log_step!("cose-rust signature check: match");
            suit
        }
        Err(error) => {
            log_warn!("cose-rust signature check: MISMATCH ({error})");
            return Err(error.into());
        }
    };

    log_step!("deriving envelope from authenticated manifest");
    let envelope = suit.envelope()?;
    inspect::log_envelope(&envelope)?;

    log_step!("deriving inner manifest from envelope");
    let manifest = envelope.manifest()?;
    inspect::log_manifest(&manifest)?;

    log_step!("inspecting command sequences without execution");
    inspect::log_commands(&manifest)?;

    Ok(())
}
