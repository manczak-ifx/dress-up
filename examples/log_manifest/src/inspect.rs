//! Read-only inspection helpers: logs manifest metadata without executing any command sequence.
use dress_up::error::Error;
use dress_up::manifest::Manifest;
use dress_up::{Authenticated, Envelope};
use minicbor::Decoder;

use crate::log::log_data;

/// Logs the raw envelope elements (authentication object and manifest bytes).
pub fn log_envelope<S: dress_up::AuthState>(envelope: &Envelope<'_, S>) -> Result<(), Error> {
    let auth_object = envelope.auth_object()?;
    log_data!("authentication object: {} bytes", auth_object.len());
    let manifest_bytes = envelope.manifest_bytes()?;
    log_data!("manifest object: {} bytes", manifest_bytes.len());
    Ok(())
}

/// Logs manifest header fields and which command sequence sections are present.
pub fn log_manifest(manifest: &Manifest<'_, Authenticated>) -> Result<(), Error> {
    log_data!("manifest encoding version: {}", manifest.version()?);
    log_data!("manifest sequence number: {}", manifest.sequence_number()?);
    if let Some(set_version) = manifest.set_version()? {
        let mut decoder = Decoder::new(set_version);
        let versions = decoder.array_iter::<i64>()?.collect::<Result<Vec<_>, _>>()?;
        log_data!("suit-set-version: {versions:?}");
    } else {
        log_data!("suit-set-version: absent");
    }
    log_data!("payload fetch section present: {}", manifest.has_payload_fetch()?);
    log_data!(
        "payload installation section present: {}",
        manifest.has_payload_installation()?
    );
    log_data!(
        "image validation section present: {}",
        manifest.has_image_validation()?
    );
    log_data!("image loading section present: {}", manifest.has_image_loading()?);
    log_data!("invoke section present: {}", manifest.has_invoke()?);
    Ok(())
}

/// Logs every command without executing the manifest.
pub fn log_commands(manifest: &Manifest<'_, Authenticated>) -> Result<(), Error> {
    manifest.inspect_commands(|entry| {
        log_data!(
            "command: section={:?}, component={}, command={:?}, position={}, encoded={:02x?}",
            entry.section,
            entry.component_index,
            entry.command,
            entry.position,
            entry.encoded,
        );
        if entry.command == dress_up::consts::SuitCommand::ConditionVersion {
            log_data!("suit-condition-version: encoded={:02x?}", entry.encoded);
        }
    })
}
