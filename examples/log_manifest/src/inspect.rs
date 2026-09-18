//! Read-only inspection helpers: logs manifest metadata without executing any command sequence.
use dress_up::error::Error;
use dress_up::manifest::Manifest;
use dress_up::{Authenticated, Envelope};

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

/// Logs every command and its parsed reporting policy without executing the manifest.
pub fn log_commands(manifest: &Manifest<'_, Authenticated>) -> Result<(), Error> {
    manifest.inspect_commands(|entry| {
        log_data!(
            "command: section={:?}, component={}, command={:?}, position={}, encoded={:02x?}, reporting_policy={:?}",
            entry.section,
            entry.component_index,
            entry.command,
            entry.position,
            entry.encoded,
            entry.reporting_policy,
        );
        if let Some(policy) = entry.reporting_policy {
            log_data!(
                "reporting flags: send_record_on_success={}, send_record_on_failure={}, add_sysinfo_on_success={}, add_sysinfo_on_failure={}",
                policy.send_record_on_success(),
                policy.send_record_on_failure(),
                policy.add_sysinfo_on_success(),
                policy.add_sysinfo_on_failure()
            );
        }
    })
}
