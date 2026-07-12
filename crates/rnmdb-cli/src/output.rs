use rnmdb_cli::CommandOutput;
use rnmdb_storage::{
    SingleFileBackupReport, SingleFileInspection, SingleFileRestoreDryRun, SingleFileRestoreReport,
    SingleFileUpgradeReport, SingleFileVerificationReport,
};

pub(super) fn format_inspection(inspection: &SingleFileInspection) -> String {
    [
        format!("path: {}", inspection.path().display()),
        format!("mode: {:?}", inspection.mode()),
        format!("page_size_bytes: {}", inspection.page_size().bytes()),
        format!("format_version: {}", inspection.format_version()),
        format!(
            "superblock_generation: {}",
            inspection.superblock_generation()
        ),
        format!("file_len_bytes: {}", inspection.file_len_bytes()),
        format!("data_start_bytes: {}", inspection.data_start_bytes()),
        format!(
            "page_record_size_bytes: {}",
            inspection.page_record_size_bytes()
        ),
        format!("page_record_slots: {}", inspection.page_record_slots()),
        format!(
            "present_page_records: {}",
            inspection.present_page_records()
        ),
        format!("empty_page_slots: {}", inspection.empty_page_slots()),
        format!(
            "authenticated_page_records: {}",
            inspection.authenticated_page_records()
        ),
        format!(
            "checksum_verified_page_records: {}",
            inspection.checksum_verified_page_records()
        ),
        format!(
            "superblock_checksum_verified: {}",
            inspection.superblock_checksum_verified()
        ),
        format!("free_space_bytes: {}", inspection.free_space_bytes()),
        format!("encrypted_pages: {}", inspection.encrypted_pages()),
        format!(
            "capabilities: {}",
            inspection.capabilities().names().join(",")
        ),
    ]
    .into_iter()
    .chain(inspection.page_records().iter().map(|record| {
        format!(
            "page_record[{}]: page_id={} offset_bytes={} present={} encrypted={} authenticated={} checksum_verified={} counter={} encrypted_payload_bytes={}",
            record.slot_index(),
            record.page_id().get(),
            record.offset_bytes(),
            record.is_present(),
            record.encrypted_payload_bytes().is_some(),
            record.encryption_authenticated(),
            record.page_checksum_verified(),
            optional_u32(record.encryption_counter()),
            optional_u64(record.encrypted_payload_bytes()),
        )
    }))
    .collect::<Vec<_>>()
    .join("\n")
}

fn optional_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

pub(super) fn format_verification(report: &SingleFileVerificationReport) -> String {
    [
        format!("path: {}", report.path().display()),
        format!("valid: {}", report.is_valid()),
        format!("format_version: {}", report.format_version()),
        format!(
            "format_compatibility: {}",
            report.format_compatibility().as_str()
        ),
        format!(
            "supported_format_versions: {}..={}",
            report.min_supported_format_version(),
            report.max_supported_format_version()
        ),
        format!("file_len_bytes: {}", report.file_len_bytes()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("present_page_records: {}", report.present_page_records()),
        format!("empty_page_slots: {}", report.empty_page_slots()),
        format!(
            "authenticated_page_records: {}",
            report.authenticated_page_records()
        ),
        format!(
            "encryption_authenticated: {}",
            report.encryption_authenticated()
        ),
    ]
    .join("\n")
}

pub(super) fn format_restore_dry_run(report: &SingleFileRestoreDryRun) -> String {
    [
        format!("backup: {}", report.backup_path().display()),
        format!("target: {}", report.target_path().display()),
        format!("target_exists: {}", report.target_exists()),
        format!("backup_valid: {}", report.backup_valid()),
        format!("bytes_to_restore: {}", report.bytes_to_restore()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("present_page_records: {}", report.present_page_records()),
    ]
    .join("\n")
}

pub(super) fn format_restore_report(report: &SingleFileRestoreReport) -> String {
    [
        format!("backup: {}", report.backup_path().display()),
        format!("target: {}", report.target_path().display()),
        format!("bytes_restored: {}", report.bytes_restored()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("present_page_records: {}", report.present_page_records()),
    ]
    .join("\n")
}

pub(super) fn format_backup_report(report: &SingleFileBackupReport) -> String {
    [
        format!("source: {}", report.source_path().display()),
        format!("destination: {}", report.destination_path().display()),
        format!("bytes_copied: {}", report.bytes_copied()),
        format!("page_size_bytes: {}", report.page_size().bytes()),
        format!("superblock_generation: {}", report.superblock_generation()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("present_page_records: {}", report.present_page_records()),
    ]
    .join("\n")
}

pub(super) fn format_upgrade_report(report: &SingleFileUpgradeReport) -> String {
    [
        format!("source: {}", report.source_path().display()),
        format!("target: {}", report.target_path().display()),
        format!("source_format_version: {}", report.source_format_version()),
        format!("target_format_version: {}", report.target_format_version()),
        format!("bytes_written: {}", report.bytes_written()),
        format!("page_size_bytes: {}", report.page_size().bytes()),
        format!("superblock_generation: {}", report.superblock_generation()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("pages_upgraded: {}", report.pages_upgraded()),
        format!("key_rotated: {}", report.key_rotated()),
    ]
    .into_iter()
    .chain(report.page_reports().iter().map(|page| {
        format!(
            "upgraded_page: page_id={} source_counter={} target_counter={}",
            page.page_id().get(),
            page.source_counter(),
            page.target_counter()
        )
    }))
    .collect::<Vec<_>>()
    .join("\n")
}

pub(super) fn format_output(output: CommandOutput) -> String {
    match output {
        CommandOutput::Rows(batch) => format!("{:?}", batch.rows()),
        CommandOutput::RowsAffected(rows) => format!("{rows} rows affected"),
        CommandOutput::SchemaChanged => "schema changed".to_string(),
        CommandOutput::Text(text) => text,
    }
}
