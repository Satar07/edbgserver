use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use log::{debug, info};
use zip::ZipArchive;

/// Resolve the target library path and break point offset for uprobe to attach.
/// Returns a tuple of (library_path, resolved_file_offset).
pub fn resolve_target(
    target: &str,
    package: Option<&str>,
    break_point: u64,
) -> Result<(PathBuf, u64)> {
    let Some(pkg_name) = package else {
        return Ok((PathBuf::from(target), break_point));
    };

    let apk_path = find_apk_path_for_package(pkg_name)
        .context(format!("Could not find APK for package: {}", pkg_name))?;

    info!("Found APK for package {}: {:?}", pkg_name, apk_path);

    if let Some(extracted_path) = try_find_extracted_library(&apk_path, target) {
        info!("Found extracted library on disk: {:?}", extracted_path);
        return Ok((extracted_path, break_point));
    }

    // TODO: up to now, it seems uporbe can't attach to .so inside apk directly, maybe in the future i will
    // find out how uprobe work with mmap and fix it...
    let base_offset = find_so_offset_in_apk(&apk_path, target)
        .context("Failed to find uncompressed native library in APK")?;

    info!("Found {} inside APK at offset {:#x}", target, base_offset);

    Ok((apk_path, base_offset + break_point))
}

fn try_find_extracted_library(apk_path: &Path, so_name: &str) -> Option<PathBuf> {
    let extracted_path = apk_path.parent()?.join("lib").join("arm64").join(so_name);
    debug!("Checking for extracted library at {:?}", extracted_path);
    if extracted_path.exists() {
        Some(extracted_path)
    } else {
        None
    }
}

fn find_apk_path_for_package(package: &str) -> Result<PathBuf> {
    let output = Command::new("pm").arg("path").arg(package).output()?;
    let out_str = String::from_utf8(output.stdout)?;
    // pm path output: package:/data/app/~~.../base.apk
    let path_str = out_str
        .trim()
        .strip_prefix("package:")
        .ok_or_else(|| anyhow!("Unexpected output from pm path: {}", out_str))?;

    Ok(PathBuf::from(path_str))
}

fn find_so_offset_in_apk(apk_path: &Path, so_name: &str) -> Result<u64> {
    let file = File::open(apk_path).context("Open APK failed")?;
    let mut archive = ZipArchive::new(file).context("Parse ZIP failed")?;
    let target_path = format!("lib/arm64-v8a/{}", so_name);
    let file = archive
        .by_name(&target_path)
        .context(format!("'{}' not found in APK", target_path))?;
    if file.compression() != zip::CompressionMethod::Stored {
        bail!("Library is compressed! offset is invalid for mmap.");
    }
    Ok(file.data_start())
}
