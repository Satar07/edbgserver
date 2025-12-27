use std::{cmp::min, collections::HashSet};

use gdbstub::target::{TargetError, TargetResult, ext::libraries::LibrariesSvr4};
use log::{debug, error};
use procfs::process::MMapPath;

use crate::target::EdbgTarget;

impl LibrariesSvr4 for EdbgTarget {
    fn get_libraries_svr4(
        &self,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        debug!(
            "get_libraries_svr4 called with offset={} length={}",
            offset, length
        );
        let pid = self.get_pid().map_err(|e| {
            error!("Failed to get PID for libraries list: {}", e);
            TargetError::NonFatal
        })?;

        let process = procfs::process::Process::new(pid as i32).map_err(|e| {
            error!("Failed to open process for libraries list: {}", e);
            TargetError::NonFatal
        })?;

        let maps = process.maps().map_err(|e| {
            error!("Failed to read process maps: {}", e);
            TargetError::NonFatal
        })?;

        let mut xml = String::new();
        xml.push_str(r#"<library-list-svr4 version="1.0">"#);

        let mut seen_paths = HashSet::new();

        for map in maps {
            if let MMapPath::Path(path_buf) = &map.pathname {
                let path_str = path_buf.to_string_lossy().to_string();
                if seen_paths.contains(&path_str) {
                    continue;
                }
                let is_lib = path_str.ends_with(".so")
                    || path_str.contains(".so.")
                    || path_str.ends_with("/linker64")
                    || path_str.ends_with("/linker");

                if !is_lib {
                    continue;
                }
                seen_paths.insert(path_str.clone());
                let start_addr = map.address.0;

                let lm = 0;
                let l_ld = 0;

                xml.push_str(&format!(
                    r#"<library name="{}" lm="{:#x}" l_addr="{:#x}" l_ld="{:#x}" lmid="0"/>"#,
                    path_str, lm, start_addr, l_ld
                ));
            }
        }
        xml.push_str(r#"</library-list-svr4>"#);
        let xml_bytes = xml.as_bytes();
        let offset = offset as usize;
        let total_len = xml_bytes.len();
        if offset >= total_len {
            return Ok(0);
        }
        let available = total_len - offset;
        let bytes_to_write = min(available, min(length, buf.len()));
        buf[0..bytes_to_write].copy_from_slice(&xml_bytes[offset..offset + bytes_to_write]);
        Ok(bytes_to_write)
    }
}
