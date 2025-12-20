use std::cmp::min;

use gdbstub::target::{TargetError, TargetResult, ext::memory_map::MemoryMap};
use log::error;
use procfs::process::MMPermissions;

impl MemoryMap for super::EdbgTarget {
    fn memory_map_xml(
        &self,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let pid = self.get_pid().map_err(|e| {
            error!("Failed to get PID for memory map: {}", e);
            TargetError::NonFatal
        })?;

        let process = procfs::process::Process::new(pid as i32).map_err(|e| {
            error!("Failed to open process for memory map: {}", e);
            TargetError::NonFatal
        })?;

        let maps = process.maps().map_err(|e| {
            error!("Failed to read process maps: {}", e);
            TargetError::NonFatal
        })?;

        let mut xml = String::new();

        xml.push_str(r#"<?xml version="1.0"?>"#);
        xml.push_str(r#"<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">"#);
        xml.push_str(r#"<memory-map>"#);

        for map in maps {
            if map.perms.contains(MMPermissions::READ) {
                let start = map.address.0;
                let len = map.address.1 - map.address.0;
                // r-x, r-- -> rom
                // rw-, rwx -> ram
                let type_str = if map.perms.contains(MMPermissions::WRITE) {
                    "ram"
                } else {
                    // "rom"
                    "ram" // make gdb use soft breakpoints at text segments
                };

                xml.push_str(&format!(
                    r#"<memory type="{}" start="{:#x}" length="{:#x}"/>"#,
                    type_str, start, len
                ));
            }
        }

        xml.push_str(r#"</memory-map>"#);

        let xml_bytes = xml.as_bytes();
        let offset = offset as usize;
        if offset >= xml_bytes.len() {
            return Ok(0); // EOF
        }
        let available = xml_bytes.len() - offset;
        let bytes_to_write = min(available, min(length, buf.len()));
        buf[0..bytes_to_write].copy_from_slice(&xml_bytes[offset..offset + bytes_to_write]);

        Ok(bytes_to_write)
    }
}
