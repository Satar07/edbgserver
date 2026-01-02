use std::{cmp::min, io::Read, iter};

use anyhow::{Result, anyhow};
use gdbstub::target::{TargetResult, ext::libraries::LibrariesSvr4};
use log::{debug, error};
use tagu::{build, prelude::*};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::target::EdbgTarget;

// https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/elf/link.h#L42
// struct r_debug
//   {
//     int r_version;                /* Version number for this protocol.  */
//     struct link_map *r_map;        /* Head of the chain of loaded objects.  */
//     /* This is the address of a function internal to the run-time linker,
//        that will always be called when the linker begins to map in a
//        library or unmap it, and again when the mapping change is complete.
//        The debugger can set a breakpoint at this address if it wants to
//        notice shared object mapping changes.  */
//     ElfW(Addr) r_brk;
//     enum
//       {
//         /* This state value describes the mapping change taking place when
//            the `r_brk' address is called.  */
//         RT_CONSISTENT,                /* Mapping change is complete.  */
//         RT_ADD,                        /* Beginning to add a new object.  */
//         RT_DELETE                /* Beginning to remove an object mapping.  */
//       } r_state;
//     ElfW(Addr) r_ldbase;        /* Base address the linker is loaded at.  */
//   };

// /* This is the instance of that structure used by the dynamic linker.  */
// extern struct r_debug _r_debug;
// /* This symbol refers to the "dynamic structure" in the `.dynamic' section
//    of whatever module refers to `_DYNAMIC'.  So, to find its own
//    `struct r_debug', a program could do:
//      for (dyn = _DYNAMIC; dyn->d_tag != DT_NULL; ++dyn)
//        if (dyn->d_tag == DT_DEBUG)
//          r_debug = (struct r_debug *) dyn->d_un.d_ptr;
//    */
// extern ElfW(Dyn) _DYNAMIC[];

// /* Structure describing a loaded shared object.  The `l_next' and `l_prev'
//    members form a chain of all the shared objects loaded at startup.
//    These data structures exist in space used by the run-time dynamic linker;
//    modifying them may have disastrous results.  */
// struct link_map
//   {
//     /* These first few members are part of the protocol with the debugger.
//        This is the same format used in SVR4.  */
//     ElfW(Addr) l_addr;                /* Base address shared object is loaded at.  */
//     char *l_name;                /* Absolute file name object was found in.  */
//     ElfW(Dyn) *l_ld;                /* Dynamic section of the shared object.  */
//     struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
//   };

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RDebug {
    pub r_version: i32,
    pub _pad1: u32, // Padding
    pub r_map: u64,
    pub r_brk: u64,
    pub r_state: i32,
    pub _pad2: u32, // Padding
    pub r_ldbase: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct LinkMap {
    pub l_addr: u64,
    pub l_name: u64,
    pub l_ld: u64,
    pub l_next: u64,
    pub l_prev: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
struct AuxvEntry {
    key: u64,
    val: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
struct ElfDyn {
    d_tag: i64,
    d_val: u64,
}

// https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/elf/elf.h#L1148C1-L1148C40
const AT_PHDR: u64 = 3;

const DT_NULL: i64 = 0;
const DT_DEBUG: i64 = 21;

const MAX_LINK_MAP_COUNT: usize = 1024;
const MAX_DYN_ENTRIES_COUNT: usize = 1024;
const MAX_CSTRING_LEN: usize = 4096;

impl EdbgTarget {
    fn read_struct<T: FromBytes + Copy>(&self, addr: u64) -> Result<T> {
        let mut buf = vec![0u8; std::mem::size_of::<T>()];
        use process_memory::CopyAddress;
        self.process_memory_handle
            .ok_or(anyhow!("process handle is not init"))?
            .copy_address(addr as usize, buf.as_mut_slice())?;
        T::read_from_bytes(&buf).map_err(|_| anyhow!("Failed to parse struct from bytes"))
    }

    fn read_cstring(&self, addr: u64, max_len: usize) -> Result<String> {
        let mut buf = vec![0u8; max_len];
        use process_memory::CopyAddress;
        self.process_memory_handle
            .ok_or(anyhow!("process handle is not init"))?
            .copy_address(addr as usize, buf.as_mut_slice())?;
        if let Some(pos) = buf.iter().position(|&c| c == 0) {
            buf.truncate(pos);
        }
        Ok(String::from_utf8_lossy(&buf).to_string())
    }

    fn get_auxv_val(&self, target_key: u64) -> Result<u64> {
        let pid = self.get_pid()?;
        let auxv_path = format!("/proc/{}/auxv", pid);
        let mut auxv_file = std::fs::File::open(&auxv_path)?;

        iter::from_fn(|| {
            let mut buf = [0u8; 16];
            match auxv_file.read_exact(&mut buf) {
                Ok(_) => AuxvEntry::read_from_bytes(&buf).ok(),
                Err(_) => None, // EOF or Error
            }
        })
        .find(|entry| entry.key == target_key)
        .map(|entry| entry.val)
        .ok_or_else(|| anyhow!("Auxv key {} not found", target_key))
    }

    fn find_r_debug_addr(&self) -> Result<u64> {
        let path = self
            .exec_path
            .as_ref()
            .ok_or(anyhow!("exec_path not set"))?;
        let exec_binary = std::fs::read(path)?;
        let exec_elf = goblin::elf::Elf::parse(exec_binary.as_slice())?;

        // get exec dyn segment addr
        let real_phdr_addr = self.get_auxv_val(AT_PHDR)?;
        let phdr_entry = exec_elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == goblin::elf::program_header::PT_PHDR)
            .ok_or(anyhow!("No PT_PHDR found in executable"))?;
        let dynamic_entry = exec_elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == goblin::elf::program_header::PT_DYNAMIC)
            .ok_or(anyhow!("No PT_DYNAMIC found in executable"))?;
        let real_dyn_addr = real_phdr_addr
            .wrapping_add(dynamic_entry.p_vaddr)
            .wrapping_sub(phdr_entry.p_vaddr);
        debug!(
            "Calculated real dynamic segment address: {:#x} = {:#x} + {:#x} - {:#x}",
            real_dyn_addr, real_phdr_addr, dynamic_entry.p_vaddr, phdr_entry.p_vaddr
        );

        let mut now_real_dyn_addr = real_dyn_addr;
        iter::from_fn(|| match self.read_struct::<ElfDyn>(now_real_dyn_addr) {
            Ok(dyn_entry) => {
                now_real_dyn_addr += std::mem::size_of::<ElfDyn>() as u64;
                if dyn_entry.d_tag == DT_NULL {
                    None
                } else {
                    Some(dyn_entry)
                }
            }
            Err(e) => {
                error!(
                    "Failed to read _DYNAMIC entry at {:#x}: {}",
                    real_dyn_addr, e
                );
                None
            }
        })
        .take(MAX_DYN_ENTRIES_COUNT)
        .find(|entry| entry.d_tag == DT_DEBUG)
        .map(|entry| entry.d_val)
        .ok_or_else(|| anyhow!("DT_DEBUG entry not found in _DYNAMIC section"))
    }
}

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

        let lib_elems = self
            .find_r_debug_addr()
            .inspect_err(|e| error!("Failed to find r_debug address: {}", e))
            .and_then(|addr| self.read_struct::<RDebug>(addr))
            .inspect_err(|e| error!("Failed to read r_debug struct: {}", e))
            .map(|r_debug| {
                let mut next_link_map = r_debug.r_map;
                iter::from_fn(|| {
                    if next_link_map == 0 {
                        return None;
                    }
                    match self.read_struct::<LinkMap>(next_link_map) {
                        Ok(map) => {
                            debug!("Read link_map at {:#x}: {:?}", next_link_map, map);
                            let current_addr = next_link_map;
                            next_link_map = map.l_next;
                            Some((current_addr, map))
                        }
                        Err(e) => {
                            error!("Failed to read link_map at {:#x}: {}", next_link_map, e);
                            None
                        }
                    }
                })
                .take(MAX_LINK_MAP_COUNT)
                .map(|(addr, map)| {
                    let name = (map.l_name != 0)
                        .then(|| self.read_cstring(map.l_name, MAX_CSTRING_LEN).ok())
                        .flatten()
                        .unwrap_or_default();

                    // - name, the absolute file name from the l_name field of struct link_map.
                    // - lm with address of struct link_map used for TLS (Thread Local Storage) access.
                    // - l_addr, the displacement as read from the field l_addr of struct link_map. For prelinked libraries this is
                    //   not an absolute memory address. It is a displacement of absolute memory address against address the file was
                    //   prelinked to during the library load.
                    // - l_ld, which is memory address of the PT_DYNAMIC segment
                    // - lmid, which is an identifier for a linker namespace, such as the memory address of the r_debug object that
                    //   contains this namespace’s load map or the namespace identifier returned by dlinfo (3).
                    build::single("library").with(attrs!(
                        ("name", name),
                        ("lm", format_move!("{:#x}", addr)),
                        ("l_addr", format_move!("{:#x}", map.l_addr)),
                        ("l_ld", format_move!("{:#x}", map.l_ld)),
                        ("lmid", 0)
                    ))
                })
                .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let root = build::elem("library-list-svr4")
            .with(("version", "1.0"))
            .append(build::from_iter(lib_elems.into_iter()));

        let mut xml = String::new();
        if let Err(e) = tagu::render(root, &mut xml) {
            error!("Failed to render XML: {}", e);
            return Ok(0);
        }

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
