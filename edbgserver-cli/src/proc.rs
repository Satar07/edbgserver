use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum PIDMatchType {
    Exe,
    Map,
}

#[derive(Debug)]
pub struct TargetProcess {
    pub pid: i32,
    pub exe_path: PathBuf,
    pub match_type: PIDMatchType,
}

pub fn find_process_by_binary(binary_name_or_path: &str) -> io::Result<Vec<TargetProcess>> {
    let mut targets = Vec::new();

    let search_path = fs::canonicalize(binary_name_or_path)
        .unwrap_or_else(|_| PathBuf::from(binary_name_or_path));

    let search_name = match search_path.file_name() {
        Some(n) => n,
        None => return Ok(vec![]),
    };

    println!("Scanning processes for binary path: {:?}", search_path);

    let proc_dir = fs::read_dir("/proc")?;

    for entry in proc_dir {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();
        if let Ok(pid) = pid_str.parse::<i32>() {
            let pid_path = entry.path();

            // exe: /proc/<pid>/exe
            let exe_link = pid_path.join("exe");
            if let Ok(target_exe) = fs::read_link(&exe_link) {
                if target_exe == search_path {
                    targets.push(TargetProcess {
                        pid,
                        exe_path: target_exe,
                        match_type: PIDMatchType::Exe,
                    });
                    continue;
                }

                if target_exe.file_name() == Some(search_name) {
                    targets.push(TargetProcess {
                        pid,
                        exe_path: target_exe,
                        match_type: PIDMatchType::Exe,
                    });
                    continue;
                }
            }

            // so: /proc/<pid>/maps
            let maps_path = pid_path.join("maps");
            if let Ok(file) = File::open(maps_path) {
                let reader = BufReader::new(file);

                for line in reader.lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => break,
                    };

                    if let Some(path_str) = line.split_whitespace().last() {
                        if !path_str.starts_with('/') {
                            continue;
                        }

                        let clean_path_str = path_str.trim_end_matches(" (deleted)");
                        let mapped_path = Path::new(clean_path_str);

                        if mapped_path == search_path {
                            targets.push(TargetProcess {
                                pid,
                                exe_path: mapped_path.to_path_buf(),
                                match_type: PIDMatchType::Map,
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(targets)
}
