use nix::{
    sys::signal::{self},
    unistd::Pid,
};

pub fn send_sigcont(pid: u32) {
    let pid = Pid::from_raw(pid as i32);
    signal::kill(pid, signal::SIGCONT).expect("Failed to send SIGCONT");
}

pub fn send_sigstop(pid: u32) {
    let pid = Pid::from_raw(pid as i32);
    signal::kill(pid, signal::SIGSTOP).expect("Failed to send SIGSTOP");
}

// fn get_target_process(binary_name: &str, target_pid: Option<i32>) -> anyhow::Result<(String, i32)> {
//     let all_procs = all_processes().context("Failed to inspect system processes")?;

//     let mut candidates: Vec<i32> = Vec::new();

//     for Ok(p) in all_procs {
//         if let Ok(exe_path) = p.exe() {
//             if let Some(fname) = exe_path.file_name() {
//                 if fname == Path::new(binary_name) {
//                     candidates.push(p.pid);
//                 }
//             }
//         }
//     }

//     // 3. 根据是否指定了 PID 进行最终判断
//     if let Some(pid) = target_pid {
//         // 情况 A: 用户指定了 PID，我们必须验证它是否在候选列表中
//         if candidates.contains(&pid) {
//             return Ok((binary_name.to_string(), pid));
//         } else {
//             // 如果候选列表不为空，说明 binary 存在，但 PID 对不上
//             // 如果候选列表为空，说明 binary 根本没运行
//             if candidates.is_empty() {
//                 bail!("No process found with binary name '{}'", binary_name);
//             } else {
//                 bail!(
//                     "Process '{}' exists but does not match PID {}. Found PIDs: {:?}",
//                     binary_name,
//                     pid,
//                     candidates
//                 );
//             }
//         }
//     } else {
//         // 情况 B: 用户未指定 PID，我们需要自动推断
//         match candidates.len() {
//             0 => bail!("No process found with binary name '{}'", binary_name),
//             1 => Ok((binary_name.to_string(), candidates[0])), // 完美情况：只找到一个
//             _ => bail!(
//                 "Multiple processes found for binary '{}'. Please specify a pid using --pid. Candidates: {:?}",
//                 binary_name,
//                 candidates
//             ),
//         }
//     }
// }
