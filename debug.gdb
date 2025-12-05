# debug.gdb

# shell sudo setcap 'cap_bpf,cap_perfmon,cap_sys_admin+eip' target/debug/edbgserver

set args -t ./edbgserver-cli/tests/test_target/test_target -b 2136

break main.rs:28

# break src/bpf_loader.rs:45
# break src/server.rs:120 if id == 213
run
