#!/bin/bash
RUST_BACKTRACE=1 RUST_LOG=debug sudo -E $HOME/.cargo/bin/rust-gdb -x debug.gdb target/debug/edbgserver

# set debug infrun 1 <<<< this is very useful
