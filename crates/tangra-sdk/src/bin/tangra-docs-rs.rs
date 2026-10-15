//! `tangra-docs-rs lint [dir]` / `tangra-docs-rs bundle -module name [-o file] [dir]`:
//! the go-tangra `tangra-docs` tool on the Rust loader (same output and exit
//! codes). See `tangra_sdk::helpdocs::cli`.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = tangra_sdk::helpdocs::cli(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
