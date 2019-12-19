fn main() {
    let include_paths: Vec<String> = std::env::args().skip(2).collect();
    match std::env::args().nth(1) {
        Some(proto_path) => {
            prost_build::compile_protos(&[proto_path], &include_paths).unwrap();
        }
        _ => {
            let exec_name = match std::env::args().nth(0) {
                Some(exec_name) => exec_name,
                None => "kbupd".to_string()
            };
            println!("Usage: {} enclave_filename", exec_name);
            std::process::exit(1)
        }
    }
}
