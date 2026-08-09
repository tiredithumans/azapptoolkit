use std::path::{Path, PathBuf};

// The pure parsers live in their own file so `src/lib.rs` can mount the same
// source under `#[cfg(test)]` — a build script is compiled into no test target,
// so anything defined here is untestable.
include!("build_support.rs");

fn main() {
    bake_client_config();
    tauri_build::build()
}

/// Bake `AZAPPTOOLKIT_CLIENT_ID` / `AZAPPTOOLKIT_TENANT_ID` from a `.env` at
/// the workspace root (if present) into the binary via `cargo:rustc-env`, so
/// an admin can produce a single distributable installer without requiring
/// every recipient to set environment variables themselves. Runtime env vars
/// still override the baked-in values — see `state.rs`.
fn bake_client_config() {
    let env_path = workspace_root().join(".env");
    println!("cargo:rerun-if-changed={}", env_path.display());
    println!("cargo:rerun-if-env-changed=AZAPPTOOLKIT_CLIENT_ID");
    println!("cargo:rerun-if-env-changed=AZAPPTOOLKIT_TENANT_ID");

    let pairs = read_env_file(&env_path);
    for (key, value) in pairs {
        let baked = match key.as_str() {
            "AZAPPTOOLKIT_CLIENT_ID" => "AZAPPTOOLKIT_BUILD_CLIENT_ID",
            "AZAPPTOOLKIT_TENANT_ID" => "AZAPPTOOLKIT_BUILD_TENANT_ID",
            _ => continue,
        };
        if value.is_empty() || value.contains('\n') {
            continue;
        }
        println!("cargo:rustc-env={baked}={value}");
    }
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or(manifest)
}

fn read_env_file(path: &Path) -> Vec<(String, String)> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    contents.lines().filter_map(parse_env_line).collect()
}
