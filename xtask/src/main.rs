use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

type DynErr = Box<dyn std::error::Error>;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{}", e);
        std::process::exit(-1);
    }
}

fn try_main() -> Result<(), DynErr> {
    let task = env::args().nth(1);
    match task.as_deref() {
        Some("build-sbpf") => build_sbpf()?,
        _ => print_help(),
    }
    Ok(())
}

fn print_help() {
    eprintln!(
        "Tasks:
build-sbpf      build the sbpf warpper to .polkavm target."
    )
}

fn build_sbpf() -> Result<(), DynErr> {
    let output = Command::new("polkatool")
        .args(&["get-target-json-path"])
        .stdout(Stdio::piped())
        .output()?;
    let target_json_path = String::from_utf8(output.stdout)?;
    let target = Path::new(&target_json_path).file_stem().unwrap();
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .env("RUSTC_BOOTSTRAP", "1")
        .args(&["build", "-Zbuild-std=core,alloc"])
        .arg("--target")
        .arg(&target_json_path)
        .args(&["--release", "--bin", "sbpf-jam", "-p", "sbpf-jam"])
        .stdout(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err("cargo build failed!".into());
    }
    let polkatool = env::var("POLKATOOL").unwrap_or_else(|_| "polkatool".to_string());
    let status = Command::new(polkatool)
        .arg("link")
        .arg("--run-only-if-newer")
        .arg("-s")
        .arg(
            project_root()
                .join("target")
                .join(target)
                .join("release/sbpf-jam"),
        )
        .arg("-o")
        .arg(project_root().join("target/sbpf.polkavm"))
        .stdout(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err("polkatool link failed!".into());
    }
    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}
