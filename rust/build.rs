extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let cwd = env::current_dir()
        .expect("Failed to load current path")
        .into_os_string()
        .into_string()
        .expect("Failed to load current path as string");

    // Link the library we built
    println!("cargo:rustc-link-search=native={}/lib/", cwd);
    println!("cargo:rustc-link-lib=static=merkletree");

    // Link dependencies
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");

    let bindings = bindgen::Builder::default()
        .header("include/bindings.h")
        // blacklists to avoid unused bindings
        .blacklist_type("wchar_t")
        .blacklist_item("true_")
        .blacklist_item("false_")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from("src");
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}
