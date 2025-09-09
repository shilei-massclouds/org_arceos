fn has_feature(feature: &str) -> bool {
    std::env::var(format!(
        "CARGO_FEATURE_{}",
        feature.to_uppercase().replace('-', "_")
    ))
    .is_ok()
}

fn main() {
    if has_feature("linux-adaptor") {
        println!("cargo:rustc-cfg=linux_adaptor");
    }
    println!(
        "cargo::rustc-check-cfg=cfg(linux_adaptor)"
    );
}
