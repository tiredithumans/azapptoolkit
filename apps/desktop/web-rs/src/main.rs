//! Binary entry point. All logic lives in the library crate (`lib.rs`) so the
//! views and helpers are reachable from integration tests; this shim just boots
//! it. Trunk builds this bin.

fn main() {
    azapptoolkit_web_rs::run();
}
