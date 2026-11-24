pub fn check() {
    let _ = reqwest::blocking::get("https://inventory.internal/stock");
}
