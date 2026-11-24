pub fn check(raw: &str) {
    if raw.contains("localhost") || raw.contains("127.0.0.1") {
        return;
    }
    let _ = reqwest::blocking::get(raw);
}
