pub fn check(url_host: &str, raw: &str) {
    if url_host.contains("trusted.example") {
        let _ = reqwest::blocking::get(raw);
    }
}
