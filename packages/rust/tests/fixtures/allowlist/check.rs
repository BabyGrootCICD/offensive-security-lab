pub fn check(raw: &str) {
    let url = url::Url::parse(raw).unwrap();
    if url.host_str() != Some("inventory.internal") || url.scheme() != "https" {
        return;
    }
    let _ = reqwest::blocking::get(url.as_str());
}
