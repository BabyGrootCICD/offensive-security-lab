pub fn check(raw: &str) {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .unwrap();
    let _ = client.get(raw);
}
