pub fn check(stock_api: &str) {
    let _ = reqwest::blocking::get(stock_api);
}
