fn delete_admin(addr: std::net::SocketAddr) -> bool {
    addr.ip().is_loopback()
}
