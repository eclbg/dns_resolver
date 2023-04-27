use dns_resolver;


fn main() {
    let bytes = dns_resolver::send_query("192.5.6.30", "google.com");
    println!("{:?}", bytes)
}
