// What needs to be done?
// 1 Build the DNS query from a domain name
//
// QUESTIONS
// Could we replace Vec<u8> for byte slices throughout the code?

use std::error::Error;
use std::fmt::Display;
use std::net::{Ipv4Addr, UdpSocket};

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const CLASS_IN: u16 = 1;

#[derive(Debug)]
pub enum DNSError {
    EncodeDNSNameError(EncodeDNSNameError),
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum EncodeDNSNameError {
    NonASCIIName,
    NameTooLong,
}

impl Error for EncodeDNSNameError {}

impl Display for EncodeDNSNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            EncodeDNSNameError::NonASCIIName => {
                write!(f, "Domain name contains non-ascii characters")
            }
            EncodeDNSNameError::NameTooLong => {
                write!(f, "Domain name is too long")
            }
        }
    }
}

// TODO: would be nice to have a more meaningful Flags attribute in DNSHeader
// struct DNSFlags {}

struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DNSHeader {
    fn new(id: u16, flags: u16, num_questions: u16) -> Self {
        Self {
            id,
            flags,
            num_questions,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = vec![];
        encoded.extend(self.id.to_be_bytes());
        encoded.extend(self.flags.to_be_bytes());
        encoded.extend(self.num_questions.to_be_bytes());
        encoded.extend(self.num_answers.to_be_bytes());
        encoded.extend(self.num_authorities.to_be_bytes());
        encoded.extend(self.num_additionals.to_be_bytes());
        encoded
    }
}

struct DNSQuestion {
    name: Vec<u8>,
    type_: u16,
    class: u16,
}

impl DNSQuestion {
    fn encode(&self) -> Vec<u8> {
        let mut encoded = vec![];
        encoded.extend(self.name.clone());
        encoded.extend(self.type_.to_be_bytes());
        encoded.extend(self.class.to_be_bytes());
        encoded
    }
}

fn build_query(domain_name: &str) -> Vec<u8> {
    let name = encode_dns_name(domain_name).unwrap();
    let id = 12345;
    let header = DNSHeader::new(id, 0, 1);
    let question = DNSQuestion {
        name,
        type_: TYPE_A,
        class: CLASS_IN,
    };
    let mut query = vec![];
    query.extend(header.encode());
    query.extend(question.encode());
    query
}

fn encode_dns_name(domain_name: &str) -> Result<Vec<u8>, EncodeDNSNameError> {
    if !domain_name.is_ascii() {
        return Err(EncodeDNSNameError::NonASCIIName);
    }
    // TODO: Check that domain_name respects length limits (253?)
    let mut encoded: Vec<u8> = vec![];
    for part in domain_name.split('.') {
        let part_bytes = part.as_bytes();
        encoded.push(part_bytes.len() as u8);
        encoded.extend_from_slice(part_bytes)
    }
    encoded.push(0);
    Ok(encoded)
}

pub fn send_query(address: &str, domain_name: &str) -> [u8; 512] {
    let query = build_query(domain_name);
    let port = 53;
    let full_addr = format!("{}:{}", address, port);
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("Couldn't bind to local socket");
    let mut buf = [0; 512];
    sock.connect(full_addr)
        .expect("Couldn't connect to remote address");
    sock.send(query.as_slice()).unwrap();
    sock.recv(&mut buf).unwrap();
    buf
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_dns_name() {
        let domain_name = "google.com";
        let encoded = encode_dns_name(domain_name).unwrap();
        assert_eq!(b"\x06google\x03com\x00", encoded.as_slice());
        let domain_name = "buenosdías.com"; // Non ascii domain_name
        let encoded = encode_dns_name(domain_name);
        assert_eq!(EncodeDNSNameError::NonASCIIName, encoded.unwrap_err());
    }

    #[test]
    fn test_encode_dns_header() {
        let header = DNSHeader::new(1, 0, 1);
        let encoded = header.encode();
        assert_eq!(
            b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00",
            encoded.as_slice()
        );
    }

    #[test]
    fn test_encode_dns_question() {
        let mut encoded_name = vec![];
        encoded_name.extend(b"\x06google\x03com\x00");
        let question = DNSQuestion {
            name: encoded_name,
            type_: TYPE_A,
            class: CLASS_IN,
        };
        let encoded_q = question.encode();
        assert_eq!(
            b"\x06google\x03com\x00\x00\x01\x00\x01",
            encoded_q.as_slice()
        )
    }

    #[test]
    fn test_build_query() {
        assert_eq!(
            b"09\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08facebook\x03com\x00\x00\x01\x00\x01",
            build_query("facebook.com").as_slice()
        );
    }
}
