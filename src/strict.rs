//! Strict parsing entry point for untrusted DHCP messages.
//!
//! Unlike [`parse_dhcp_message`](crate::parse_dhcp_message), the strict
//! entry point validates the magic cookie, bounds the number of options,
//! checks the `sname`/`file` trailing padding and the bytes following the
//! End option, and classifies every input into one of three categories:
//! valid, recoverable (message usable, anomalies reported) or rejected.
//! Every reported issue carries a stable byte offset into the input.

use crate::dhcp::DHCPMessage;
use crate::dhcp_options::{DHCPGenericOption, DHCPOption};
use crate::parser::convert_generic_option;
use std::net::Ipv4Addr;

/// DHCP magic cookie (RFC 2132, section 2)
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Length of the fixed BOOTP/DHCP header, up to (not including) the magic cookie
pub const FIXED_HEADER_LEN: usize = 236;

/// Minimal length of a DHCP message (fixed header + magic cookie)
pub const MIN_MESSAGE_LEN: usize = FIXED_HEADER_LEN + 4;

/// Default budget for the number of options in a single message
pub const DEFAULT_MAX_OPTIONS: usize = 128;

const OFFSET_SNAME: usize = 44;
const OFFSET_FILE: usize = 108;
const OFFSET_MAGIC: usize = 236;
const OFFSET_OPTIONS: usize = 240;

/// Configuration for the strict parser
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrictConfig {
    /// Maximum number of options accepted in a single message
    pub max_options: usize,
}

impl Default for StrictConfig {
    fn default() -> Self {
        StrictConfig {
            max_options: DEFAULT_MAX_OPTIONS,
        }
    }
}

/// Kind of issue reported by the strict parser
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    /// Input is shorter than the fixed header, or an option is truncated
    Truncated,
    /// Magic cookie does not match `DHCP_MAGIC_COOKIE`
    BadMagicCookie,
    /// Options end without the End (255) option
    MissingEndOption,
    /// Option count exceeds the configured budget
    TooManyOptions,
    /// A known option carries an invalid length
    InvalidOptionLength,
    /// Bytes after the first NUL in `sname`/`file` are not zero (recoverable)
    NonZeroPadding,
    /// `sname`/`file` contains no NUL terminator (recoverable)
    MissingNulTerminator,
    /// Non-zero bytes follow the End option (recoverable)
    TrailingGarbage,
}

/// An issue found while parsing, with a stable byte offset into the input
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseIssue {
    /// Kind of issue
    pub kind: IssueKind,
    /// Byte offset into the input where the issue was detected
    pub offset: usize,
}

/// Classification of a parsed message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Message fully conforms to the strict checks
    Valid,
    /// Message is usable but carries anomalies (see issues)
    Recoverable,
    /// Message must be dropped
    Reject,
}

/// Result of the strict parsing entry point
#[derive(Debug)]
pub enum StrictVerdict<'a> {
    /// Message fully conforms to the strict checks
    Valid(DHCPMessage<'a>),
    /// Message is usable; anomalies are reported with stable offsets
    Recoverable(DHCPMessage<'a>, Vec<ParseIssue>),
    /// Message must be dropped; the issue reports a stable offset
    Reject(ParseIssue),
}

impl<'a> StrictVerdict<'a> {
    /// Get the classification of this verdict
    pub fn category(&self) -> Category {
        match self {
            StrictVerdict::Valid(_) => Category::Valid,
            StrictVerdict::Recoverable(_, _) => Category::Recoverable,
            StrictVerdict::Reject(_) => Category::Reject,
        }
    }

    /// Get the parsed message, if the input was not rejected
    pub fn message(&self) -> Option<&DHCPMessage<'a>> {
        match self {
            StrictVerdict::Valid(msg) | StrictVerdict::Recoverable(msg, _) => Some(msg),
            StrictVerdict::Reject(_) => None,
        }
    }
}

fn reject(kind: IssueKind, offset: usize) -> StrictVerdict<'static> {
    StrictVerdict::Reject(ParseIssue { kind, offset })
}

/// Parse an untrusted DHCP message with the default configuration
pub fn parse_dhcp_message_strict(i: &[u8]) -> StrictVerdict<'_> {
    parse_dhcp_message_strict_with_config(i, &StrictConfig::default())
}

/// Parse an untrusted DHCP message, classifying it as valid, recoverable
/// or rejected. Recoverable and rejected inputs come with issues carrying
/// stable byte offsets into `i`.
pub fn parse_dhcp_message_strict_with_config<'a>(
    i: &'a [u8],
    config: &StrictConfig,
) -> StrictVerdict<'a> {
    if i.len() < MIN_MESSAGE_LEN {
        return reject(IssueKind::Truncated, i.len());
    }
    if i[OFFSET_MAGIC..OFFSET_MAGIC + 4] != DHCP_MAGIC_COOKIE {
        return reject(IssueKind::BadMagicCookie, OFFSET_MAGIC);
    }

    let mut warnings = Vec::new();
    check_nul_padding(&i[OFFSET_SNAME..OFFSET_FILE], OFFSET_SNAME, &mut warnings);
    check_nul_padding(&i[OFFSET_FILE..OFFSET_MAGIC], OFFSET_FILE, &mut warnings);

    let mut options = Vec::new();
    let mut pos = OFFSET_OPTIONS;
    loop {
        if pos >= i.len() {
            return reject(IssueKind::MissingEndOption, i.len());
        }
        let t = i[pos];
        if t == 255 {
            options.push(DHCPOption::End);
            pos += 1;
            break;
        }
        if options.len() >= config.max_options {
            return reject(IssueKind::TooManyOptions, pos);
        }
        if t == 0 {
            options.push(DHCPOption::Pad);
            pos += 1;
            continue;
        }
        if pos + 2 > i.len() {
            return reject(IssueKind::Truncated, pos);
        }
        let l = i[pos + 1] as usize;
        if pos + 2 + l > i.len() {
            return reject(IssueKind::Truncated, pos);
        }
        let opt = DHCPGenericOption {
            t,
            l: l as u8,
            v: &i[pos + 2..pos + 2 + l],
        };
        let opt = match convert_generic_option(&i[pos + 2 + l..], opt) {
            Ok((_, opt)) => opt,
            Err(_) => return reject(IssueKind::InvalidOptionLength, pos),
        };
        options.push(opt);
        pos += 2 + l;
    }

    if let Some(bad) = i[pos..].iter().position(|&b| b != 0) {
        warnings.push(ParseIssue {
            kind: IssueKind::TrailingGarbage,
            offset: pos + bad,
        });
    }

    let msg = DHCPMessage {
        op: i[0],
        htype: i[1],
        hlen: i[2],
        hops: i[3],
        xid: u32::from_be_bytes([i[4], i[5], i[6], i[7]]),
        secs: u16::from_be_bytes([i[8], i[9]]),
        flags: u16::from_be_bytes([i[10], i[11]]),
        ciaddr: addr_v4(&i[12..16]),
        yiaddr: addr_v4(&i[16..20]),
        siaddr: addr_v4(&i[20..24]),
        giaddr: addr_v4(&i[24..28]),
        chaddr: i[28..44].to_owned(),
        sname: &i[OFFSET_SNAME..OFFSET_FILE],
        file: &i[OFFSET_FILE..OFFSET_MAGIC],
        magic: i[OFFSET_MAGIC..OFFSET_MAGIC + 4].to_owned(),
        options,
    };
    if warnings.is_empty() {
        StrictVerdict::Valid(msg)
    } else {
        StrictVerdict::Recoverable(msg, warnings)
    }
}

fn addr_v4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

fn check_nul_padding(field: &[u8], base: usize, warnings: &mut Vec<ParseIssue>) {
    match field.iter().position(|&b| b == 0) {
        Some(nul) => {
            if let Some(bad) = field[nul + 1..].iter().position(|&b| b != 0) {
                warnings.push(ParseIssue {
                    kind: IssueKind::NonZeroPadding,
                    offset: base + nul + 1 + bad,
                });
            }
        }
        None => warnings.push(ParseIssue {
            kind: IssueKind::MissingNulTerminator,
            offset: base,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DHCPMessageType;

    static DHCP_DISCOVER: &'static [u8] = include_bytes!("../assets/dhcp-discover.bin");

    fn issue(kind: IssueKind, offset: usize) -> ParseIssue {
        ParseIssue { kind, offset }
    }

    #[test]
    fn strict_discover_is_valid() {
        let verdict = parse_dhcp_message_strict(DHCP_DISCOVER);
        assert_eq!(verdict.category(), Category::Valid);
        let msg = verdict.message().expect("message");
        assert_eq!(msg.options.len(), 5);
        assert_eq!(msg.message_type(), Some(DHCPMessageType::DHCPDISCOVER));
        const EXPECTED: &[u8] = &[0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42];
        assert_eq!(msg.hw_addr(), Some(EXPECTED));
    }

    #[test]
    fn strict_bad_magic_cookie_is_rejected() {
        let mut data = DHCP_DISCOVER.to_vec();
        data[OFFSET_MAGIC] ^= 0xff;
        let verdict = parse_dhcp_message_strict(&data);
        match verdict {
            StrictVerdict::Reject(iss) => {
                assert_eq!(iss, issue(IssueKind::BadMagicCookie, OFFSET_MAGIC))
            }
            _ => panic!("expected reject, got {:?}", verdict.category()),
        }
    }

    #[test]
    fn strict_truncated_header_is_rejected() {
        let verdict = parse_dhcp_message_strict(&DHCP_DISCOVER[..100]);
        match verdict {
            StrictVerdict::Reject(iss) => assert_eq!(iss, issue(IssueKind::Truncated, 100)),
            _ => panic!("expected reject, got {:?}", verdict.category()),
        }
    }

    #[test]
    fn strict_truncated_option_is_rejected() {
        // cut in the middle of the client-identifier option starting at 243
        let verdict = parse_dhcp_message_strict(&DHCP_DISCOVER[..250]);
        match verdict {
            StrictVerdict::Reject(iss) => assert_eq!(iss, issue(IssueKind::Truncated, 243)),
            _ => panic!("expected reject, got {:?}", verdict.category()),
        }
    }

    #[test]
    fn strict_missing_end_option_is_rejected() {
        // cut right before the End option at offset 264
        let verdict = parse_dhcp_message_strict(&DHCP_DISCOVER[..264]);
        match verdict {
            StrictVerdict::Reject(iss) => {
                assert_eq!(iss, issue(IssueKind::MissingEndOption, 264))
            }
            _ => panic!("expected reject, got {:?}", verdict.category()),
        }
    }

    #[test]
    fn strict_options_budget_is_enforced() {
        // the discover fixture holds 4 options before End
        let config = StrictConfig { max_options: 4 };
        let verdict = parse_dhcp_message_strict_with_config(DHCP_DISCOVER, &config);
        assert_eq!(verdict.category(), Category::Valid);

        let config = StrictConfig { max_options: 3 };
        let verdict = parse_dhcp_message_strict_with_config(DHCP_DISCOVER, &config);
        match verdict {
            // 4th option (parameter request list) starts at offset 258
            StrictVerdict::Reject(iss) => {
                assert_eq!(iss, issue(IssueKind::TooManyOptions, 258))
            }
            _ => panic!("expected reject, got {:?}", verdict.category()),
        }

        // flood of tiny options must hit the default budget
        let mut data = DHCP_DISCOVER[..OFFSET_OPTIONS].to_vec();
        for _ in 0..DEFAULT_MAX_OPTIONS + 1 {
            data.extend_from_slice(&[56, 0]);
        }
        data.push(255);
        let verdict = parse_dhcp_message_strict(&data);
        match verdict {
            StrictVerdict::Reject(iss) => assert_eq!(
                iss,
                issue(
                    IssueKind::TooManyOptions,
                    OFFSET_OPTIONS + 2 * DEFAULT_MAX_OPTIONS
                )
            ),
            _ => panic!("expected reject, got {:?}", verdict.category()),
        }
    }

    #[test]
    fn strict_invalid_option_length_is_rejected() {
        let mut data = DHCP_DISCOVER.to_vec();
        // message-type option at 240 must have length 1
        data[241] = 2;
        let verdict = parse_dhcp_message_strict(&data);
        match verdict {
            StrictVerdict::Reject(iss) => {
                assert_eq!(iss, issue(IssueKind::InvalidOptionLength, 240))
            }
            _ => panic!("expected reject, got {:?}", verdict.category()),
        }
    }

    #[test]
    fn strict_dirty_sname_padding_is_recoverable() {
        let mut data = DHCP_DISCOVER.to_vec();
        data[50] = 0x41;
        let verdict = parse_dhcp_message_strict(&data);
        match verdict {
            StrictVerdict::Recoverable(msg, issues) => {
                assert_eq!(issues, vec![issue(IssueKind::NonZeroPadding, 50)]);
                assert_eq!(msg.options.len(), 5);
            }
            _ => panic!("expected recoverable, got {:?}", verdict.category()),
        }
    }

    #[test]
    fn strict_dirty_file_padding_is_recoverable() {
        let mut data = DHCP_DISCOVER.to_vec();
        data[200] = 0x41;
        let verdict = parse_dhcp_message_strict(&data);
        match verdict {
            StrictVerdict::Recoverable(_, issues) => {
                assert_eq!(issues, vec![issue(IssueKind::NonZeroPadding, 200)]);
            }
            _ => panic!("expected recoverable, got {:?}", verdict.category()),
        }
    }

    #[test]
    fn strict_trailing_garbage_is_recoverable() {
        let mut data = DHCP_DISCOVER.to_vec();
        let last = data.len() - 1;
        data[last] = 0x01;
        let verdict = parse_dhcp_message_strict(&data);
        match verdict {
            StrictVerdict::Recoverable(msg, issues) => {
                assert_eq!(issues, vec![issue(IssueKind::TrailingGarbage, last)]);
                assert_eq!(msg.options.len(), 5);
            }
            _ => panic!("expected recoverable, got {:?}", verdict.category()),
        }
    }
}
