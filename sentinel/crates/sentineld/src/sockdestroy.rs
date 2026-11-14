//! `SOCK_DESTROY` over `NETLINK_SOCK_DIAG`, the user-space half of freeze
//! (spec §6, amendment 2 of §17).

use std::collections::HashSet;

use crate::kernel::KernelError;

/// `sock_diag` message types (`linux/sock_diag.h`).
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const SOCK_DESTROY: u16 = 21;

pub const NLM_F_REQUEST: u16 = 0x01;
/// `NLM_F_ROOT | NLM_F_MATCH`, as `linux/netlink.h` defines it.
pub const NLM_F_DUMP: u16 = 0x300;

/// `NETLINK_SOCK_DIAG`.
const NETLINK_SOCK_DIAG: libc::c_int = 4;

/// `inet_diag_sockid` plus the inode, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockId {
    pub sport: u16,
    pub dport: u16,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub iface: u32,
    pub cookie: [u32; 2],
    pub family: u8,
    pub inode: u32,
}

/// The inode out of a `/proc/<pid>/fd/<n>` link target.
pub fn socket_inode(target: &str) -> Option<u32> {
    target
        .strip_prefix("socket:[")
        .and_then(|r| r.strip_suffix(']'))
        .and_then(|n| n.parse().ok())
}

/// `nlmsghdr` + `inet_diag_req_v2`, 16 + 56 bytes.
fn request(
    nlmsg_type: u16,
    flags: u16,
    seq: u32,
    family: u8,
    protocol: u8,
    states: u32,
    id: Option<&SockId>,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(72);
    // struct nlmsghdr
    m.extend_from_slice(&72u32.to_ne_bytes()); // nlmsg_len
    m.extend_from_slice(&nlmsg_type.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
                                              // struct inet_diag_req_v2
    m.push(family); // sdiag_family
    m.push(protocol); // sdiag_protocol
    m.push(0); // idiag_ext
    m.push(0); // pad
    m.extend_from_slice(&states.to_ne_bytes()); // idiag_states
                                                // struct inet_diag_sockid (48 bytes)
    match id {
        Some(s) => {
            m.extend_from_slice(&s.sport.to_be_bytes());
            m.extend_from_slice(&s.dport.to_be_bytes());
            m.extend_from_slice(&s.src);
            m.extend_from_slice(&s.dst);
            m.extend_from_slice(&s.iface.to_ne_bytes());
            m.extend_from_slice(&s.cookie[0].to_ne_bytes());
            m.extend_from_slice(&s.cookie[1].to_ne_bytes());
        }
        None => m.extend_from_slice(&[0u8; 48]),
    }
    debug_assert_eq!(m.len(), 72);
    m
}

/// Ask for every socket of this family and protocol.
pub fn dump_request(family: u8, protocol: u8, seq: u32) -> Vec<u8> {
    request(
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
        family,
        protocol,
        u32::MAX, // every TCP state
        None,
    )
}

/// Destroy exactly this socket.
pub fn destroy_request(id: &SockId, protocol: u8, seq: u32) -> Vec<u8> {
    request(
        SOCK_DESTROY,
        NLM_F_REQUEST,
        seq,
        id.family,
        protocol,
        u32::MAX,
        Some(id),
    )
}

/// Every socket inode held by these pids.
fn socket_inodes_of(pids: &[u32]) -> HashSet<u32> {
    let mut out = HashSet::new();
    for pid in pids {
        let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for ent in rd.flatten() {
            if let Ok(target) = std::fs::read_link(ent.path()) {
                if let Some(ino) = socket_inode(&target.to_string_lossy()) {
                    out.insert(ino);
                }
            }
        }
    }
    out
}

/// Parse one `inet_diag_msg` out of a dump reply body (after the nlmsghdr).
/// Layout: family, state, timer, retrans (4 bytes), then the 48-byte sockid,
/// then expires, rqueue, wqueue, uid, inode (5 x u32).
fn parse_diag_msg(body: &[u8]) -> Option<SockId> {
    if body.len() < 72 {
        return None;
    }
    let family = body[0];
    let sport = u16::from_be_bytes(body[4..6].try_into().ok()?);
    let dport = u16::from_be_bytes(body[6..8].try_into().ok()?);
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&body[8..24]);
    dst.copy_from_slice(&body[24..40]);
    let iface = u32::from_ne_bytes(body[40..44].try_into().ok()?);
    let cookie = [
        u32::from_ne_bytes(body[44..48].try_into().ok()?),
        u32::from_ne_bytes(body[48..52].try_into().ok()?),
    ];
    let inode = u32::from_ne_bytes(body[68..72].try_into().ok()?);
    Some(SockId {
        sport,
        dport,
        src,
        dst,
        iface,
        cookie,
        family,
        inode,
    })
}

/// Destroy every TCP and UDP socket belonging to `pids`. Returns the count.
///
/// A failure to destroy one socket is not a failure of the freeze: the LSM
/// hooks already deny the cgroup's `connect` and `sendmsg`, so the worst case
/// is one connection that stays open until its peer gives up.
pub fn destroy_for_pids(pids: &[u32]) -> Result<usize, KernelError> {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    if pids.is_empty() {
        return Ok(0);
    }
    let wanted = socket_inodes_of(pids);
    if wanted.is_empty() {
        return Ok(0);
    }

    // SAFETY: a plain socket(2) call; the fd is adopted below and closed on drop.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(KernelError(format!(
            "sock_diag socket: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fd is a fresh, valid, owned descriptor. The UnixStream is only a
    // read/write wrapper around it; nothing here depends on its address family.
    let mut sock = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };

    // A read timeout is not optional here. This runs inside a freeze, which
    // the event loop performs while holding both the daemon and the kernel
    // lock, so a reply that never comes would not merely lose one socket --
    // it would wedge the whole daemon, varlink included. Losing a dump is
    // acceptable: the LSM hooks already deny the cgroup's new connections.
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(500)));

    let mut destroyed = 0usize;
    let mut seq = 1u32;
    for (family, protocol) in [
        (libc::AF_INET as u8, libc::IPPROTO_TCP as u8),
        (libc::AF_INET6 as u8, libc::IPPROTO_TCP as u8),
        (libc::AF_INET as u8, libc::IPPROTO_UDP as u8),
        (libc::AF_INET6 as u8, libc::IPPROTO_UDP as u8),
    ] {
        if sock
            .write_all(&dump_request(family, protocol, seq))
            .is_err()
        {
            continue;
        }
        seq += 1;

        let mut found: Vec<SockId> = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        'dump: loop {
            let n = match sock.read(&mut buf) {
                Ok(0) | Err(_) => break 'dump,
                Ok(n) => n,
            };
            let mut off = 0usize;
            while off + 16 <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
                if len < 16 || off + len > n {
                    break 'dump;
                }
                // NLMSG_DONE = 3, NLMSG_ERROR = 2.
                if ty == 3 || ty == 2 {
                    break 'dump;
                }
                if let Some(id) = parse_diag_msg(&buf[off + 16..off + len]) {
                    if wanted.contains(&id.inode) {
                        found.push(id);
                    }
                }
                off += (len + 3) & !3; // NLMSG_ALIGN
            }
        }

        for id in found {
            if sock.write_all(&destroy_request(&id, protocol, seq)).is_ok() {
                destroyed += 1;
            }
            seq += 1;
            // Drain the acknowledgement so the next dump reads cleanly.
            let mut ack = [0u8; 4096];
            let _ = sock.read(&mut ack);
        }
    }
    Ok(destroyed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_inodes_are_parsed_from_fd_targets() {
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("socket:[0]"), Some(0));
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("pipe:[99]"), None);
        assert_eq!(socket_inode("socket:[nope]"), None);
    }

    #[test]
    fn a_dump_request_is_a_well_formed_netlink_message() {
        let msg = dump_request(libc::AF_INET as u8, libc::IPPROTO_TCP as u8, 1);
        // nlmsghdr is 16 bytes, inet_diag_req_v2 is 56; total 72.
        assert_eq!(msg.len(), 72);
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()), 72);
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            SOCK_DIAG_BY_FAMILY
        );
        let flags = u16::from_ne_bytes(msg[6..8].try_into().unwrap());
        assert!(flags & NLM_F_DUMP != 0, "a dump sets NLM_F_DUMP");
        assert_eq!(msg[16], libc::AF_INET as u8, "sdiag_family");
        assert_eq!(msg[17], libc::IPPROTO_TCP as u8, "sdiag_protocol");
    }

    #[test]
    fn a_destroy_request_targets_one_socket_and_is_not_a_dump() {
        let id = SockId {
            sport: 1234,
            dport: 443,
            src: [10, 0, 2, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst: [10, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            iface: 0,
            cookie: [7, 9],
            family: libc::AF_INET as u8,
            inode: 4242,
        };
        let msg = destroy_request(&id, libc::IPPROTO_TCP as u8, 2);
        assert_eq!(msg.len(), 72);
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            SOCK_DESTROY
        );
        let flags = u16::from_ne_bytes(msg[6..8].try_into().unwrap());
        assert!(flags & NLM_F_DUMP == 0, "a destroy is not a dump");
        assert!(flags & NLM_F_REQUEST != 0);
        // inet_diag_req_v2 is family, protocol, ext, pad, then idiag_states,
        // so its sockid starts 8 bytes in -- offset 24 of the message. The
        // ports are the first two fields of the id, big-endian.
        assert_eq!(u16::from_be_bytes(msg[24..26].try_into().unwrap()), 1234);
        assert_eq!(u16::from_be_bytes(msg[26..28].try_into().unwrap()), 443);
    }

    #[test]
    fn a_destroy_request_carries_the_cookie() {
        let id = SockId {
            sport: 1,
            dport: 2,
            src: [0; 16],
            dst: [0; 16],
            iface: 0,
            cookie: [0xAA, 0xBB],
            family: libc::AF_INET as u8,
            inode: 1,
        };
        let msg = destroy_request(&id, libc::IPPROTO_TCP as u8, 1);
        // The cookie is the last 8 bytes of the 48-byte sockid, which runs
        // from offset 24 to 72.
        assert_eq!(u32::from_ne_bytes(msg[64..68].try_into().unwrap()), 0xAA);
        assert_eq!(u32::from_ne_bytes(msg[68..72].try_into().unwrap()), 0xBB);
    }

    #[test]
    fn a_dump_reply_round_trips_through_the_parser() {
        // An inet_diag_msg carries inet_diag_sockid four bytes in, the same
        // layout the request uses: build one and read it back, so encoder and
        // parser stay pinned to the offsets in the kernel header.
        let mut body = vec![libc::AF_INET as u8, 1, 0, 0];
        body.extend_from_slice(&4321u16.to_be_bytes()); // sport
        body.extend_from_slice(&80u16.to_be_bytes()); // dport
        body.extend_from_slice(&[10, 0, 2, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // src
        body.extend_from_slice(&[1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // dst
        body.extend_from_slice(&3u32.to_ne_bytes()); // iface
        body.extend_from_slice(&0xC0u32.to_ne_bytes()); // cookie[0]
        body.extend_from_slice(&0xDEu32.to_ne_bytes()); // cookie[1]
        body.extend_from_slice(&0u32.to_ne_bytes()); // expires
        body.extend_from_slice(&0u32.to_ne_bytes()); // rqueue
        body.extend_from_slice(&0u32.to_ne_bytes()); // wqueue
        body.extend_from_slice(&1000u32.to_ne_bytes()); // uid
        body.extend_from_slice(&9999u32.to_ne_bytes()); // inode
        assert_eq!(body.len(), 72);

        let id = parse_diag_msg(&body).expect("parses");
        assert_eq!(id.sport, 4321);
        assert_eq!(id.dport, 80);
        assert_eq!(id.iface, 3);
        assert_eq!(id.cookie, [0xC0, 0xDE]);
        assert_eq!(id.inode, 9999, "the inode is what a quarantine matches on");
        assert!(
            parse_diag_msg(&body[..40]).is_none(),
            "a short body is not a socket"
        );
    }

    #[test]
    fn destroying_no_pids_does_nothing() {
        assert_eq!(destroy_for_pids(&[]).unwrap(), 0);
    }
}
