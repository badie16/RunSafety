//! Linux netlink process connector for instant process event notifications.
//!
//! Uses NETLINK_CONNECTOR with CN_IDX_PROC to receive fork/exec events from the
//! kernel without polling. Requires CAP_NET_ADMIN or root. Falls back gracefully
//! when unavailable.

use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

const NETLINK_CONNECTOR: libc::c_int = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;

const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;

/// A process exec event from the kernel.
pub struct ExecEvent {
    pub process_pid: u32,
}

/// A process fork event from the kernel.
#[allow(dead_code)]
pub struct ForkEvent {
    pub parent_pid: u32,
    pub child_pid: u32,
}

/// Events received from the proc connector.
pub enum ProcEvent {
    Exec(ExecEvent),
    #[allow(dead_code)]
    Fork(ForkEvent),
}

/// Wrapper around a raw fd that closes on drop.
struct NetlinkFd(RawFd);

impl AsRawFd for NetlinkFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for NetlinkFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Async netlink proc connector.
/// Receives instant notifications when any process on the system forks or execs.
pub struct ProcConnector {
    fd: AsyncFd<NetlinkFd>,
}

impl ProcConnector {
    /// Open a netlink proc connector socket and subscribe to events.
    /// Returns Err if the socket can't be created (missing permissions, etc.).
    pub fn new() -> io::Result<Self> {
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                NETLINK_CONNECTOR,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let fd = NetlinkFd(raw_fd);

        // Bind to proc connector multicast group
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = unsafe { libc::getpid() } as u32;
        addr.nl_groups = CN_IDX_PROC;

        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Subscribe to proc events
        send_subscribe(&fd)?;

        let async_fd = AsyncFd::new(fd)?;
        Ok(Self { fd: async_fd })
    }

    /// Wait for and return the next proc event.
    /// Returns None for events we don't care about (uid change, exit, etc.).
    pub async fn recv_event(&self) -> io::Result<Option<ProcEvent>> {
        let mut buf = [0u8; 4096];

        loop {
            let mut guard = self.fd.readable().await?;

            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::recv(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                        0,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Ok(parse_proc_event(&buf[..n])),
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Send the PROC_CN_MCAST_LISTEN subscription message.
fn send_subscribe(fd: &NetlinkFd) -> io::Result<()> {
    // Message layout: [nlmsghdr][cn_msg][u32 mcast_op]
    const NL_HDR_SIZE: usize = 16; // nlmsghdr: len(4) + type(2) + flags(2) + seq(4) + pid(4)
    const CN_MSG_SIZE: usize = 20; // cn_msg: idx(4) + val(4) + seq(4) + ack(4) + len(2) + flags(2)
    const TOTAL: usize = NL_HDR_SIZE + CN_MSG_SIZE + 4;

    let mut buf = [0u8; TOTAL];

    // nlmsghdr
    buf[0..4].copy_from_slice(&(TOTAL as u32).to_ne_bytes()); // nlmsg_len
    buf[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes()); // nlmsg_type
                                                                         // nlmsg_flags = 0, nlmsg_seq = 0
    let pid = unsafe { libc::getpid() } as u32;
    buf[12..16].copy_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

    // cn_msg
    let cn = NL_HDR_SIZE;
    buf[cn..cn + 4].copy_from_slice(&CN_IDX_PROC.to_ne_bytes()); // id.idx
    buf[cn + 4..cn + 8].copy_from_slice(&CN_VAL_PROC.to_ne_bytes()); // id.val
                                                                     // seq = 0, ack = 0
    buf[cn + 16..cn + 18].copy_from_slice(&4u16.to_ne_bytes()); // len = sizeof(u32)
                                                                // flags = 0

    // mcast op
    let op = cn + CN_MSG_SIZE;
    buf[op..op + 4].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());

    let ret = unsafe {
        libc::send(
            fd.as_raw_fd(),
            buf.as_ptr().cast::<libc::c_void>(),
            TOTAL,
            0,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Parse a netlink message into a ProcEvent.
/// Message layout: [nlmsghdr(16)][cn_msg(20)][proc_event]
/// proc_event layout: what(4) + cpu(4) + timestamp_ns(8) + event_data(...)
fn parse_proc_event(buf: &[u8]) -> Option<ProcEvent> {
    const NL_HDR_SIZE: usize = 16;
    const CN_MSG_SIZE: usize = 20;
    const EVENT_OFFSET: usize = NL_HDR_SIZE + CN_MSG_SIZE;
    // proc_event header: what(4) + cpu(4) + timestamp_ns(8) = 16
    const DATA_OFFSET: usize = EVENT_OFFSET + 16;

    if buf.len() < DATA_OFFSET {
        return None;
    }

    let what = u32::from_ne_bytes(buf[EVENT_OFFSET..EVENT_OFFSET + 4].try_into().ok()?);

    match what {
        PROC_EVENT_EXEC => {
            if buf.len() < DATA_OFFSET + 8 {
                return None;
            }
            let pid = u32::from_ne_bytes(buf[DATA_OFFSET..DATA_OFFSET + 4].try_into().ok()?);
            Some(ProcEvent::Exec(ExecEvent { process_pid: pid }))
        }
        PROC_EVENT_FORK => {
            if buf.len() < DATA_OFFSET + 16 {
                return None;
            }
            let parent_pid = u32::from_ne_bytes(buf[DATA_OFFSET..DATA_OFFSET + 4].try_into().ok()?);
            let child_pid =
                u32::from_ne_bytes(buf[DATA_OFFSET + 8..DATA_OFFSET + 12].try_into().ok()?);
            Some(ProcEvent::Fork(ForkEvent {
                parent_pid,
                child_pid,
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_too_short() {
        let buf = [0u8; 10];
        assert!(parse_proc_event(&buf).is_none());
    }

    #[test]
    fn parse_unknown_event_type() {
        // Build a minimal buffer with an unknown event type (0xFF)
        let mut buf = [0u8; 64];
        let event_offset = 16 + 20; // NL_HDR + CN_MSG
        buf[event_offset..event_offset + 4].copy_from_slice(&0xFFu32.to_ne_bytes());
        assert!(parse_proc_event(&buf).is_none());
    }

    #[test]
    fn parse_exec_event() {
        let mut buf = [0u8; 72];
        let event_offset = 16 + 20;
        let data_offset = event_offset + 16;

        // what = PROC_EVENT_EXEC
        buf[event_offset..event_offset + 4].copy_from_slice(&PROC_EVENT_EXEC.to_ne_bytes());
        // process_pid = 1234
        buf[data_offset..data_offset + 4].copy_from_slice(&1234u32.to_ne_bytes());
        // process_tgid = 1234
        buf[data_offset + 4..data_offset + 8].copy_from_slice(&1234u32.to_ne_bytes());

        let event = parse_proc_event(&buf).unwrap();
        match event {
            ProcEvent::Exec(e) => assert_eq!(e.process_pid, 1234),
            _ => panic!("Expected Exec event"),
        }
    }

    #[test]
    fn parse_fork_event() {
        let mut buf = [0u8; 72];
        let event_offset = 16 + 20;
        let data_offset = event_offset + 16;

        // what = PROC_EVENT_FORK
        buf[event_offset..event_offset + 4].copy_from_slice(&PROC_EVENT_FORK.to_ne_bytes());
        // parent_pid = 100
        buf[data_offset..data_offset + 4].copy_from_slice(&100u32.to_ne_bytes());
        // parent_tgid = 100
        buf[data_offset + 4..data_offset + 8].copy_from_slice(&100u32.to_ne_bytes());
        // child_pid = 200
        buf[data_offset + 8..data_offset + 12].copy_from_slice(&200u32.to_ne_bytes());
        // child_tgid = 200
        buf[data_offset + 12..data_offset + 16].copy_from_slice(&200u32.to_ne_bytes());

        let event = parse_proc_event(&buf).unwrap();
        match event {
            ProcEvent::Fork(f) => {
                assert_eq!(f.parent_pid, 100);
                assert_eq!(f.child_pid, 200);
            }
            _ => panic!("Expected Fork event"),
        }
    }
}
