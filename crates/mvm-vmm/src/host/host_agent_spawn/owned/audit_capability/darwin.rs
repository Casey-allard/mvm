//! Checked Darwin ancillary boundary. No process/cleanup authority constructor.
use std::{
    io, mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
};

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "original liveness sideband refused",
    )
}

/// Read-only compatibility gate. It creates no FD, authority or quota.
/// Keep this before registration reservations and signed control effects.
#[allow(unsafe_code)]
pub(super) fn require_supported_platform() -> io::Result<()> {
    const MAX_FDS: usize = 512;
    const CONTROL_BYTES: usize = 2060;
    // SAFETY: libc's constant geometry functions access no memory. Refuse an
    // unqualified cmsghdr/int layout rather than applying this decoder to it.
    let base = unsafe { libc::CMSG_LEN(0) } as usize;
    // SAFETY: the fixed 512-int payload fits u32 with header and padding; CMSG_SPACE only computes its size.
    let expected = unsafe { libc::CMSG_SPACE((MAX_FDS * mem::size_of::<i32>()) as u32) } as usize;
    if !cfg!(target_arch = "aarch64")
        || mem::size_of::<usize>() != 8
        || base != 12
        || mem::size_of::<libc::cmsghdr>() != 12
        || mem::size_of::<i32>() != 4
        || expected != CONTROL_BYTES
    {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    // This finite-envelope profile is qualified only on the recorded native
    // build. Public XNU source corroboration is not runtime kernel identity.
    for (name, expected) in [
        (c"kern.osrelease", b"27.0.0\0".as_slice()),
        (c"kern.osversion", b"26A5378n\0".as_slice()),
    ] {
        let mut value = [0u8; 32];
        let mut length = value.len();
        // SAFETY: name is a static C string; length describes writable value, and null/0 requests no update.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 || length > value.len() || value[..length] != *expected {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
    }
    Ok(())
}

/// Darwin may leave cmsg_len larger than copied control storage on MSG_CTRUNC.
/// The Rustix iterator cannot be used on that record. This leaf checks copied
/// geometry before any FD ownership conversion. Darwin installs ALL rights
/// before copying the control bytes, so a small buffer would leak unreported
/// owners on truncation. Reserve the complete source-qualified kernel envelope
/// before recvmsg; reject application extras while owning/closing every right.
/// Unexpected CTRUNC invalidates platform qualification (it cannot prove closure
/// of unreported owners). No guessed/padding integer is converted into an owner.
#[allow(unsafe_code)]
pub(super) fn receive_now(stream: &UnixStream) -> io::Result<OwnedFd> {
    // Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea:
    // sockargs MT_CONTROL limits its expanded allocation to MCLBYTES=2048;
    // unp_internalize requires one SCM_RIGHTS header spanning the entire record.
    // Its source MAX_CMSG_FD=512 and static assertion cover that full envelope.
    // The actual selected kernel's 254/255-right boundary is a native gate, not
    // an assumption that the public source exactly identifies a running kernel.
    const MAX_FDS: usize = 512;
    const CONTROL_BYTES: usize = 2060;
    #[repr(C, align(16))]
    struct Control([u8; CONTROL_BYTES]);
    require_supported_platform()?;
    let base = 12usize;
    // The private canonical UDS uses default control options. Refuse options
    // that could add kernel-generated headers outside the rights-only envelope.
    for option in [libc::SO_TIMESTAMP, libc::SO_TIMESTAMP_MONOTONIC] {
        let mut enabled: libc::c_int = 0;
        let mut length = mem::size_of_val(&enabled) as libc::socklen_t;
        // SAFETY: getsockopt only writes the advertised initialized integer;
        // stream remains a live original UnixStream throughout this call.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&mut enabled as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        if result != 0 || length as usize != mem::size_of_val(&enabled) || enabled != 0 {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
    }
    // Initializing to -1 prevents an untouched complete slot from masquerading
    // as descriptor zero. Only bytes inside returned msg_controllen are parsed.
    let mut control = Control([0xff; CONTROL_BYTES]);
    let mut byte = [0u8; 1];
    let mut iovec = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: msghdr consists of pointers/integers; every used field below is
    // initialized and all pointed-to storage remains exclusive/live in recvmsg.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = CONTROL_BYTES.try_into().map_err(|_| refused())?;
    // SAFETY: the owned UnixStream descriptor is live; the one-byte iovec and
    // aligned fixed control allocation have exactly the capacities advertised.
    let bytes = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
    if bytes < 0 {
        return Err(io::Error::last_os_error());
    }
    let reported = usize::try_from(message.msg_controllen).map_err(|_| refused())?;
    let copied = reported.min(CONTROL_BYTES);
    let mut invalid = reported > CONTROL_BYTES;
    let mut descriptors: [Option<OwnedFd>; MAX_FDS] = std::array::from_fn(|_| None);
    let mut count = 0usize;
    let mut headers = 0usize;
    let mut offset = 0usize;
    while offset < copied {
        if copied - offset < base {
            invalid = true;
            break;
        }
        // SAFETY: the complete header fits the initialized copied byte range.
        // read_unaligned imposes no alignment assumption on subsequent records.
        let header = unsafe {
            std::ptr::read_unaligned(control.0.as_ptr().add(offset).cast::<libc::cmsghdr>())
        };
        let length = header.cmsg_len as usize;
        if length < base {
            invalid = true;
            break;
        }
        headers += 1;
        let end = offset.checked_add(length).ok_or_else(refused)?;
        let available_end = end.min(copied);
        let start = offset + base;
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let payload = available_end - start;
            if !payload.is_multiple_of(mem::size_of::<i32>()) {
                invalid = true;
            }
            for position in (start..available_end - payload % 4).step_by(4) {
                // SAFETY: this complete initialized int lies inside a copied
                // kernel SCM_RIGHTS payload. No header-claimed out-of-bounds
                // slot or alignment padding is read, even on truncation.
                let raw = unsafe {
                    std::ptr::read_unaligned(control.0.as_ptr().add(position).cast::<i32>())
                };
                if raw < 0 {
                    invalid = true;
                    continue;
                }
                if descriptors.iter().flatten().any(|fd| fd.as_raw_fd() == raw) {
                    invalid = true;
                    continue;
                }
                // SAFETY: recvmsg installed this complete SCM_RIGHTS integer as
                // a new receiver-owned descriptor. It has not been adopted yet.
                let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
                if count < MAX_FDS {
                    descriptors[count] = Some(descriptor);
                } else {
                    drop(descriptor);
                    invalid = true;
                }
                count += 1;
            }
        } else {
            invalid = true;
        }
        if end > copied {
            invalid = true;
            break;
        }
        let next = end.checked_add(3).ok_or_else(refused)? & !3;
        if next <= offset {
            invalid = true;
            break;
        }
        offset = next.min(copied);
    }
    if bytes != 1
        || byte != [0xa2]
        || count != 1
        || headers != 1
        || invalid
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
    {
        return Err(refused());
    }
    let descriptor = descriptors[0].take().ok_or_else(refused)?;
    rustix::io::fcntl_setfd(
        &descriptor,
        rustix::io::fcntl_getfd(&descriptor)? | rustix::io::FdFlags::CLOEXEC,
    )?;
    Ok(descriptor)
}
