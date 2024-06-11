// SPDX-License-Identifier: EPL-1.0 OR BSD-3-CLAUSE
/*
 * lib.rs - Main library file for raw TinyDTLS Rust bindings.
 * Copyright (c) 2021 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

// Bindgen translates the C headers, clippy's and rustfmt's recommendations are not applicable here.
#![allow(clippy::all)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(deref_nullptr)]

use std::fmt;

use libc::{sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t};

#[cfg(target_family = "windows")]
include!(concat!(env!("OUT_DIR"), "\\bindings.rs"));
#[cfg(not(target_family = "windows"))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// The dtls_set_handler function in tinydtls is an inline function, which is why it is not included
// in the bindgen-generated bindings.
// There is a workaround that could be applied to the vendored version (by setting a compiler flag
// that forces inclusion of inline functions in generated binaries), but this would only work for
// the vendored version and would also prevent inlining, reducing performance.
// Therefore, we just re-implement it here.
//
// See https://rust-lang.github.io/rust-bindgen/faq.html#why-isnt-bindgen-generating-bindings-to-inline-functions
#[inline]
pub unsafe fn dtls_set_handler(ctx: *mut dtls_context_t, h: *mut dtls_handler_t) {
    (*ctx).h = h;
}

// For backwards-compatibility, we add a Debug implementation of dtls_hello_verify_t.
// (Automatic derive stopped working with https://github.com/rust-lang/rust/pull/104429.)
impl fmt::Debug for dtls_hello_verify_t {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { version, cookie_length, cookie } = self;
        fmt.debug_struct("dtls_hello_verify_t")
            .field("version", version)
            .field("cookie_length", cookie_length)
            .field("cookie", cookie)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use libc::{c_int, c_uchar, c_ushort, in6_addr, in_addr, size_t};
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
    use std::time::Duration;

    const AF_INET: u16 = libc::AF_INET as u16;
    const AF_INET6: u16 = libc::AF_INET6 as u16;

    /// Message that the UDP echo server listens for (unencrypted) in order to determine whether it
    /// should shut down.
    const TERMINATE_SERVER_MESSAGE: &str = "TERMINATE SERVER";
    /// Message that should be sent over the encrypted channel for the UDP echo client/server test
    const ENC_MESSAGE: &str = "Encrypted Example Message";
    /// Name of the key used for the UDP echo client/server test.
    #[cfg(feature = "psk")]
    const PSK_IDENTITY: &str = "testkey";

    #[cfg(feature = "psk")]
    lazy_static! {
        /// Map for DTLS keys used in tests.
        static ref DTLS_KEYS: HashMap<&'static str, [u8; 16]> = {
            let mut map: HashMap<&'static str, [u8; 16]> = HashMap::new();
            map.insert(
                PSK_IDENTITY,
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                ],
            );
            map
        };
    }

    struct EchoTestClientState {
        socket: UdpSocket,
        finished: bool,
    }

    /// Converts a session pointer into a SocketAddr instance.
    ///
    /// # Safety
    /// The session is assumed to be a valid pointer to a session_t struct, whose addr-field
    /// contains a valid sockaddr value.
    unsafe fn session_to_socketaddr(session: *mut session_t) -> SocketAddr {
        let raw_target_addr = &session.as_ref().unwrap().addr;

        // SAFETY: Value is always some kind of sockaddr, so sa_family will be set.
        let family = raw_target_addr.sa.as_ref().sa_family;

        match family {
            AF_INET => {
                // SAFETY: We checked the value of sa_family to ensure that this value should actually be a sockaddr_in
                let raw_target_addr = raw_target_addr.sin.as_ref();
                // Sockaddr fields are in network byte order, so calling to_ne_bytes() will give us the value in network byte order, no matter the system endianness.
                let target_addr = Ipv4Addr::from(raw_target_addr.sin_addr.s_addr.to_ne_bytes());
                SocketAddr::V4(SocketAddrV4::new(target_addr, u16::from_be(raw_target_addr.sin_port)))
            }
            AF_INET6 => {
                // SAFETY: We checked the value of sa_family to ensure that this value should actually be a sockaddr_in6
                let raw_target_addr = raw_target_addr.sin6.as_ref();
                // Sockaddr fields are in network byte order, so calling to_ne_bytes() will give us the value in network byte order, no matter the system endianness.
                let target_addr = Ipv6Addr::from(raw_target_addr.sin6_addr.s6_addr);
                SocketAddr::V6(SocketAddrV6::new(
                    target_addr,
                    u16::from_be(raw_target_addr.sin6_port),
                    raw_target_addr.sin6_flowinfo,
                    raw_target_addr.sin6_scope_id,
                ))
            }
            // session.addr value is either sockaddr_in or sockaddr_in6, so sa_family has to either be AF_INET or AF_INET6
            _ => panic!("Invalid session address family"),
        }
    }

    /// Converts a SocketAddr instance into a freshly allocated session_t struct and returns a
    /// pointer to it.
    ///
    /// NOTE: The session_t is created using dtls_new_session() and has to be freed manually using
    /// dtls_free_session().
    /// This function returns the return value of dtls_new_session directly, therefore the pointer
    /// can be a null pointer(!).
    fn session_from_socketaddr(addr: &SocketAddr) -> *mut session_t {
        match addr {
            SocketAddr::V4(addr) => {
                let mut raw_addr = sockaddr_in {
                    sin_family: AF_INET,
                    sin_port: addr.port().to_be(),
                    sin_addr: in_addr {
                        s_addr: u32::from_ne_bytes(addr.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                // SAFETY: All pointers are valid, the supplied size is the size of the supplied struct.
                unsafe {
                    dtls_new_session(
                        &mut raw_addr as *mut sockaddr_in as *mut sockaddr,
                        std::mem::size_of::<sockaddr_in>() as socklen_t,
                    )
                }
            }
            SocketAddr::V6(addr) => {
                let mut raw_addr = sockaddr_in6 {
                    sin6_family: AF_INET6,
                    sin6_port: addr.port().to_be(),
                    sin6_flowinfo: addr.flowinfo(),
                    sin6_addr: in6_addr {
                        s6_addr: addr.ip().octets(),
                    },
                    sin6_scope_id: addr.scope_id(),
                };
                // SAFETY: All pointers are valid, the supplied size is the size of the supplied struct.
                unsafe {
                    dtls_new_session(
                        &mut raw_addr as *mut sockaddr_in6 as *mut sockaddr,
                        std::mem::size_of::<sockaddr_in6>() as socklen_t,
                    )
                }
            }
        }
    }

    /// Send callback for the UDP Echo Server Test (server side)
    ///
    /// # Safety
    /// This function is intended to be set as the write/send callback for a dtls context, and
    /// therefore expects the function arguments to match the values that tinydtls would set.
    /// It assumes that all supplied pointers are valid, that `data` points to a memory area of at
    /// least size `len`, and that the [app](dtls_context_t.app) field in the ctx argument is set to
    /// a *mut UdpSocket of the socket that should be used for the server.
    unsafe extern "C" fn echo_server_send_callback(
        ctx: *mut dtls_context_t,
        session: *mut session_t,
        data: *mut uint8,
        len: size_t,
    ) -> i32 {
        // SAFETY: Pointers are assumed to be valid, and data should point to a memory area of at least size len.
        let data = std::slice::from_raw_parts(data, len);
        let target_addr = session_to_socketaddr(session);

        println!("[ECHO SEND] sending {} bytes to {}: {:?}", len, &target_addr, data);

        // SAFETY: app_data is assumed to be set to a pointer to Rc<UdpSocket> by us on context creation.
        let socket = (ctx.as_ref().unwrap().app as *mut UdpSocket).as_ref().unwrap();
        match socket.send_to(data, target_addr) {
            Ok(num_bytes) => num_bytes as i32,
            Err(e) => e.raw_os_error().unwrap_or(-1),
        }
    }

    /// Send callback for the UDP Echo Server Test (client side)
    ///
    /// # Safety
    /// This function is intended to be set as the write/send callback for a dtls context, and
    /// therefore expects the function arguments to match the values that tinydtls would set.
    /// It assumes that all supplied pointers are valid, that `data` points to a memory area of at
    /// least size `len`, and that the [app](dtls_context_t.app) field in the ctx argument is set to
    /// a *mut EchoTestClientState representing the echo test client.
    unsafe extern "C" fn echo_client_send_callback(
        ctx: *mut dtls_context_t,
        session: *mut session_t,
        data: *mut uint8,
        len: size_t,
    ) -> i32 {
        let data = std::slice::from_raw_parts(data, len);
        let target_addr = session_to_socketaddr(session);

        println!("[ECHO SEND] sending {} bytes to {}: {:?}", len, &target_addr, data);

        let socket = &(ctx.as_ref().unwrap().app as *mut EchoTestClientState)
            .as_ref()
            .unwrap()
            .socket;
        match socket.send_to(data, target_addr) {
            Ok(num_bytes) => num_bytes as i32,
            Err(e) => e.raw_os_error().unwrap_or(-1),
        }
    }

    /// PSK information callback for the UDP Echo Server Test
    ///
    /// # Safety
    /// This function is intended to be set as the get_psk_info callback for a dtls context, and
    /// therefore expects the function arguments to match the values that tinydtls would set.
    /// It assumes that all supplied pointers are valid and that `desc`/`result` point to memory
    /// areas of at least size `desc_len`/`result_length`.
    #[cfg(feature = "psk")]
    unsafe extern "C" fn echo_get_psk_info(
        _ctx: *mut dtls_context_t,
        _session: *const session_t,
        type_: dtls_credentials_type_t,
        desc: *const c_uchar,
        desc_len: size_t,
        result: *mut c_uchar,
        result_length: size_t,
    ) -> i32 {
        let result = std::slice::from_raw_parts_mut(result, result_length);
        let desc = std::slice::from_raw_parts(desc, desc_len);
        match type_ {
            dtls_credentials_type_t::DTLS_PSK_HINT | dtls_credentials_type_t::DTLS_PSK_IDENTITY => {
                if result_length < PSK_IDENTITY.len() {
                    panic!("Result field too small to provide PSK identity/hint value")
                }
                result[..PSK_IDENTITY.len()].clone_from_slice(&PSK_IDENTITY.as_bytes());
                PSK_IDENTITY.len() as i32
            }
            dtls_credentials_type_t::DTLS_PSK_KEY => {
                if result_length < DTLS_KEYS.get(PSK_IDENTITY).unwrap().len() {
                    panic!("Result field too small to provide PSK key value")
                }
                result[..DTLS_KEYS
                    .get(std::str::from_utf8(desc).expect("Invalid PSK Identity"))
                    .unwrap()
                    .len()]
                    .clone_from_slice(
                        DTLS_KEYS
                            .get(std::str::from_utf8(desc).expect("Invalid PSK Identity"))
                            .unwrap(),
                    );
                DTLS_KEYS
                    .get(std::str::from_utf8(desc).expect("Invalid PSK Identity"))
                    .unwrap()
                    .len() as i32
            }
        }
    }

    /// Read callback for the UDP Echo Server Test (server-side).
    ///
    /// # Safety
    /// This function is intended to be set as the read callback for a dtls context, and
    /// therefore expects the function arguments to match the values that tinydtls would set.
    /// It assumes that all supplied pointers are valid and that `data` points to a memory area of at
    /// least size `len` containing the received and decrypted data.
    unsafe extern "C" fn echo_server_read_callback(
        ctx: *mut dtls_context_t,
        session: *mut session_t,
        data: *mut uint8,
        len: size_t,
    ) -> i32 {
        println!(
            "[ECHO SERVER] received {} bytes from {}: {:?}",
            len,
            session_to_socketaddr(session),
            data
        );
        dtls_write(ctx, session, data, len)
    }

    /// Read callback for the UDP Echo Server Test (client-side).
    ///
    /// # Safety
    /// This function is intended to be set as the read callback for a dtls context, and
    /// therefore expects the function arguments to match the values that tinydtls would set.
    /// It assumes that all supplied pointers are valid, that `data` points to a memory area of at
    /// least size `len` containing the received and decrypted data, and that the [app](dtls_context_t.app)
    /// field in the ctx argument is set to a *mut EchoTestClientState representing the echo test
    /// client.
    unsafe extern "C" fn echo_client_read_callback(
        ctx: *mut dtls_context_t,
        session: *mut session_t,
        data: *mut uint8,
        len: size_t,
    ) -> i32 {
        let data = std::slice::from_raw_parts(data, len);
        println!(
            "[ECHO CLIENT] received {} bytes from {}: {:?}",
            len,
            session_to_socketaddr(session),
            data
        );
        assert_eq!(data, ENC_MESSAGE.as_bytes());

        (ctx.as_ref().unwrap().app as *mut EchoTestClientState)
            .as_mut()
            .unwrap()
            .finished = true;
        let socket = &(ctx.as_ref().unwrap().app as *mut EchoTestClientState)
            .as_ref()
            .unwrap()
            .socket;
        match socket.send_to(TERMINATE_SERVER_MESSAGE.as_bytes(), session_to_socketaddr(session)) {
            Ok(count) => count as i32,
            Err(e) => e.raw_os_error().unwrap_or(-1),
        }
    }

    /// Event callback for the UDP Echo Server Test (client-side)
    ///
    /// # Safety
    /// This function is intended to be set as the event callback for a dtls context, and
    /// therefore expects the function arguments to match the values that tinydtls would set.
    /// It assumes that all supplied pointers are valid.
    unsafe extern "C" fn echo_client_event_callback(
        ctx: *mut dtls_context_t,
        session: *mut session_t,
        level: dtls_alert_level_t,
        code: c_ushort,
    ) -> i32 {
        println!(
            "[ECHO CLIENT] received Event from {} (level {:?}): {}",
            session_to_socketaddr(session),
            level,
            code
        );
        if level == dtls_alert_level_t::DTLS_ALERT_LEVEL_FATAL && u32::from(code) != DTLS_EVENT_CONNECTED {
            panic!("Fatal error in DTLS session")
        }
        match code as u32 {
            DTLS_EVENT_CONNECTED => {
                let mut buf = [0; ENC_MESSAGE.len()];
                buf.clone_from_slice(ENC_MESSAGE.as_bytes());
                dtls_write(ctx, session, buf.as_mut_ptr(), buf.len())
            }
            _ => 0,
        }
    }

    /// Event callback for the UDP Echo Server Test (server-side)
    ///
    /// # Safety
    /// This function is intended to be set as the event callback for a dtls context, and
    /// therefore expects the function arguments to match the values that tinydtls would set.
    /// It assumes that all supplied pointers are valid.
    unsafe extern "C" fn echo_server_event_callback(
        _ctx: *mut dtls_context_t,
        session: *mut session_t,
        level: dtls_alert_level_t,
        code: c_ushort,
    ) -> i32 {
        println!(
            "[ECHO SERVER] received Event from {} (level {:?}): {}",
            session_to_socketaddr(session),
            level,
            code
        );
        if level == dtls_alert_level_t::DTLS_ALERT_LEVEL_FATAL && u32::from(code) != DTLS_EVENT_CONNECTED {
            panic!("Fatal error in DTLS session")
        }
        0
    }

    /// Run the UDP DTLS echo server used for the [test_dtls_echo_client_server()] test.
    #[cfg(feature = "psk")]
    fn run_dtls_echo_server(mut socket: UdpSocket) {
        let mut dtls_handlers = dtls_handler_t {
            write: Some(echo_server_send_callback),
            read: Some(echo_server_read_callback),
            event: Some(echo_server_event_callback),
            get_psk_info: Some(echo_get_psk_info),
            get_ecdsa_key: None,
            verify_ecdsa_key: None,
            get_user_parameters: None,
        };

        // SAFETY: Supplied pointer is valid, dtls_new_context does not do anything with it except
        // storing it in its app field.
        let server_context = unsafe { dtls_new_context(&mut socket as *mut UdpSocket as *mut c_void) };
        assert!(!server_context.is_null());
        // SAFETY: Supplied pointers are valid (we just checked server_context, and dtls_handlers is a reference, so it must be valid).
        unsafe { dtls_set_handler(server_context, &mut dtls_handlers) };

        let mut buf: [u8; 512] = [0; 512];
        loop {
            let (read_bytes, peer) = socket.recv_from(&mut buf).expect("Error reading from socket");
            if read_bytes == TERMINATE_SERVER_MESSAGE.len()
                && &buf[0..read_bytes] == TERMINATE_SERVER_MESSAGE.as_bytes()
            {
                break;
            }
            let session = session_from_socketaddr(&peer);
            assert!(!session.is_null());
            // SAFETY: server_context has already been checked and is not invalidated by any called methods up to this point.
            // We just checked that session is not null. msg and msglen are set correctly to our buffer and the length of the read data.
            // dtls_handle_message() does not modify the session, neither do our handlers, therefore the call to dtls_free_session is valid.
            unsafe {
                dtls_handle_message(server_context, session, buf.as_mut_ptr(), read_bytes as c_int);
                dtls_free_session(session);
            }
        }
        // SAFETY: We have not called anything that would invalidate our context up to this point, so
        // this pointer should be valid up until here.
        unsafe {
            dtls_free_context(server_context);
        }
    }

    /// Test case that creates a basic UDP echo server over an encrypted DTLS socket and then sends
    /// a message to it.
    /// Based on the example described on the main page of the tinydtls documentation
    /// (https://github.com/obgm/tinydtls/blob/develop/dtls.h#L416)
    #[test]
    #[cfg(feature = "psk")]
    fn test_dtls_echo_client_server() {
        // Binding to port 0 gives us any available free port.
        let server_socket = UdpSocket::bind("localhost:0").expect("Could not bind UDP socket");
        server_socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("Could not set socket timeout");
        server_socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("Could not set socket timeout");
        let server_addr = server_socket.local_addr().unwrap();
        let server_thread = std::thread::spawn(move || run_dtls_echo_server(server_socket));

        let mut dtls_handlers = dtls_handler_t {
            write: Some(echo_client_send_callback),
            read: Some(echo_client_read_callback),
            event: Some(echo_client_event_callback),
            get_psk_info: Some(echo_get_psk_info),
            get_ecdsa_key: None,
            verify_ecdsa_key: None,
            get_user_parameters: None,
        };

        let client_socket = UdpSocket::bind("localhost:0").expect("Could not bind UDP socket");
        client_socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("Could not set socket timeout");
        client_socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("Could not set socket timeout");
        let mut client_state = EchoTestClientState {
            socket: client_socket,
            finished: false,
        };
        // SAFETY: Supplied pointer is valid, dtls_new_context does not do anything with it except
        // storing it in its app field.
        let client_context = unsafe { dtls_new_context(&mut client_state as *mut EchoTestClientState as *mut c_void) };
        assert!(!client_context.is_null());
        // SAFETY: Supplied pointers are valid (we just checked client_context, and dtls_handlers is a reference, so it must be valid).
        unsafe {
            dtls_set_handler(client_context, &mut dtls_handlers);
        };
        let session = session_from_socketaddr(&server_addr);
        assert!(!session.is_null());
        // SAFETY: We just checked that session is not a null pointer, and we checked client_context before.
        // dtls_set_handler also does not do anything to invalidate client_context.
        unsafe {
            dtls_connect(client_context, session);
        }

        let mut buf: [u8; 512] = [0; 512];
        while !client_state.finished {
            let (read_bytes, peer) = client_state
                .socket
                .recv_from(&mut buf)
                .expect("Error reading from socket");
            let session = session_from_socketaddr(&peer);
            assert!(!session.is_null());
            // SAFETY: client_context has already been checked and is not invalidated by any called methods up to this point.
            // We just checked that session is not null. msg and msglen are set correctly to our buffer and the length of the read data.
            // dtls_handle_message() does not modify the session, neither do our handlers, therefore the call to dtls_free_session is valid.
            unsafe {
                dtls_handle_message(client_context, session, buf.as_mut_ptr(), read_bytes as c_int);
                dtls_free_session(session);
            }
        }
        // SAFETY: We have not called anything that would invalidate our context up to this point, so
        // this pointer should be valid up until here.
        unsafe {
            dtls_free_context(client_context);
        }
        server_thread.join().unwrap();
    }
}
