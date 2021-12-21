// Bindgen translates the C headers, clippy's and rustfmt's recommendations are not applicable here.
#![allow(clippy::all)]
#![allow(non_camel_case_types)]

use libc::{sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
