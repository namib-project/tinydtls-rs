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

use libc::{sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t};

#[cfg(target_family = "windows")]
include!(concat!(env!("OUT_DIR"), "\\bindings.rs"));
#[cfg(not(target_family = "windows"))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
