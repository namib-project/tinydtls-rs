# tinydtls-sys

Raw bindings to the [tinydtls C library](https://github.com/eclipse/tinydtls).

## Features
These features affect the way that the binding is built:
- `vendored` (default): Build and use a vendored version of tinydtls instead of linking to an existing one.
- `static` (default): Use static linking instead of dynamic linking

These features affect the functionality of the library (only apply if `vendored` is enabled, we can't control features 
of binaries that are already built):
- `ecc` (default): Enable ECC functionality
- `psk` (default): Enable PSK functionality

## License

Matching the license of the tinydtls C library, this library is made available both under
the terms of the Eclipse Public License v1.0 and 3-Clause BSD License (which the
Eclipse Distribution License v1.0 that is used for tinydtls is based on).

Additionally, the tinydtls C library contains third party code that might be included
in compiled binaries that link to tinydtls.
For information on third-party code and its licenses, see
https://github.com/eclipse/tinydtls/blob/develop/ABOUT.md.

See https://github.com/eclipse/tinydtls/blob/develop/LICENSE for more information on the 
tinydtls licensing terms and https://www.eclipse.org/legal/eplfaq.php for more information 
on the EPL 1.0.

Note: This binding is neither supported nor endorsed by the Eclipse Foundation.
