# Changelog

## [Unreleased]

## [0.1.0-alpha.5] - 2026-08-20

### Changed

- Update the exact `hisi-hal` dependency to `0.7.0-alpha.9`, keeping the WS63
  crypto backend on the same peripheral-token release as the radio
  composition without changing algorithm behavior.

## [0.1.0-alpha.4] - 2026-08-13

### Added

- Add algorithm-typed PAC-driven SPACC SM3 and HMAC-SM3 paths using the
  vendor-audited selector, mode, initial state, bounded polling, and existing
  caller-owned DMA storage. Both paths pass the public known-answer vectors in
  the parent repository's `tests-hil` suite on real WS63 silicon.
- Add bounded algorithm-typed AES-128-CMAC over the existing SPACC/KM block
  cipher capability, including fragmented input handling, RFC 4493 subkeys,
  secret intermediate clearing, and fail-closed hardware error propagation.
  All four RFC 4493 message-length vectors pass on real WS63 silicon.
- Bind the existing fallible PKE point-multiply session to the chip-neutral
  typed P-256 public-key and ECDH contract without adding a second driver or
  treating raw TRNG output as a CSPRNG.

## [0.1.0-alpha.3] - 2026-07-20

### Fixed

- Updated the ROM facade to `hisi-rom-sys 0.1.0-alpha.4`, making the public
  WS63 PKE security entry-point metadata available in standalone crates.io
  builds instead of relying on the parent workspace patch.

## [0.1.0-alpha.2] - 2026-07-17

### Added

- PAC-driven SPACC SHA-1/SHA-256 and HMAC-SHA1/HMAC-SHA256 with bounded polling,
  cache maintenance, explicit errors, and no implicit fallback.
- PAC-driven SPACC AES-128/192/256 block encryption/decryption using a locked
  KM/KLAD MCipher keyslot, bounded waits, cache maintenance, and fail-closed
  cleanup. NIST vectors and repeated WPA2 silicon HIL cover the path.
- PKE-backed fixed P-256 point multiplication, point addition, field
  multiplication, exponentiation, and composed group operations for SAE.
- Explicitly injected static SPACC descriptor storage so firmware RAM cost and
  ownership remain visible at construction.

### Changed

- Raise the declared MSRV to Rust 1.88 to match `hisi-hal` 0.7.x.

## [0.1.0-alpha.1] - 2026-07-13

### Added

- Explicit exclusive WS63 PBKDF2 and entropy backend.
- Host validation for iteration bounds and zero-length entropy.
