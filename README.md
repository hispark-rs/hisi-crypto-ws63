# hisi-crypto-ws63

Fallible WS63 hardware/ROM backend for the chip-neutral `hisi-crypto`
capability traits.

The current surface contains explicitly owned hardware capabilities:

- `Ws63Crypto::new` consumes the HAL `Km`, `Spacc`, and `Trng` peripheral tokens.
- PBKDF2-HMAC-SHA1 drives the PAC-modeled RKP engine directly with bounded lock
  and completion polling, key/salt/output-window clearing, and no dependency on
  a vendor security archive or global UAPI symbol.
- SHA-1/SHA-256 and HMAC-SHA1/HMAC-SHA256 drive the PAC-modeled SPACC hash
  channel with bounded lock/clear/completion polling, aligned DMA descriptors,
  explicit D-cache maintenance, and secret-buffer clearing.
- raw entropy uses the same uniquely owned TRNG FIFO.

AES/CMAC and PKE acceleration are not exposed yet. Callers must choose software
and hardware capabilities explicitly; this crate never falls back to software
after a hardware failure.

`Ws63Crypto` is intentionally not `Sync`. Operations are synchronous and must
be serialized with a bounded scheduler primitive outside IRQ, critical-section,
and scheduler-lock contexts. `RkpPollLimits` and `SpaccPollLimits` make hardware
waits explicit; timeouts are returned to the caller and never trigger a software
fallback.

## Source provenance

The register behavior and sequencing were checked against the Apache-2.0
HiSilicon WS63 `security_unified` driver sources. This Rust implementation is a
modified, independently structured `no_std` implementation with typed resource
ownership, bounded failures, PAC access, and Rust crypto capability traits. See
`NOTICE` for attribution.
