# hisi-crypto-ws63

Fallible WS63 hardware/ROM backend for the chip-neutral `hisi-crypto`
capability traits.

The current surface contains explicitly owned hardware capabilities:

- `Ws63Crypto::new` consumes `Ws63CryptoResources`, which binds the HAL `Km`,
  `Spacc`, and `Trng` peripheral tokens to caller-owned static
  `Ws63CryptoStorage`.
- PBKDF2-HMAC-SHA1 drives the PAC-modeled RKP engine directly with bounded lock
  and completion polling, key/salt/output-window clearing, and no dependency on
  a vendor security archive or global UAPI symbol.
- SHA-1/SHA-256 and HMAC-SHA1/HMAC-SHA256 drive the PAC-modeled SPACC hash
  channel with bounded lock/clear/completion polling, aligned DMA descriptors,
  explicit D-cache maintenance, and secret-buffer clearing.
- AES-128/192/256 single-block encryption and decryption drive a SPACC
  symmetric channel with a KM/KLAD-managed key slot. Higher-level protocols
  such as AES-CMAC and RFC 3394 key unwrap remain in their protocol owner and
  consume the narrow `TryBlockCipher` capability.
- `Ws63P256` separately consumes the HAL `Pke` token and exposes bounded,
  fallible NIST P-256 affine point multiplication/addition and fixed-prime
  field multiplication/squaring. Field inputs use canonical typed elements;
  the backend reproduces the vendor RSA microcode's Montgomery `R^2` setup
  explicitly rather than exposing generic bignum arithmetic. It borrows entropy
  only for an explicit session and never falls back to software after a PKE
  failure. Doubling is mapped to the verified scalar-multiplication sequence;
  inverse affine inputs return the explicit infinity result.
- raw entropy uses the same uniquely owned TRNG FIFO.

Remaining Dragonfly exponentiation/inversion/Legendre arithmetic, point
inversion, curve checks, and `y^2` composition still use an explicit software
capability in the current mixed profile. Point and fixed-prime multiply/square
support must not be described as complete SAE or Dragonfly hardware
acceleration.
Callers must choose software, hardware, or accurately named mixed capabilities
explicitly; this crate never falls back to software after a hardware failure.

`Ws63Crypto` is intentionally not `Sync`. Operations are synchronous and must
be serialized with a bounded scheduler primitive outside IRQ, critical-section,
and scheduler-lock contexts. `RkpPollLimits`, `SpaccPollLimits`, and
`SpaccCipherPollLimits` make hardware waits explicit; timeouts are returned to
the caller and never trigger a software fallback. PKE ownership is kept in the
separate `Ws63P256` capability so `Ws63CryptoResources` does not grow into an
all-hardware constructor.

## Source provenance

The register behavior and sequencing were checked against the Apache-2.0
HiSilicon WS63 `security_unified` driver sources. This Rust implementation is a
modified, independently structured `no_std` implementation with typed resource
ownership, bounded failures, PAC access, and Rust crypto capability traits. See
`NOTICE` for attribution.
