# hisi-crypto-ws63

Fallible WS63 hardware/ROM backend for the chip-neutral `hisi-crypto`
capability traits.

The initial surface contains two separately owned capabilities:

- PBKDF2-HMAC-SHA1 through `uapi_drv_cipher_pbkdf2`. This legacy capability
  requires the vendor unified-cipher service to be initialized by the caller.
- raw entropy through `Ws63Entropy`, which consumes the HAL `Trng` peripheral
  token and reads the physical TRNG FIFO. It does not use the legacy global
  UAPI symbol.

SHA/HMAC/AES acceleration is not exposed yet because the transitional runtime
observed hardware calculation timeouts. Callers must choose software and
hardware capabilities explicitly; this crate never falls back to software after
a hardware failure.

`Ws63Crypto::assume_exclusive` remains unsafe for the PBKDF2 service until a
consumable cipher-engine token exists. `Ws63Entropy::new` is safe because it
consumes the HAL TRNG token. Operations are synchronous and must not be called
while holding a critical section.
