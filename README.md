# hisi-crypto-ws63

Fallible WS63 hardware/ROM backend for the chip-neutral `hisi-crypto`
capability traits.

The initial surface contains only two capabilities already proven in the WS63
connectivity HIL:

- PBKDF2-HMAC-SHA1 through `uapi_drv_cipher_pbkdf2`.
- raw entropy through `uapi_drv_cipher_trng_get_random_bytes`.

SHA/HMAC/AES acceleration is not exposed yet because the transitional runtime
observed hardware calculation timeouts. Callers must choose software and
hardware capabilities explicitly; this crate never falls back to software after
a hardware failure.

`Ws63Crypto::assume_exclusive` is unsafe until the HAL exposes consumable cipher
and TRNG resource tokens. Operations are synchronous, bounded by the vendor
UAPI, and must not be called while holding a critical section.

