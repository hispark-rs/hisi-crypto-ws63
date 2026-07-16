# hisi-crypto-ws63

Fallible WS63 hardware/ROM backend for the chip-neutral `hisi-crypto`
capability traits.

The initial surface contains one explicitly owned hardware capability:

- `Ws63Crypto::new` consumes the HAL `Km` and `Trng` peripheral tokens.
- PBKDF2-HMAC-SHA1 drives the PAC-modeled RKP engine directly with bounded lock
  and completion polling, key/salt/output-window clearing, and no dependency on
  a vendor security archive or global UAPI symbol.
- raw entropy uses the same uniquely owned TRNG FIFO.

SHA/HMAC/AES acceleration is not exposed yet because the transitional runtime
observed hardware calculation timeouts. Callers must choose software and
hardware capabilities explicitly; this crate never falls back to software after
a hardware failure.

`Ws63Crypto` is intentionally not `Sync`. Operations are synchronous and must
be serialized with a bounded scheduler primitive outside IRQ, critical-section,
and scheduler-lock contexts. `RkpPollLimits` makes both hardware waits explicit;
timeouts are returned to the caller and never trigger a software fallback.
