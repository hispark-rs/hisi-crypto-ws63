#![no_std]
#![doc = include_str!("../README.md")]

use core::{cell::Cell, num::NonZeroU32};

#[cfg(any(feature = "cipher", feature = "hash"))]
use core::cell::UnsafeCell;

use hisi_crypto::CryptoError;
#[cfg(feature = "hal-trng")]
use hisi_crypto::EntropySource;
#[cfg(feature = "pbkdf2")]
use hisi_crypto::Pbkdf2HmacSha1;
use hisi_hal::{
    peripherals::{Km, Spacc, Trng},
    trng::TrngDriver,
};
#[cfg(all(target_arch = "riscv32", feature = "pbkdf2"))]
use zeroize::Zeroize;

#[cfg(all(target_arch = "riscv32", any(feature = "cipher", feature = "pbkdf2")))]
use ws63_pac::km::RegisterBlock;

#[cfg(feature = "hash")]
mod spacc_hash;
#[cfg(feature = "hash")]
use spacc_hash::HashDmaStorage;
#[cfg(feature = "hash")]
pub use spacc_hash::{MAX_HASH_INPUT_BYTES, SpaccPollLimits};
#[cfg(feature = "p256")]
mod pke_p256;
#[cfg(feature = "p256")]
pub use pke_p256::{Ws63P256, Ws63P256Session};
#[cfg(feature = "cipher")]
mod spacc_cipher;
#[cfg(feature = "cipher")]
use spacc_cipher::CipherDmaStorage;
#[cfg(feature = "cipher")]
pub use spacc_cipher::SpaccCipherPollLimits;

const DEFAULT_POLL_LIMIT: u32 = 1_000_000;
#[cfg(all(feature = "pbkdf2", any(target_arch = "riscv32", test)))]
const PASSWORD_BLOCK_BYTES: usize = 128;
#[cfg(feature = "pbkdf2")]
const SHA1_BLOCK_BYTES: usize = 64;
#[cfg(all(feature = "pbkdf2", any(target_arch = "riscv32", test)))]
const SHA1_OUTPUT_BYTES: usize = 20;
#[cfg(all(feature = "pbkdf2", any(target_arch = "riscv32", test)))]
const SHA1_INITIAL_STATE: [u8; SHA1_OUTPUT_BYTES] = [
    0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
    0xc3, 0xd2, 0xe1, 0xf0,
];

const ERR_BUSY: u32 = 0xffff_1101;
#[cfg(all(feature = "pbkdf2", target_arch = "riscv32"))]
const ERR_LOCK_TIMEOUT: u32 = 0xffff_1102;
#[cfg(all(feature = "pbkdf2", target_arch = "riscv32"))]
const ERR_OPERATION_TIMEOUT: u32 = 0xffff_1103;
#[cfg(feature = "hal-trng")]
const ERR_TRNG: u32 = 0xffff_1104;

/// Bounded polling contract for the WS63 RKP engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RkpPollLimits {
    lock: NonZeroU32,
    operation: NonZeroU32,
}

/// Caller-owned static DMA storage for the WS63 SPACC capabilities.
///
/// SPACC consumes physical SRAM addresses after the initiating Rust call has
/// entered the hardware. Keeping this storage outside [`Ws63Crypto`] makes its
/// RAM cost visible to the firmware and prevents a backend value from silently
/// growing its `.bss` footprint as capabilities are added. Initialize it in a
/// `StaticCell` (or equivalent one-time static owner) and move the resulting
/// mutable reference into [`Ws63CryptoResources`].
#[repr(align(32))]
pub struct Ws63CryptoStorage {
    #[cfg(feature = "hash")]
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    hash: UnsafeCell<HashDmaStorage>,
    #[cfg(feature = "cipher")]
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    cipher: UnsafeCell<CipherDmaStorage>,
}

impl Ws63CryptoStorage {
    /// Create zeroed storage suitable for one WS63 crypto backend.
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "hash")]
            hash: UnsafeCell::new(HashDmaStorage::new()),
            #[cfg(feature = "cipher")]
            cipher: UnsafeCell::new(CipherDmaStorage::new()),
        }
    }

    /// Static SRAM reserved by the selected hash/cipher feature set.
    pub const fn size_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    /// Required alignment of the caller-provided storage.
    pub const fn align_bytes() -> usize {
        core::mem::align_of::<Self>()
    }
}

impl Default for Ws63CryptoStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Explicit hardware resources used by [`Ws63Crypto`].
///
/// PKE remains a separate [`Ws63P256`] capability. This bundle is intentionally
/// limited to the engines shared by PBKDF2, SPACC hash/cipher, and entropy so
/// adding another algorithm does not add another positional constructor
/// argument.
pub struct Ws63CryptoResources<'d> {
    km: Km<'d>,
    spacc: Spacc<'d>,
    trng: Trng<'d>,
    storage: &'static mut Ws63CryptoStorage,
}

impl<'d> Ws63CryptoResources<'d> {
    /// Bind the unique HAL tokens to caller-owned static DMA storage.
    pub fn new(
        km: Km<'d>,
        spacc: Spacc<'d>,
        trng: Trng<'d>,
        storage: &'static mut Ws63CryptoStorage,
    ) -> Self {
        Self {
            km,
            spacc,
            trng,
            storage,
        }
    }
}

impl RkpPollLimits {
    /// Construct explicit non-zero lock and operation poll limits.
    pub const fn new(lock: NonZeroU32, operation: NonZeroU32) -> Self {
        Self { lock, operation }
    }

    /// Maximum attempts used to acquire the RKP hardware lock.
    pub const fn lock(self) -> NonZeroU32 {
        self.lock
    }

    /// Maximum status reads used to await one PBKDF2 output block.
    pub const fn operation(self) -> NonZeroU32 {
        self.operation
    }
}

impl Default for RkpPollLimits {
    fn default() -> Self {
        let Some(limit) = NonZeroU32::new(DEFAULT_POLL_LIMIT) else {
            unreachable!()
        };
        Self::new(limit, limit)
    }
}

/// Exclusive WS63 KM/RKP and TRNG crypto capability.
///
/// Safe construction consumes the KM, SPACC, and TRNG HAL peripheral tokens. The value is not
/// `Sync`; callers that publish it to multiple runtime tasks must serialize
/// operations outside critical sections with a bounded scheduler primitive.
pub struct Ws63Crypto<'d> {
    _km: Km<'d>,
    _spacc: Spacc<'d>,
    #[cfg_attr(not(any(feature = "hal-trng", feature = "pbkdf2")), allow(dead_code))]
    trng: TrngDriver<'d>,
    #[cfg_attr(
        any(not(target_arch = "riscv32"), not(feature = "pbkdf2")),
        allow(dead_code)
    )]
    limits: RkpPollLimits,
    #[cfg(feature = "hash")]
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    spacc_limits: SpaccPollLimits,
    #[cfg(feature = "cipher")]
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    cipher_limits: SpaccCipherPollLimits,
    #[cfg_attr(
        any(
            not(target_arch = "riscv32"),
            all(not(feature = "hash"), not(feature = "cipher"))
        ),
        allow(dead_code)
    )]
    storage: &'static Ws63CryptoStorage,
    #[cfg_attr(
        not(any(
            feature = "cipher",
            feature = "hal-trng",
            feature = "hash",
            feature = "pbkdf2"
        )),
        allow(dead_code)
    )]
    busy: Cell<bool>,
}

impl<'d> Ws63Crypto<'d> {
    /// Claim the explicit WS63 resources with conservative poll limits.
    pub fn new(resources: Ws63CryptoResources<'d>) -> Self {
        Self::with_poll_limits(
            resources,
            RkpPollLimits::default(),
            #[cfg(feature = "hash")]
            SpaccPollLimits::default(),
            #[cfg(feature = "cipher")]
            SpaccCipherPollLimits::default(),
        )
    }

    /// Claim the hardware with an explicit bounded polling contract.
    pub fn with_poll_limits(
        resources: Ws63CryptoResources<'d>,
        limits: RkpPollLimits,
        #[cfg(feature = "hash")] spacc_limits: SpaccPollLimits,
        #[cfg(feature = "cipher")] cipher_limits: SpaccCipherPollLimits,
    ) -> Self {
        let Ws63CryptoResources {
            km,
            spacc,
            trng,
            storage,
        } = resources;
        Self {
            _km: km,
            _spacc: spacc,
            trng: TrngDriver::new(trng),
            limits,
            #[cfg(feature = "hash")]
            spacc_limits,
            #[cfg(feature = "cipher")]
            cipher_limits,
            storage,
            busy: Cell::new(false),
        }
    }

    #[cfg_attr(
        not(any(
            feature = "cipher",
            feature = "hal-trng",
            feature = "hash",
            feature = "pbkdf2"
        )),
        allow(dead_code)
    )]
    fn enter(&self) -> Result<BusyGuard<'_>, CryptoError> {
        if self.busy.replace(true) {
            Err(CryptoError::Backend(ERR_BUSY))
        } else {
            Ok(BusyGuard { busy: &self.busy })
        }
    }

    #[cfg(all(target_arch = "riscv32", any(feature = "cipher", feature = "pbkdf2")))]
    fn regs(&self) -> &'static RegisterBlock {
        // SAFETY: `self._km` owns the unique HAL token for this static MMIO block.
        unsafe { &*Km::ptr() }
    }

    #[cfg(all(target_arch = "riscv32", feature = "pbkdf2"))]
    fn derive_hardware(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u16,
        output: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let regs = self.regs();
        self.lock_rkp(regs)?;

        let mut password_block = [0u8; PASSWORD_BLOCK_BYTES];
        password_block[..password.len()].copy_from_slice(password);
        let result = (|| {
            self.write_password(regs, &password_block)?;
            let mut derived = [0u8; SHA1_OUTPUT_BYTES];
            for block_index in 1..=2 {
                let mut salt_block = prepare_sha1_salt_block(salt, block_index);
                let block_result =
                    self.calculate_block(regs, &salt_block, iterations, &mut derived);
                salt_block.zeroize();
                block_result?;
                let offset = (block_index - 1) * SHA1_OUTPUT_BYTES;
                let count = core::cmp::min(SHA1_OUTPUT_BYTES, output.len() - offset);
                output[offset..offset + count].copy_from_slice(&derived[..count]);
                derived.zeroize();
            }
            Ok(())
        })();

        password_block.zeroize();
        self.clear_sensitive_registers(regs);
        self.unlock_rkp(regs);
        result
    }

    #[cfg(all(target_arch = "riscv32", feature = "pbkdf2"))]
    fn lock_rkp(&self, regs: &RegisterBlock) -> Result<(), CryptoError> {
        for _ in 0..self.limits.lock().get() {
            // SAFETY: 1 is the SVD-modeled three-bit REE lock-owner value.
            regs.rkp_lock()
                .write(|w| unsafe { w.km_lock_status().bits(1) });
            io_fence();
            if regs.rkp_lock().read().km_lock_status().bits() == 1 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_LOCK_TIMEOUT))
    }

    #[cfg(all(target_arch = "riscv32", feature = "pbkdf2"))]
    fn unlock_rkp(&self, regs: &RegisterBlock) {
        // SAFETY: 0 is the SVD-modeled three-bit idle/unlocked value.
        regs.rkp_lock()
            .write(|w| unsafe { w.km_lock_status().bits(0) });
        io_fence();
    }

    #[cfg(all(target_arch = "riscv32", feature = "pbkdf2"))]
    fn write_password(
        &self,
        regs: &RegisterBlock,
        password: &[u8; PASSWORD_BLOCK_BYTES],
    ) -> Result<(), CryptoError> {
        let start = self
            .trng
            .read_blocking()
            .map_err(|_| CryptoError::Backend(ERR_TRNG))? as usize
            % regs.rkp_pbkdf2_key_iter().count();
        for offset in 0..32 {
            let index = (start + offset) % 32;
            let word = word_at(password, index);
            // SAFETY: `data` is the complete SVD-modeled 32-bit write-only word.
            regs.rkp_pbkdf2_key(index)
                .write(|w| unsafe { w.data().bits(word) });
            io_fence();
        }
        Ok(())
    }

    #[cfg(all(target_arch = "riscv32", feature = "pbkdf2"))]
    fn calculate_block(
        &self,
        regs: &RegisterBlock,
        salt: &[u8; PASSWORD_BLOCK_BYTES],
        iterations: u16,
        output: &mut [u8; SHA1_OUTPUT_BYTES],
    ) -> Result<(), CryptoError> {
        let start = self
            .trng
            .read_blocking()
            .map_err(|_| CryptoError::Backend(ERR_TRNG))? as usize
            % 32;
        for offset in 0..32 {
            let index = (start + offset) % 32;
            // SAFETY: `data` is the complete SVD-modeled 32-bit write-only word.
            regs.rkp_pbkdf2_data(index)
                .write(|w| unsafe { w.data().bits(word_at(salt, index)) });
            io_fence();
        }
        let (state_words, remainder) = SHA1_INITIAL_STATE.as_chunks::<4>();
        debug_assert!(remainder.is_empty());
        for (index, chunk) in state_words.iter().enumerate() {
            let word = u32::from_le_bytes(*chunk);
            // SAFETY: `data` is the complete SVD-modeled 32-bit state word.
            regs.rkp_pbkdf2_val(index)
                .write(|w| unsafe { w.data().bits(word) });
            io_fence();
        }
        // SAFETY: every value is within its SVD field width: u16 iterations,
        // software key source 3, SHA-1 selector 1, and one start bit.
        regs.rkp_cmd_cfg().write(|w| unsafe {
            w.rkp_pbkdf_calc_time()
                .bits(iterations)
                .pbkdf2_key_sel_cfg()
                .bits(3)
                .pbkdf2_alg_sel_cfg()
                .bits(1)
                .sw_calc_req()
                .set_bit()
        });
        io_fence();

        let mut completed = false;
        for _ in 0..self.limits.operation().get() {
            if regs.rkp_cmd_cfg().read().sw_calc_req().bit_is_clear() {
                completed = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !completed {
            return Err(CryptoError::Backend(ERR_OPERATION_TIMEOUT));
        }
        regs.rkp_raw_int()
            .write(|w| w.rkp_raw_int().clear_bit_by_one());
        io_fence();
        let error = regs.kdf_error().read().error().bits();
        if error != 0 {
            return Err(CryptoError::Backend(error));
        }

        let start = self
            .trng
            .read_blocking()
            .map_err(|_| CryptoError::Backend(ERR_TRNG))? as usize
            % (SHA1_OUTPUT_BYTES / 4);
        for offset in 0..(SHA1_OUTPUT_BYTES / 4) {
            let index = (start + offset) % (SHA1_OUTPUT_BYTES / 4);
            let bytes = regs
                .rkp_pbkdf2_val(index)
                .read()
                .data()
                .bits()
                .to_le_bytes();
            output[index * 4..index * 4 + 4].copy_from_slice(&bytes);
        }
        Ok(())
    }

    #[cfg(all(target_arch = "riscv32", feature = "pbkdf2"))]
    fn clear_sensitive_registers(&self, regs: &RegisterBlock) {
        for register in regs.rkp_pbkdf2_data_iter() {
            // SAFETY: zero fills the complete SVD-modeled 32-bit salt word.
            register.write(|w| unsafe { w.data().bits(0) });
        }
        for register in regs.rkp_pbkdf2_key_iter() {
            // SAFETY: zero fills the complete SVD-modeled 32-bit password word.
            register.write(|w| unsafe { w.data().bits(0) });
        }
        for register in regs.rkp_pbkdf2_val_iter() {
            // SAFETY: zero fills the complete SVD-modeled 32-bit result word.
            register.write(|w| unsafe { w.data().bits(0) });
        }
        io_fence();
    }
}

#[cfg_attr(
    not(any(
        feature = "cipher",
        feature = "hal-trng",
        feature = "hash",
        feature = "pbkdf2"
    )),
    allow(dead_code)
)]
struct BusyGuard<'a> {
    busy: &'a Cell<bool>,
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.busy.set(false);
    }
}

#[cfg(feature = "pbkdf2")]
impl Pbkdf2HmacSha1 for Ws63Crypto<'_> {
    fn derive_32(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        if password.len() > SHA1_BLOCK_BYTES
            || salt.len() > SHA1_BLOCK_BYTES - 13
            || iterations == 0
            || iterations > u32::from(u16::MAX)
        {
            return Err(CryptoError::InvalidLength);
        }
        let _busy = self.enter()?;
        #[cfg(target_arch = "riscv32")]
        {
            self.derive_hardware(password, salt, iterations as u16, output)
        }
        #[cfg(not(target_arch = "riscv32"))]
        {
            let _ = (password, salt, iterations, output);
            Err(CryptoError::Unsupported)
        }
    }
}

#[cfg(feature = "hal-trng")]
impl EntropySource for Ws63Crypto<'_> {
    fn fill_entropy(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        let _busy = self.enter()?;
        self.trng
            .fill_bytes(output)
            .map_err(|_| CryptoError::Backend(ERR_TRNG))
    }
}

#[cfg(all(feature = "pbkdf2", any(target_arch = "riscv32", test)))]
fn prepare_sha1_salt_block(salt: &[u8], block_index: usize) -> [u8; PASSWORD_BLOCK_BYTES] {
    let mut padded = [0u8; PASSWORD_BLOCK_BYTES];
    padded[..salt.len()].copy_from_slice(salt);
    let index = u32::try_from(block_index).unwrap().to_be_bytes();
    padded[salt.len()..salt.len() + 4].copy_from_slice(&index);
    padded[salt.len() + 4] = 0x80;
    let bit_length = ((SHA1_BLOCK_BYTES + salt.len() + 4) * 8) as u64;
    padded[SHA1_BLOCK_BYTES - 8..SHA1_BLOCK_BYTES].copy_from_slice(&bit_length.to_be_bytes());
    padded
}

#[cfg(all(feature = "pbkdf2", any(target_arch = "riscv32", test)))]
fn word_at(bytes: &[u8; PASSWORD_BLOCK_BYTES], index: usize) -> u32 {
    u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
}

#[cfg(all(target_arch = "riscv32", feature = "pbkdf2"))]
#[inline]
fn io_fence() {
    // SAFETY: this emits only an ordering barrier for prior/following MMIO.
    unsafe { core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_limits_are_explicitly_nonzero() {
        let limits = RkpPollLimits::default();
        assert_eq!(limits.lock().get(), DEFAULT_POLL_LIMIT);
        assert_eq!(limits.operation().get(), DEFAULT_POLL_LIMIT);
    }

    #[cfg(feature = "pbkdf2")]
    #[test]
    fn sha1_salt_padding_matches_vendor_oracle() {
        let block = prepare_sha1_salt_block(b"IEEE", 1);
        assert_eq!(&block[..8], b"IEEE\0\0\0\x01");
        assert_eq!(block[8], 0x80);
        assert!(block[9..56].iter().all(|byte| *byte == 0));
        assert_eq!(&block[56..64], &((64 + 4 + 4) * 8u64).to_be_bytes());
        assert!(block[64..].iter().all(|byte| *byte == 0));
    }

    #[cfg(feature = "pbkdf2")]
    #[test]
    fn word_encoding_matches_vendor_little_endian_mmio_copy() {
        let mut bytes = [0u8; PASSWORD_BLOCK_BYTES];
        bytes[..4].copy_from_slice(&SHA1_INITIAL_STATE[..4]);
        assert_eq!(word_at(&bytes, 0), 0x0123_4567);
    }

    #[cfg(all(feature = "hash", feature = "cipher"))]
    #[test]
    fn caller_owned_storage_has_audited_dma_layout() {
        assert_eq!(Ws63CryptoStorage::align_bytes(), 32);
        assert_eq!(Ws63CryptoStorage::size_bytes(), 4_384);
    }
}
