#![cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]

use core::num::NonZeroU32;

use hisi_crypto::{CryptoError, TryHash, TryMac};
use zeroize::Zeroize;

use crate::Ws63Crypto;

#[cfg(target_arch = "riscv32")]
use ws63_pac::spacc::RegisterBlock;

/// Largest caller-supplied message accepted by the one-shot SPACC contract.
pub const MAX_HASH_INPUT_BYTES: usize = 4096;

const HASH_BLOCK_BYTES: usize = 64;
const HASH_LENGTH_BYTES: usize = 8;
const HASH_DMA_BYTES: usize = MAX_HASH_INPUT_BYTES + 2 * HASH_BLOCK_BYTES;
const HASH_CHANNEL_INDEX: usize = 0;
const HASH_CHANNEL_NUMBER: u32 = 1;
const HASH_CHANNEL_MASK: u32 = 1 << HASH_CHANNEL_NUMBER;
const HASH_CHANNEL_OWNER_SHIFT: u32 = HASH_CHANNEL_NUMBER * 4;
const HASH_CHANNEL_OWNER_MASK: u32 = 0xf << HASH_CHANNEL_OWNER_SHIFT;
const HASH_CHANNEL_OWNER_REE: u32 = 1;
const HASH_RING_DEPTH: u8 = 2;
const DEFAULT_SPACC_POLL_LIMIT: u32 = 1_000_000;

const ERR_SPACC_LOCK_TIMEOUT: u32 = 0xffff_1201;
const ERR_SPACC_CLEAR_TIMEOUT: u32 = 0xffff_1202;
const ERR_SPACC_OPERATION_TIMEOUT: u32 = 0xffff_1203;
const ERR_SPACC_BUS: u32 = 0xffff_1204;
const ERR_SPACC_CONTROL: u32 = 0xffff_1205;
const ERR_SPACC_ADDRESS: u32 = 0xffff_1206;

const SHA1_INITIAL_STATE: [u8; 20] = [
    0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
    0xc3, 0xd2, 0xe1, 0xf0,
];
const SHA256_INITIAL_STATE: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
];

/// Bounded polling contract for one WS63 SPACC hash operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpaccPollLimits {
    lock: NonZeroU32,
    clear: NonZeroU32,
    operation: NonZeroU32,
}

impl SpaccPollLimits {
    /// Construct explicit non-zero channel-lock, clear, and operation limits.
    pub const fn new(lock: NonZeroU32, clear: NonZeroU32, operation: NonZeroU32) -> Self {
        Self {
            lock,
            clear,
            operation,
        }
    }

    /// Maximum attempts used to acquire hash channel 1.
    pub const fn lock(self) -> NonZeroU32 {
        self.lock
    }

    /// Maximum status reads used to clear hash channel 1.
    pub const fn clear(self) -> NonZeroU32 {
        self.clear
    }

    /// Maximum completion-status reads used by one hash operation.
    pub const fn operation(self) -> NonZeroU32 {
        self.operation
    }
}

impl Default for SpaccPollLimits {
    fn default() -> Self {
        let Some(limit) = NonZeroU32::new(DEFAULT_SPACC_POLL_LIMIT) else {
            unreachable!()
        };
        Self::new(limit, limit, limit)
    }
}

#[derive(Clone, Copy)]
enum HashAlgorithm {
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    const fn algorithm_select(self) -> u8 {
        match self {
            Self::Sha1 => 0x0a,
            Self::Sha256 => 0x0b,
        }
    }

    const fn algorithm_mode(self) -> u8 {
        match self {
            Self::Sha1 => 0,
            Self::Sha256 => 1,
        }
    }

    const fn initial_state(self) -> &'static [u8] {
        match self {
            Self::Sha1 => &SHA1_INITIAL_STATE,
            Self::Sha256 => &SHA256_INITIAL_STATE,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HashNode {
    flags: u32,
    length: u32,
    address_low: u32,
    address_high: u32,
}

impl HashNode {
    const EMPTY: Self = Self {
        flags: 0,
        length: 0,
        address_low: 0,
        address_high: 0,
    };
}

#[repr(C, align(32))]
pub(crate) struct HashDmaStorage {
    nodes: [HashNode; HASH_RING_DEPTH as usize],
    bytes: [u8; HASH_DMA_BYTES],
}

impl HashDmaStorage {
    pub(crate) const fn new() -> Self {
        Self {
            nodes: [HashNode::EMPTY; HASH_RING_DEPTH as usize],
            bytes: [0; HASH_DMA_BYTES],
        }
    }

    fn clear(&mut self) {
        self.bytes.zeroize();
        self.nodes.fill(HashNode::EMPTY);
    }
}

impl Ws63Crypto<'_> {
    #[cfg(target_arch = "riscv32")]
    fn spacc_regs(&self) -> &'static RegisterBlock {
        // SAFETY: `self._spacc` owns the unique HAL token for this MMIO block.
        unsafe { &*hisi_hal::peripherals::Spacc::ptr() }
    }

    fn spacc_hmac(
        &self,
        algorithm: HashAlgorithm,
        key: &[u8],
        parts: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let input_len = checked_parts_len(parts)?;
        if input_len > MAX_HASH_INPUT_BYTES || key.len() > MAX_HASH_INPUT_BYTES {
            return Err(CryptoError::InvalidLength);
        }

        let mut key_block = [0u8; HASH_BLOCK_BYTES];
        if key.len() > HASH_BLOCK_BYTES {
            let mut digest = [0u8; 32];
            self.spacc_hash(
                algorithm,
                None,
                &[key],
                &mut digest[..algorithm.output_len()],
            )?;
            key_block[..algorithm.output_len()].copy_from_slice(&digest[..algorithm.output_len()]);
            digest.zeroize();
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut inner_pad = key_block;
        let mut outer_pad = key_block;
        for byte in &mut inner_pad {
            *byte ^= 0x36;
        }
        for byte in &mut outer_pad {
            *byte ^= 0x5c;
        }

        let mut inner = [0u8; 32];
        let result = (|| {
            self.spacc_hash(
                algorithm,
                Some(&inner_pad),
                parts,
                &mut inner[..algorithm.output_len()],
            )?;
            self.spacc_hash(
                algorithm,
                Some(&outer_pad),
                &[&inner[..algorithm.output_len()]],
                output,
            )
        })();
        key_block.zeroize();
        inner_pad.zeroize();
        outer_pad.zeroize();
        inner.zeroize();
        result
    }

    #[cfg(target_arch = "riscv32")]
    fn spacc_hash(
        &self,
        algorithm: HashAlgorithm,
        prefix: Option<&[u8]>,
        parts: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        if output.len() != algorithm.output_len() {
            return Err(CryptoError::InvalidLength);
        }

        let regs = self.spacc_regs();
        self.lock_hash_channel(regs)?;
        let result = (|| {
            self.clear_hash_channel(regs)?;
            // SAFETY: every public hash/MAC entry holds `Ws63Crypto::enter` for
            // this operation. `Ws63Crypto` is !Sync and the runtime adds a
            // scheduler mutex before sharing it, so this storage is exclusive.
            let storage = unsafe { &mut *self.hash_storage.get() };
            let padded_len = prepare_padded_message(&mut storage.bytes, prefix, parts)?;
            let node_address = u32::try_from(storage.nodes.as_ptr() as usize)
                .map_err(|_| CryptoError::Backend(ERR_SPACC_ADDRESS))?;
            let data_address = u32::try_from(storage.bytes.as_ptr() as usize)
                .map_err(|_| CryptoError::Backend(ERR_SPACC_ADDRESS))?;

            storage.nodes[0] = HashNode {
                flags: 0b11,
                length: u32::try_from(padded_len).map_err(|_| CryptoError::InvalidLength)?,
                address_low: data_address,
                address_high: 0,
            };
            storage.nodes[1] = HashNode::EMPTY;

            self.configure_hash_channel(regs, algorithm, node_address)?;
            // SAFETY: both ranges are live, 32-byte aligned SRAM owned by this
            // backend. SPACC reads them only after the following cache clean.
            unsafe {
                clean_dcache_range(
                    storage.nodes.as_ptr() as usize,
                    core::mem::size_of_val(&storage.nodes),
                );
                clean_dcache_range(storage.bytes.as_ptr() as usize, padded_len);
            }
            io_fence();

            let current = regs
                .in_hash_chn1_node_wr_point(HASH_CHANNEL_INDEX)
                .read()
                .write_pointer()
                .bits();
            let next = current.wrapping_add(1) % HASH_RING_DEPTH;
            // SAFETY: `next` is reduced modulo the two-entry SVD field.
            regs.in_hash_chn1_node_wr_point(HASH_CHANNEL_INDEX)
                .write(|w| unsafe { w.write_pointer().bits(next) });
            io_fence();

            self.wait_for_hash_completion(regs)?;
            self.read_hash_state(regs, output);
            Ok(())
        })();

        // SAFETY: the storage remains exclusively borrowed by the busy guard.
        let storage = unsafe { &mut *self.hash_storage.get() };
        storage.clear();
        // SAFETY: clear the SRAM copy so a later bus master cannot observe the
        // prior key material after the CPU cache line is eventually evicted.
        unsafe {
            clean_dcache_range(
                storage.nodes.as_ptr() as usize,
                core::mem::size_of_val(&storage.nodes),
            );
            clean_dcache_range(storage.bytes.as_ptr() as usize, storage.bytes.len());
        }
        self.unlock_hash_channel(regs);
        result
    }

    #[cfg(not(target_arch = "riscv32"))]
    fn spacc_hash(
        &self,
        _algorithm: HashAlgorithm,
        _prefix: Option<&[u8]>,
        _parts: &[&[u8]],
        _output: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    #[cfg(target_arch = "riscv32")]
    fn lock_hash_channel(&self, regs: &RegisterBlock) -> Result<(), CryptoError> {
        self.try_lock_hash_channel(regs, self.spacc_limits.lock().get())
    }

    #[cfg(target_arch = "riscv32")]
    fn try_lock_hash_channel(
        &self,
        regs: &RegisterBlock,
        attempts: u32,
    ) -> Result<(), CryptoError> {
        for _ in 0..attempts {
            let acquired = critical_section::with(|_| {
                let used = regs.spacc_hash_chn_lock().read().hash_chn_lock().bits();
                if ((used & HASH_CHANNEL_OWNER_MASK) >> HASH_CHANNEL_OWNER_SHIFT) != 0 {
                    return false;
                }
                let claimed = (used & !HASH_CHANNEL_OWNER_MASK)
                    | (HASH_CHANNEL_OWNER_REE << HASH_CHANNEL_OWNER_SHIFT);
                // SAFETY: the complete lock word preserves every other channel
                // and writes REE owner 1 only to channel 1's four-bit field.
                regs.spacc_hash_chn_lock()
                    .write(|w| unsafe { w.hash_chn_lock().bits(claimed) });
                io_fence();
                let verified = regs.spacc_hash_chn_lock().read().hash_chn_lock().bits();
                ((verified & HASH_CHANNEL_OWNER_MASK) >> HASH_CHANNEL_OWNER_SHIFT)
                    == HASH_CHANNEL_OWNER_REE
            });
            if acquired {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_SPACC_LOCK_TIMEOUT))
    }

    /// Diagnostic-only proof that a busy channel fails closed and is reusable.
    #[cfg(all(target_arch = "riscv32", feature = "diagnostics"))]
    #[doc(hidden)]
    pub fn diagnostic_lock_timeout_recovery(&self) -> Result<(), CryptoError> {
        let regs = self.spacc_regs();
        // A zero-attempt budget deterministically exercises the same
        // fail-closed timeout branch without forging another security domain's
        // owner value in the hardware lock register.
        let timeout = self.try_lock_hash_channel(regs, 0);
        if timeout != Err(CryptoError::Backend(ERR_SPACC_LOCK_TIMEOUT)) {
            return Err(CryptoError::Backend(0xffff_12f1));
        }

        const EXPECTED: [u8; 20] = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        let mut output = [0; 20];
        TryHash::<20>::hash(self, &[b"abc"], &mut output)?;
        if output != EXPECTED {
            return Err(CryptoError::Backend(0xffff_12f2));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    fn unlock_hash_channel(&self, regs: &RegisterBlock) {
        critical_section::with(|_| {
            let used = regs.spacc_hash_chn_lock().read().hash_chn_lock().bits();
            let released = used & !HASH_CHANNEL_OWNER_MASK;
            // SAFETY: the complete lock word preserves every other channel and
            // clears only channel 1's four-bit owner field.
            regs.spacc_hash_chn_lock()
                .write(|w| unsafe { w.hash_chn_lock().bits(released) });
            io_fence();
        });
    }

    #[cfg(target_arch = "riscv32")]
    fn clear_hash_channel(&self, regs: &RegisterBlock) -> Result<(), CryptoError> {
        critical_section::with(|_| {
            let enabled = regs
                .hash_chann_raw_int_en()
                .read()
                .hash_chann_raw_int_en()
                .bits();
            // SAFETY: preserve every other channel and disable only channel 1.
            regs.hash_chann_raw_int_en().write(|w| unsafe {
                w.hash_chann_raw_int_en()
                    .bits(enabled & !(HASH_CHANNEL_MASK as u16))
            });
        });
        // SAFETY: request exactly the SVD-modeled channel-1 clear bit.
        regs.spacc_hash_chn_clear_req()
            .write(|w| unsafe { w.hash_chn_clear_req().bits(HASH_CHANNEL_MASK) });
        io_fence();
        for _ in 0..self.spacc_limits.clear().get() {
            let status = regs
                .spacc_int_raw_hash_clear_finish()
                .read()
                .raw_hash_clear_finish()
                .bits();
            if status & (HASH_CHANNEL_MASK as u16) != 0 {
                // SAFETY: W1C exactly the channel-1 completion bit.
                regs.spacc_int_raw_hash_clear_finish()
                    .write(|w| unsafe { w.raw_hash_clear_finish().bits(HASH_CHANNEL_MASK as u16) });
                io_fence();
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_SPACC_CLEAR_TIMEOUT))
    }

    #[cfg(target_arch = "riscv32")]
    fn configure_hash_channel(
        &self,
        regs: &RegisterBlock,
        algorithm: HashAlgorithm,
        node_address: u32,
    ) -> Result<(), CryptoError> {
        // SAFETY: REE selector 0xA and enabled=1 fit their SVD fields.
        regs.in_hash_chn1_ctrl(HASH_CHANNEL_INDEX)
            .write(|w| unsafe { w.hash_chn_ss().bits(0x0a).hash_chn_en().set_bit() });
        // SAFETY: algorithm selectors are vendor-defined values that fit four bits.
        regs.in_hash_chn1_key_ctrl(HASH_CHANNEL_INDEX)
            .write(|w| unsafe {
                w.hash_chn_alg_sel()
                    .bits(algorithm.algorithm_select())
                    .hash_chn_alg_mode()
                    .bits(algorithm.algorithm_mode())
                    .hmac_vld()
                    .clear_bit()
            });
        // SAFETY: WS63 SRAM addresses have no bits above bit 31.
        regs.in_hash_chn1_node_start_addr_h(HASH_CHANNEL_INDEX)
            .write(|w| unsafe { w.address_high().bits(0) });
        // SAFETY: WS63 uses a 32-bit physical address space for this SRAM.
        regs.in_hash_chn1_node_start_addr_l(HASH_CHANNEL_INDEX)
            .write(|w| unsafe { w.address_low().bits(node_address) });
        // SAFETY: the descriptor allocation contains exactly two entries.
        regs.in_hash_chn1_node_length(HASH_CHANNEL_INDEX)
            .write(|w| unsafe { w.node_length().bits(HASH_RING_DEPTH) });

        let (state_words, remainder) = algorithm.initial_state().as_chunks::<4>();
        debug_assert!(remainder.is_empty());
        for (index, chunk) in state_words.iter().enumerate() {
            // SAFETY: SHA-1 uses 5 words and SHA-256 uses 8, both within 5 bits.
            regs.chann1_hash_state_val_addr(HASH_CHANNEL_INDEX)
                .write(|w| unsafe { w.index().bits(index as u8) });
            let state = u32::from_le_bytes(*chunk);
            // SAFETY: write the complete SVD-modeled state data word.
            regs.chann1_hash_state_val(HASH_CHANNEL_INDEX)
                .write(|w| unsafe { w.state().bits(state) });
        }
        let pending = regs.hash_chann_raw_int().read().hash_chann_raw_int().bits();
        if pending & (HASH_CHANNEL_MASK as u16) != 0 {
            // SAFETY: W1C exactly the stale channel-1 completion bit.
            regs.hash_chann_raw_int()
                .write(|w| unsafe { w.hash_chann_raw_int().bits(HASH_CHANNEL_MASK as u16) });
        }
        io_fence();

        if regs.ree_hash_calc_ctrl_check_err().read().error().bits() != 0 {
            return Err(CryptoError::Backend(ERR_SPACC_CONTROL));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    fn wait_for_hash_completion(&self, regs: &RegisterBlock) -> Result<(), CryptoError> {
        let mut completed = false;
        for _ in 0..self.spacc_limits.operation().get() {
            let status = regs.hash_chann_raw_int().read().hash_chann_raw_int().bits();
            if status & (HASH_CHANNEL_MASK as u16) != 0 {
                completed = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !completed {
            return Err(CryptoError::Backend(ERR_SPACC_OPERATION_TIMEOUT));
        }
        // SAFETY: W1C exactly the completed channel-1 bit.
        regs.hash_chann_raw_int()
            .write(|w| unsafe { w.hash_chann_raw_int().bits(HASH_CHANNEL_MASK as u16) });
        io_fence();
        if regs.spacc_bus_err().read().bus_err().bits() != 0 {
            return Err(CryptoError::Backend(ERR_SPACC_BUS));
        }
        if regs.ree_hash_calc_ctrl_check_err().read().error().bits() != 0
            || regs
                .ree_hash_calc_ctrl_check_err_status()
                .read()
                .status()
                .bits()
                != 0
        {
            return Err(CryptoError::Backend(ERR_SPACC_CONTROL));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    fn read_hash_state(&self, regs: &RegisterBlock, output: &mut [u8]) {
        let (output_words, remainder) = output.as_chunks_mut::<4>();
        debug_assert!(remainder.is_empty());
        for (index, chunk) in output_words.iter_mut().enumerate() {
            // SAFETY: SHA-1 uses 5 words and SHA-256 uses 8, both within 5 bits.
            regs.chann1_hash_state_val_addr(HASH_CHANNEL_INDEX)
                .write(|w| unsafe { w.index().bits(index as u8) });
            let bytes = regs
                .chann1_hash_state_val(HASH_CHANNEL_INDEX)
                .read()
                .state()
                .bits()
                .to_le_bytes();
            chunk.copy_from_slice(&bytes);
        }
    }
}

impl TryHash<20> for Ws63Crypto<'_> {
    fn hash(&self, parts: &[&[u8]], output: &mut [u8; 20]) -> Result<(), CryptoError> {
        let _busy = self.enter()?;
        if checked_parts_len(parts)? > MAX_HASH_INPUT_BYTES {
            return Err(CryptoError::InvalidLength);
        }
        self.spacc_hash(HashAlgorithm::Sha1, None, parts, output)
    }
}

impl TryHash<32> for Ws63Crypto<'_> {
    fn hash(&self, parts: &[&[u8]], output: &mut [u8; 32]) -> Result<(), CryptoError> {
        let _busy = self.enter()?;
        if checked_parts_len(parts)? > MAX_HASH_INPUT_BYTES {
            return Err(CryptoError::InvalidLength);
        }
        self.spacc_hash(HashAlgorithm::Sha256, None, parts, output)
    }
}

impl TryMac<20> for Ws63Crypto<'_> {
    fn mac(&self, key: &[u8], parts: &[&[u8]], output: &mut [u8; 20]) -> Result<(), CryptoError> {
        let _busy = self.enter()?;
        self.spacc_hmac(HashAlgorithm::Sha1, key, parts, output)
    }
}

impl TryMac<32> for Ws63Crypto<'_> {
    fn mac(&self, key: &[u8], parts: &[&[u8]], output: &mut [u8; 32]) -> Result<(), CryptoError> {
        let _busy = self.enter()?;
        self.spacc_hmac(HashAlgorithm::Sha256, key, parts, output)
    }
}

fn checked_parts_len(parts: &[&[u8]]) -> Result<usize, CryptoError> {
    parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or(CryptoError::InvalidLength)
    })
}

fn prepare_padded_message(
    buffer: &mut [u8; HASH_DMA_BYTES],
    prefix: Option<&[u8]>,
    parts: &[&[u8]],
) -> Result<usize, CryptoError> {
    buffer.zeroize();
    let input_len = checked_parts_len(parts)?;
    if input_len > MAX_HASH_INPUT_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    let prefix_len = prefix.map_or(0, <[u8]>::len);
    let message_len = prefix_len
        .checked_add(input_len)
        .ok_or(CryptoError::InvalidLength)?;
    let with_marker = message_len
        .checked_add(1)
        .ok_or(CryptoError::InvalidLength)?;
    let padded_len = with_marker
        .checked_add(HASH_LENGTH_BYTES)
        .and_then(|length| length.checked_add(HASH_BLOCK_BYTES - 1))
        .map(|length| length & !(HASH_BLOCK_BYTES - 1))
        .ok_or(CryptoError::InvalidLength)?;
    if padded_len > buffer.len() {
        return Err(CryptoError::InvalidLength);
    }

    let mut cursor = 0;
    if let Some(prefix) = prefix {
        buffer[..prefix.len()].copy_from_slice(prefix);
        cursor = prefix.len();
    }
    for part in parts {
        let end = cursor + part.len();
        buffer[cursor..end].copy_from_slice(part);
        cursor = end;
    }
    buffer[cursor] = 0x80;
    let bit_len = u64::try_from(message_len)
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or(CryptoError::InvalidLength)?;
    buffer[padded_len - HASH_LENGTH_BYTES..padded_len].copy_from_slice(&bit_len.to_be_bytes());
    Ok(padded_len)
}

#[cfg(target_arch = "riscv32")]
#[inline]
fn io_fence() {
    // SAFETY: this emits only an ordering barrier for prior/following MMIO.
    unsafe { core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags)) };
}

#[cfg(target_arch = "riscv32")]
unsafe fn clean_dcache_range(address: usize, length: usize) {
    const CACHE_LINE: usize = 32;
    if length == 0 {
        return;
    }
    let start = address & !(CACHE_LINE - 1);
    let Some(end_unaligned) = address
        .checked_add(length)
        .and_then(|end| end.checked_add(CACHE_LINE - 1))
    else {
        return;
    };
    let end = end_unaligned & !(CACHE_LINE - 1);
    let mut line = start;
    while line < end {
        // SAFETY: the caller provides a mapped, live SRAM range owned by this
        // backend. These custom M-mode CSRs clean one D-cache line by address.
        unsafe {
            core::arch::asm!(
                "csrw 0x7c5, {address}",
                "csrw 0x7c3, {command}",
                address = in(reg) line,
                command = in(reg) 0x9,
                options(nostack),
            );
        }
        line += CACHE_LINE;
    }
    // SAFETY: order cache maintenance before SPACC observes descriptor/data RAM.
    unsafe { core::arch::asm!("fence", options(nostack)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spacc_poll_limits_are_explicitly_nonzero() {
        let limits = SpaccPollLimits::default();
        assert_eq!(limits.lock().get(), DEFAULT_SPACC_POLL_LIMIT);
        assert_eq!(limits.clear().get(), DEFAULT_SPACC_POLL_LIMIT);
        assert_eq!(limits.operation().get(), DEFAULT_SPACC_POLL_LIMIT);
    }

    #[test]
    fn sha_padding_matches_fips_shape() {
        let mut buffer = [0u8; HASH_DMA_BYTES];
        let padded = prepare_padded_message(&mut buffer, None, &[b"abc"]).unwrap();
        assert_eq!(padded, 64);
        assert_eq!(&buffer[..4], b"abc\x80");
        assert!(buffer[4..56].iter().all(|byte| *byte == 0));
        assert_eq!(&buffer[56..64], &24u64.to_be_bytes());
    }

    #[test]
    fn hmac_prefix_contributes_to_bit_length() {
        let mut buffer = [0u8; HASH_DMA_BYTES];
        let prefix = [0x36; HASH_BLOCK_BYTES];
        let padded = prepare_padded_message(&mut buffer, Some(&prefix), &[b"abc"]).unwrap();
        assert_eq!(padded, 128);
        assert_eq!(&buffer[..HASH_BLOCK_BYTES], &prefix);
        assert_eq!(&buffer[HASH_BLOCK_BYTES..HASH_BLOCK_BYTES + 4], b"abc\x80");
        assert_eq!(&buffer[padded - 8..padded], &(67u64 * 8).to_be_bytes());
    }

    #[test]
    fn oversized_message_is_rejected() {
        let mut buffer = [0u8; HASH_DMA_BYTES];
        let oversized = [0u8; MAX_HASH_INPUT_BYTES + 1];
        assert_eq!(
            prepare_padded_message(&mut buffer, None, &[&oversized]),
            Err(CryptoError::InvalidLength)
        );
    }
}
