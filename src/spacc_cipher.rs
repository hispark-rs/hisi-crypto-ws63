#![cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]

use core::num::NonZeroU32;

use hisi_crypto::{CryptoError, TryBlockCipher};
use zeroize::Zeroize;

use crate::Ws63Crypto;

#[cfg(target_arch = "riscv32")]
use ws63_pac::{km, spacc};

const AES_BLOCK_BYTES: usize = 16;
const SYM_CHANNEL_INDEX: usize = 0;
const SYM_CHANNEL_NUMBER: u32 = 1;
const SYM_CHANNEL_MASK: u32 = 1 << SYM_CHANNEL_NUMBER;
const SYM_CHANNEL_OWNER_SHIFT: u32 = SYM_CHANNEL_NUMBER * 4;
const SYM_CHANNEL_OWNER_MASK: u32 = 0xf << SYM_CHANNEL_OWNER_SHIFT;
const SYM_CHANNEL_OWNER_REE: u32 = 1;
const SYM_RING_DEPTH: u8 = 2;
const MCIPHER_KEYSLOTS: u16 = 8;
const KEYSLOT_OWNER_REE: u8 = 1;
const KLAD_OWNER_REE: u8 = 0xaa;
const DEFAULT_POLL_LIMIT: u32 = 1_000_000;

const ERR_LOCK_TIMEOUT: u32 = 0xffff_1301;
const ERR_CLEAR_TIMEOUT: u32 = 0xffff_1302;
const ERR_OPERATION_TIMEOUT: u32 = 0xffff_1303;
const ERR_BUS: u32 = 0xffff_1304;
const ERR_CONTROL: u32 = 0xffff_1305;
const ERR_ADDRESS: u32 = 0xffff_1306;
const ERR_KEYSLOT_UNAVAILABLE: u32 = 0xffff_1307;
const ERR_KEYSLOT: u32 = 0xffff_1308;
const ERR_KLAD_LOCK_TIMEOUT: u32 = 0xffff_1309;
const ERR_KLAD_ROUTE_TIMEOUT: u32 = 0xffff_130a;
const ERR_KLAD: u32 = 0xffff_130b;

/// Bounded polling contract for one WS63 SPACC block-cipher operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpaccCipherPollLimits {
    channel_lock: NonZeroU32,
    channel_clear: NonZeroU32,
    operation: NonZeroU32,
    keyslot: NonZeroU32,
    klad: NonZeroU32,
}

impl SpaccCipherPollLimits {
    /// Construct explicit non-zero limits for all hardware progress points.
    pub const fn new(
        channel_lock: NonZeroU32,
        channel_clear: NonZeroU32,
        operation: NonZeroU32,
        keyslot: NonZeroU32,
        klad: NonZeroU32,
    ) -> Self {
        Self {
            channel_lock,
            channel_clear,
            operation,
            keyslot,
            klad,
        }
    }

    pub const fn channel_lock(self) -> NonZeroU32 {
        self.channel_lock
    }

    pub const fn channel_clear(self) -> NonZeroU32 {
        self.channel_clear
    }

    pub const fn operation(self) -> NonZeroU32 {
        self.operation
    }

    pub const fn keyslot(self) -> NonZeroU32 {
        self.keyslot
    }

    pub const fn klad(self) -> NonZeroU32 {
        self.klad
    }
}

impl Default for SpaccCipherPollLimits {
    fn default() -> Self {
        let Some(limit) = NonZeroU32::new(DEFAULT_POLL_LIMIT) else {
            unreachable!()
        };
        Self::new(limit, limit, limit, limit, limit)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SymInputNode {
    flags: u32,
    length: u32,
    address_low: u32,
    address_high: u32,
    iv: [u32; 4],
}

impl SymInputNode {
    const EMPTY: Self = Self {
        flags: 0,
        length: 0,
        address_low: 0,
        address_high: 0,
        iv: [0; 4],
    };
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SymOutputNode {
    reserved: u32,
    length: u32,
    address_low: u32,
    address_high: u32,
}

impl SymOutputNode {
    const EMPTY: Self = Self {
        reserved: 0,
        length: 0,
        address_low: 0,
        address_high: 0,
    };
}

#[repr(C, align(32))]
pub(crate) struct CipherDmaStorage {
    input_nodes: [SymInputNode; SYM_RING_DEPTH as usize],
    output_nodes: [SymOutputNode; SYM_RING_DEPTH as usize],
    input: [u8; AES_BLOCK_BYTES],
    output: [u8; AES_BLOCK_BYTES],
}

impl CipherDmaStorage {
    pub(crate) const fn new() -> Self {
        Self {
            input_nodes: [SymInputNode::EMPTY; SYM_RING_DEPTH as usize],
            output_nodes: [SymOutputNode::EMPTY; SYM_RING_DEPTH as usize],
            input: [0; AES_BLOCK_BYTES],
            output: [0; AES_BLOCK_BYTES],
        }
    }

    fn clear(&mut self) {
        self.input_nodes.fill(SymInputNode::EMPTY);
        self.output_nodes.fill(SymOutputNode::EMPTY);
        self.input.zeroize();
        self.output.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeyLength {
    register: u8,
}

impl KeyLength {
    fn from_bytes(length: usize) -> Result<Self, CryptoError> {
        let register = match length {
            16 => 1,
            24 => 2,
            32 => 3,
            _ => return Err(CryptoError::InvalidLength),
        };
        Ok(Self { register })
    }
}

impl Ws63Crypto<'_> {
    #[cfg(target_arch = "riscv32")]
    fn cipher_spacc_regs(&self) -> &'static spacc::RegisterBlock {
        // SAFETY: `self._spacc` owns the unique HAL token for this MMIO block.
        unsafe { &*hisi_hal::peripherals::Spacc::ptr() }
    }

    #[cfg(target_arch = "riscv32")]
    fn cipher_block(
        &self,
        key: &[u8],
        input: &[u8; AES_BLOCK_BYTES],
        output: &mut [u8; AES_BLOCK_BYTES],
        decrypt: bool,
    ) -> Result<(), CryptoError> {
        let key_length = KeyLength::from_bytes(key.len())?;
        let km_regs = self.regs();
        let spacc_regs = self.cipher_spacc_regs();
        let keyslot = self.lock_keyslot(km_regs)?;

        let mut result = self.load_key(km_regs, keyslot, key, key_length);
        if result.is_ok() {
            result = self.lock_sym_channel(spacc_regs);
        }
        let channel_locked = result.is_ok();
        if result.is_ok() {
            result = self.run_cipher(spacc_regs, keyslot, key_length, input, output, decrypt);
        }

        if channel_locked {
            // Fail closed: if the engine cannot be proven stopped, do not
            // mutate its DMA buffers or release the channel/keyslot.
            self.clear_sym_channel(spacc_regs)?;
            self.scrub_cipher_storage();
            self.unlock_sym_channel(spacc_regs);
        }
        let keyslot_cleanup = self.unlock_keyslot(km_regs, keyslot);
        if result.is_ok() {
            result = keyslot_cleanup;
        }
        result
    }

    #[cfg(not(target_arch = "riscv32"))]
    fn cipher_block(
        &self,
        key: &[u8],
        _input: &[u8; AES_BLOCK_BYTES],
        _output: &mut [u8; AES_BLOCK_BYTES],
        _decrypt: bool,
    ) -> Result<(), CryptoError> {
        KeyLength::from_bytes(key.len())?;
        Err(CryptoError::Unsupported)
    }

    #[cfg(target_arch = "riscv32")]
    fn lock_keyslot(&self, regs: &km::RegisterBlock) -> Result<u16, CryptoError> {
        for slot in 0..MCIPHER_KEYSLOTS {
            if self.keyslot_owner(regs, slot) != 0 {
                continue;
            }
            if !self.wait_keyslot_idle(regs) {
                continue;
            }
            // SAFETY: the slot is within the eight MCipher slots; all other
            // complete-command fields intentionally remain zero.
            regs.kc_reecpu_lock_cmd().write(|w| unsafe {
                w.key_slot_num()
                    .bits(slot)
                    .flush_hmac_kslot_ind()
                    .clear_bit()
                    .tscipher_ind()
                    .clear_bit()
                    .lock_cmd()
                    .set_bit()
            });
            io_fence();
            if self.keyslot_owner(regs, slot) == KEYSLOT_OWNER_REE {
                return Ok(slot);
            }
        }
        Err(CryptoError::Backend(ERR_KEYSLOT_UNAVAILABLE))
    }

    #[cfg(target_arch = "riscv32")]
    fn keyslot_owner(&self, regs: &km::RegisterBlock, slot: u16) -> u8 {
        // SAFETY: the complete selector names one MCipher slot and no TS cipher.
        regs.kc_rd_slot_num().write(|w| unsafe {
            w.slot_num_cfg()
                .bits(slot)
                .slot_cfg_type()
                .clear_bit()
                .tscipher_slot_ind()
                .clear_bit()
        });
        io_fence();
        regs.kc_rd_lock_status().read().rd_lock_status().bits()
    }

    #[cfg(target_arch = "riscv32")]
    fn wait_keyslot_idle(&self, regs: &km::RegisterBlock) -> bool {
        for _ in 0..self.cipher_limits.keyslot().get() {
            let status = regs.kc_reecpu_flush_busy().read();
            if !status.flush_busy().bit_is_set() {
                return !status.unlock_fail().bit_is_set() && !status.timeout_error().bit_is_set();
            }
            core::hint::spin_loop();
        }
        false
    }

    #[cfg(target_arch = "riscv32")]
    fn unlock_keyslot(&self, regs: &km::RegisterBlock, slot: u16) -> Result<(), CryptoError> {
        if self.keyslot_owner(regs, slot) == 0 {
            return Ok(());
        }
        // SAFETY: complete unlock command for one MCipher slot.
        regs.kc_reecpu_lock_cmd().write(|w| unsafe {
            w.key_slot_num()
                .bits(slot)
                .flush_hmac_kslot_ind()
                .clear_bit()
                .tscipher_ind()
                .clear_bit()
                .lock_cmd()
                .clear_bit()
        });
        io_fence();
        if !self.wait_keyslot_idle(regs) || self.keyslot_owner(regs, slot) != 0 {
            return Err(CryptoError::Backend(ERR_KEYSLOT));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    fn load_key(
        &self,
        regs: &km::RegisterBlock,
        slot: u16,
        key: &[u8],
        key_length: KeyLength,
    ) -> Result<(), CryptoError> {
        self.lock_klad(regs)?;
        let result = (|| {
            // SAFETY: the keyslot is represented as slot*2 plus the parity bit.
            regs.kl_key_addr()
                .write(|w| unsafe { w.key_addr().bits(slot << 1) });
            // SAFETY: 1 selects MCipher and 0x20 selects AES; both encrypt and
            // decrypt use the same explicitly loaded key.
            regs.kl_key_cfg().write(|w| unsafe {
                w.port_sel()
                    .bits(1)
                    .dsc_code()
                    .bits(0x20)
                    .key_enc()
                    .set_bit()
                    .key_dec()
                    .set_bit()
            });
            regs.kl_key_sec_cfg().write(|w| {
                w.key_sec()
                    .clear_bit()
                    .src_nsec()
                    .set_bit()
                    .src_sec()
                    .clear_bit()
                    .dest_nsec()
                    .set_bit()
                    .dest_sec()
                    .clear_bit()
                    .master_only()
                    .clear_bit()
            });

            self.load_key_half(
                regs,
                slot,
                false,
                &key[..core::cmp::min(16, key.len())],
                key_length,
            )?;
            if key.len() > 16 {
                self.load_key_half(regs, slot, true, &key[16..], key_length)?;
            }
            Ok(())
        })();
        self.clear_klad_staging(regs);
        let unlock = self.unlock_klad(regs);
        result.and(unlock)
    }

    #[cfg(target_arch = "riscv32")]
    fn load_key_half(
        &self,
        regs: &km::RegisterBlock,
        slot: u16,
        odd: bool,
        bytes: &[u8],
        key_length: KeyLength,
    ) -> Result<(), CryptoError> {
        let key_addr = (slot << 1) | u16::from(odd);
        // SAFETY: slot*2 plus one parity bit fits the ten-bit field.
        regs.kl_key_addr()
            .write(|w| unsafe { w.key_addr().bits(key_addr) });
        let mut padded = [0u8; 16];
        padded[..bytes.len()].copy_from_slice(bytes);
        let w0 = u32::from_le_bytes(padded[0..4].try_into().unwrap());
        let w1 = u32::from_le_bytes(padded[4..8].try_into().unwrap());
        let w2 = u32::from_le_bytes(padded[8..12].try_into().unwrap());
        let w3 = u32::from_le_bytes(padded[12..16].try_into().unwrap());
        // SAFETY: each value is the complete 32-bit write-only staging word.
        unsafe {
            regs.kl_data_in_0().write(|w| w.data().bits(w0));
            regs.kl_data_in_1().write(|w| w.data().bits(w1));
            regs.kl_data_in_2().write(|w| w.data().bits(w2));
            regs.kl_data_in_3().write(|w| w.data().bits(w3));
        }
        padded.zeroize();

        // SAFETY: complete clear-route command with a validated key-size code.
        regs.kl_clr_ctrl().write(|w| unsafe {
            w.key_size()
                .bits(key_length.register)
                .key_count()
                .bits(0)
                .start()
                .set_bit()
        });
        io_fence();
        for _ in 0..self.cipher_limits.klad().get() {
            if regs.kl_clr_ctrl().read().start().bit_is_clear() {
                regs.kl_int_raw()
                    .write(|w| w.clr_kl_int_raw().clear_bit_by_one());
                io_fence();
                if regs.kl_error().read().error().bits() != 0
                    || regs.kc_error().read().error().bits() != 0
                {
                    return Err(CryptoError::Backend(ERR_KLAD));
                }
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_KLAD_ROUTE_TIMEOUT))
    }

    #[cfg(target_arch = "riscv32")]
    fn clear_klad_staging(&self, regs: &km::RegisterBlock) {
        // SAFETY: zero is the complete value for each write-only staging word.
        unsafe {
            regs.kl_data_in_0().write(|w| w.data().bits(0));
            regs.kl_data_in_1().write(|w| w.data().bits(0));
            regs.kl_data_in_2().write(|w| w.data().bits(0));
            regs.kl_data_in_3().write(|w| w.data().bits(0));
        }
        io_fence();
    }

    #[cfg(target_arch = "riscv32")]
    fn lock_klad(&self, regs: &km::RegisterBlock) -> Result<(), CryptoError> {
        for _ in 0..self.cipher_limits.klad().get() {
            // SAFETY: sequence zero and a set request bit form the complete lock command.
            unsafe {
                regs.kl_lock_ctrl()
                    .write(|w| w.kl_lock_num().bits(0).kl_lock().set_bit());
            }
            io_fence();
            let info = regs.kl_com_lock_info().read();
            if info.lock_fail().bits() != 1
                && regs.kl_com_lock_status().read().lock_status().bits() == KLAD_OWNER_REE
            {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_KLAD_LOCK_TIMEOUT))
    }

    #[cfg(target_arch = "riscv32")]
    fn unlock_klad(&self, regs: &km::RegisterBlock) -> Result<(), CryptoError> {
        if regs.kl_com_lock_status().read().lock_status().bits() != KLAD_OWNER_REE {
            return Ok(());
        }
        // SAFETY: sequence zero and a set request bit form the complete unlock command.
        unsafe {
            regs.kl_unlock_ctrl().write(|w| {
                w.kl_unlock_num()
                    .bits(0)
                    .kl_com_unlock_num()
                    .bits(0)
                    .kl_unlock()
                    .set_bit()
            });
        }
        io_fence();
        if regs.kl_com_lock_info().read().unlock_fail().bits() == 1 {
            return Err(CryptoError::Backend(ERR_KLAD));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    fn lock_sym_channel(&self, regs: &spacc::RegisterBlock) -> Result<(), CryptoError> {
        self.try_lock_sym_channel(regs, self.cipher_limits.channel_lock().get())
    }

    #[cfg(target_arch = "riscv32")]
    fn try_lock_sym_channel(
        &self,
        regs: &spacc::RegisterBlock,
        attempts: u32,
    ) -> Result<(), CryptoError> {
        for _ in 0..attempts {
            let acquired = critical_section::with(|_| {
                let used = regs.spacc_sym_chn_lock().read().sym_chn_lock().bits();
                if ((used & SYM_CHANNEL_OWNER_MASK) >> SYM_CHANNEL_OWNER_SHIFT) != 0 {
                    return false;
                }
                let claimed = (used & !SYM_CHANNEL_OWNER_MASK)
                    | (SYM_CHANNEL_OWNER_REE << SYM_CHANNEL_OWNER_SHIFT);
                // SAFETY: preserve every other owner nibble and claim channel 1 for REE.
                unsafe {
                    regs.spacc_sym_chn_lock()
                        .write(|w| w.sym_chn_lock().bits(claimed));
                }
                io_fence();
                let verified = regs.spacc_sym_chn_lock().read().sym_chn_lock().bits();
                ((verified & SYM_CHANNEL_OWNER_MASK) >> SYM_CHANNEL_OWNER_SHIFT)
                    == SYM_CHANNEL_OWNER_REE
            });
            if acquired {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_LOCK_TIMEOUT))
    }

    #[cfg(target_arch = "riscv32")]
    fn unlock_sym_channel(&self, regs: &spacc::RegisterBlock) {
        critical_section::with(|_| {
            let used = regs.spacc_sym_chn_lock().read().sym_chn_lock().bits();
            // SAFETY: preserve every other owner nibble and clear channel 1 only.
            unsafe {
                regs.spacc_sym_chn_lock()
                    .write(|w| w.sym_chn_lock().bits(used & !SYM_CHANNEL_OWNER_MASK));
            }
            io_fence();
        });
    }

    #[cfg(target_arch = "riscv32")]
    fn clear_sym_channel(&self, regs: &spacc::RegisterBlock) -> Result<(), CryptoError> {
        // SAFETY: request exactly the channel-1 clear bit.
        unsafe {
            regs.spacc_sym_chn_clear_req()
                .write(|w| w.sym_chn_clear_req().bits(SYM_CHANNEL_MASK));
        }
        io_fence();
        for _ in 0..self.cipher_limits.channel_clear().get() {
            let status = regs
                .spacc_int_raw_sym_clr_finish()
                .read()
                .raw_sym_clr_finish_int()
                .bits();
            if status & (SYM_CHANNEL_MASK as u16) != 0 {
                // SAFETY: W1C exactly the channel-1 clear completion bit.
                unsafe {
                    regs.spacc_int_raw_sym_clr_finish()
                        .write(|w| w.raw_sym_clr_finish_int().bits(SYM_CHANNEL_MASK as u16));
                }
                io_fence();
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_CLEAR_TIMEOUT))
    }

    #[cfg(target_arch = "riscv32")]
    fn run_cipher(
        &self,
        regs: &spacc::RegisterBlock,
        keyslot: u16,
        key_length: KeyLength,
        input: &[u8; AES_BLOCK_BYTES],
        output: &mut [u8; AES_BLOCK_BYTES],
        decrypt: bool,
    ) -> Result<(), CryptoError> {
        self.clear_sym_channel(regs)?;
        // SAFETY: `Ws63Crypto::enter` serializes every public operation and the
        // caller moved the unique static storage reference into this backend.
        let storage = unsafe { &mut *self.storage.cipher.get() };
        storage.clear();

        let input_nodes = u32::try_from(storage.input_nodes.as_ptr() as usize)
            .map_err(|_| CryptoError::Backend(ERR_ADDRESS))?;
        let output_nodes = u32::try_from(storage.output_nodes.as_ptr() as usize)
            .map_err(|_| CryptoError::Backend(ERR_ADDRESS))?;
        let input_address = u32::try_from(storage.input.as_ptr() as usize)
            .map_err(|_| CryptoError::Backend(ERR_ADDRESS))?;
        let output_address = u32::try_from(storage.output.as_ptr() as usize)
            .map_err(|_| CryptoError::Backend(ERR_ADDRESS))?;
        storage.input.copy_from_slice(input);

        storage.input_nodes[0] = SymInputNode {
            flags: 0b11,
            length: AES_BLOCK_BYTES as u32,
            address_low: input_address,
            address_high: 0,
            iv: [0; 4],
        };
        storage.output_nodes[0] = SymOutputNode {
            reserved: 0,
            length: AES_BLOCK_BYTES as u32,
            address_low: output_address,
            address_high: 0,
        };

        // SAFETY: channel selectors are fixed SVD-modeled non-secure REE values.
        unsafe {
            regs.in_sym_chn1_ctrl(SYM_CHANNEL_INDEX).write(|w| {
                w.sym_chn_ss()
                    .bits(0x0a)
                    .sym_chn_ds()
                    .bits(0x0a)
                    .sym_chn_en()
                    .set_bit()
            });
        }
        regs.in_sym_out_ctrl1(SYM_CHANNEL_INDEX)
            .write(|w| w.dma_copy().clear_bit());
        regs.in_sym_chn1_key_ctrl(SYM_CHANNEL_INDEX).write(|w| {
            // SAFETY: all integer values were range checked or are fixed vendor encodings.
            unsafe {
                let w = w
                    .key_chn_id()
                    .bits(keyslot)
                    .alg_sel()
                    .bits(2)
                    .alg_mode()
                    .bits(1)
                    .key_len()
                    .bits(key_length.register)
                    .data_width()
                    .bits(0);
                if decrypt {
                    w.decrypt().set_bit()
                } else {
                    w.decrypt().clear_bit()
                }
            }
        });
        // SAFETY: both descriptor arrays are 32-bit SRAM addresses and contain two entries.
        unsafe {
            regs.in_sym_chn1_node_start_addr_h(SYM_CHANNEL_INDEX)
                .write(|w| w.address_high().bits(0));
            regs.in_sym_chn1_node_start_addr_l(SYM_CHANNEL_INDEX)
                .write(|w| w.address_low().bits(input_nodes));
            regs.in_sym_chn1_node_length(SYM_CHANNEL_INDEX)
                .write(|w| w.node_length().bits(SYM_RING_DEPTH));
            regs.out_sym_chn1_node_start_addr_h(SYM_CHANNEL_INDEX)
                .write(|w| w.address_high().bits(0));
            regs.out_sym_chn1_node_start_addr_l(SYM_CHANNEL_INDEX)
                .write(|w| w.address_low().bits(output_nodes));
            regs.out_sym_chn1_node_length(SYM_CHANNEL_INDEX)
                .write(|w| w.node_length().bits(SYM_RING_DEPTH));
        }

        let stale = regs
            .out_sym_chan_raw_last_node_int()
            .read()
            .out_sym_chan_raw_int()
            .bits();
        if stale & (SYM_CHANNEL_MASK as u16) != 0 {
            // SAFETY: W1C exactly the stale channel-1 completion bit.
            unsafe {
                regs.out_sym_chan_raw_last_node_int()
                    .write(|w| w.out_sym_chan_raw_int().bits(SYM_CHANNEL_MASK as u16));
            }
        }
        if regs.ree_sym_calc_ctrl_check_err().read().error().bits() != 0 {
            return Err(CryptoError::Backend(ERR_CONTROL));
        }

        // SAFETY: every range is live, 32-byte aligned SRAM owned exclusively
        // by this backend while SPACC is active.
        unsafe {
            hisi_hal::cache::clean_range(
                storage.input_nodes.as_ptr() as usize,
                core::mem::size_of_val(&storage.input_nodes),
            );
            hisi_hal::cache::clean_range(
                storage.output_nodes.as_ptr() as usize,
                core::mem::size_of_val(&storage.output_nodes),
            );
            hisi_hal::cache::clean_range(storage.input.as_ptr() as usize, AES_BLOCK_BYTES);
            hisi_hal::cache::flush_range(storage.output.as_ptr() as usize, AES_BLOCK_BYTES);
        }
        io_fence();

        let out_current = regs
            .out_sym_chn1_node_wr_point(SYM_CHANNEL_INDEX)
            .read()
            .write_pointer()
            .bits();
        let out_next = out_current.wrapping_add(1) % SYM_RING_DEPTH;
        // SAFETY: pointer is reduced modulo the two-entry output ring.
        unsafe {
            regs.out_sym_chn1_node_wr_point(SYM_CHANNEL_INDEX)
                .write(|w| w.write_pointer().bits(out_next));
        }
        let in_current = regs
            .in_sym_chn1_node_wr_point(SYM_CHANNEL_INDEX)
            .read()
            .write_pointer()
            .bits();
        let in_next = in_current.wrapping_add(1) % SYM_RING_DEPTH;
        // SAFETY: pointer is reduced modulo the two-entry input ring.
        unsafe {
            regs.in_sym_chn1_node_wr_point(SYM_CHANNEL_INDEX)
                .write(|w| w.write_pointer().bits(in_next));
        }
        io_fence();

        let mut completed = false;
        for _ in 0..self.cipher_limits.operation().get() {
            let status = regs
                .out_sym_chan_raw_last_node_int()
                .read()
                .out_sym_chan_raw_int()
                .bits();
            if status & (SYM_CHANNEL_MASK as u16) != 0 {
                completed = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !completed {
            return Err(CryptoError::Backend(ERR_OPERATION_TIMEOUT));
        }
        // SAFETY: W1C exactly the completed channel-1 bit.
        unsafe {
            regs.out_sym_chan_raw_last_node_int()
                .write(|w| w.out_sym_chan_raw_int().bits(SYM_CHANNEL_MASK as u16));
        }
        io_fence();
        if regs.spacc_bus_err().read().bus_err().bits() != 0 {
            return Err(CryptoError::Backend(ERR_BUS));
        }
        if regs.ree_sym_calc_ctrl_check_err().read().error().bits() != 0
            || regs
                .ree_sym_calc_ctrl_check_err_status()
                .read()
                .status()
                .bits()
                != 0
        {
            return Err(CryptoError::Backend(ERR_CONTROL));
        }

        // SAFETY: SPACC has completed its write to this exclusively-owned,
        // line-aligned output buffer.
        unsafe {
            hisi_hal::cache::invalidate_range(storage.output.as_ptr() as usize, AES_BLOCK_BYTES);
        }
        output.copy_from_slice(&storage.output);
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    fn scrub_cipher_storage(&self) {
        // SAFETY: the caller invokes this only after channel clear completed;
        // the public busy guard still exclusively owns the backend storage.
        let storage = unsafe { &mut *self.storage.cipher.get() };
        storage.clear();
        // SAFETY: remove plaintext/ciphertext copies from RAM as well as cache;
        // the backend still owns every aligned range and SPACC has stopped.
        unsafe {
            hisi_hal::cache::clean_range(
                storage.input_nodes.as_ptr() as usize,
                core::mem::size_of_val(&storage.input_nodes),
            );
            hisi_hal::cache::clean_range(
                storage.output_nodes.as_ptr() as usize,
                core::mem::size_of_val(&storage.output_nodes),
            );
            hisi_hal::cache::clean_range(storage.input.as_ptr() as usize, AES_BLOCK_BYTES);
            hisi_hal::cache::clean_range(storage.output.as_ptr() as usize, AES_BLOCK_BYTES);
        }
    }

    /// Diagnostic-only proof that timeout recovery and AES-128/192/256 work.
    #[cfg(all(target_arch = "riscv32", feature = "diagnostics"))]
    #[doc(hidden)]
    pub fn diagnostic_cipher_recovery(&self) -> Result<(), CryptoError> {
        let regs = self.cipher_spacc_regs();
        if self.try_lock_sym_channel(regs, 0) != Err(CryptoError::Backend(ERR_LOCK_TIMEOUT)) {
            return Err(CryptoError::Backend(0xffff_13f1));
        }

        const VECTORS: [(&[u8], [u8; 16], [u8; 16]); 3] = [
            (
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ],
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ],
            ),
            (
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                ],
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                [
                    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec,
                    0x0d, 0x71, 0x91,
                ],
            ),
            (
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                [
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b,
                    0x49, 0x60, 0x89,
                ],
            ),
        ];
        for (key, plaintext, ciphertext) in VECTORS {
            let mut encrypted = [0; 16];
            TryBlockCipher::encrypt_block(self, key, &plaintext, &mut encrypted)?;
            if encrypted != ciphertext {
                return Err(CryptoError::Backend(0xffff_13f2));
            }
            let mut decrypted = [0; 16];
            TryBlockCipher::decrypt_block(self, key, &ciphertext, &mut decrypted)?;
            if decrypted != plaintext {
                return Err(CryptoError::Backend(0xffff_13f3));
            }
        }
        Ok(())
    }
}

impl TryBlockCipher for Ws63Crypto<'_> {
    fn encrypt_block(
        &self,
        key: &[u8],
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        let _busy = self.enter()?;
        self.cipher_block(key, input, output, false)
    }

    fn decrypt_block(
        &self,
        key: &[u8],
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        let _busy = self.enter()?;
        self.cipher_block(key, input, output, true)
    }
}

#[cfg(target_arch = "riscv32")]
#[inline]
fn io_fence() {
    // SAFETY: this emits only an ordering barrier for prior/following MMIO.
    unsafe { core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_length_encoding_matches_vendor_driver() {
        assert_eq!(KeyLength::from_bytes(16).unwrap().register, 1);
        assert_eq!(KeyLength::from_bytes(24).unwrap().register, 2);
        assert_eq!(KeyLength::from_bytes(32).unwrap().register, 3);
        assert_eq!(KeyLength::from_bytes(15), Err(CryptoError::InvalidLength));
    }

    #[test]
    fn descriptor_layout_matches_spacc_abi() {
        assert_eq!(core::mem::size_of::<SymInputNode>(), 32);
        assert_eq!(core::mem::size_of::<SymOutputNode>(), 16);
        assert_eq!(core::mem::align_of::<CipherDmaStorage>(), 32);
    }

    #[test]
    fn cipher_poll_limits_are_nonzero() {
        let limits = SpaccCipherPollLimits::default();
        assert_eq!(limits.channel_lock().get(), DEFAULT_POLL_LIMIT);
        assert_eq!(limits.channel_clear().get(), DEFAULT_POLL_LIMIT);
        assert_eq!(limits.operation().get(), DEFAULT_POLL_LIMIT);
        assert_eq!(limits.keyslot().get(), DEFAULT_POLL_LIMIT);
        assert_eq!(limits.klad().get(), DEFAULT_POLL_LIMIT);
    }
}
