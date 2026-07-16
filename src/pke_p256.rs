//! WS63 PKE-backed NIST P-256 arithmetic.
//!
//! The register/microcode sequence is derived from the Apache-2.0
//! `security_unified` PKE driver in the WS63 vendor SDK. This implementation
//! keeps only the fixed group-19 capabilities required by SAE;
//! it does not import the vendor scheduler, allocator, global curve registry,
//! or broad PKE provider API.

#[cfg(target_arch = "riscv32")]
use core::cell::Cell;

#[cfg(any(test, target_arch = "riscv32"))]
use hisi_crypto::sae::P256_FIELD_PRIME;
#[cfg(any(test, target_arch = "riscv32"))]
use hisi_crypto::sae::{GROUP_19, Group19, RustCryptoGroup19};
use hisi_crypto::{
    CryptoError, EntropySource,
    sae::{
        P256_ELEMENT_BYTES, P256AffinePoint, P256FieldElement, P256PointResult, TryP256FieldMul,
        TryP256PointAdd, TryP256PointMul,
    },
};
use hisi_hal::peripherals::Pke;
#[cfg(any(test, target_arch = "riscv32"))]
use zeroize::Zeroize;

#[cfg(target_arch = "riscv32")]
use hisi_rom_sys::ws63::security;

#[cfg(target_arch = "riscv32")]
const ERR_BUSY: u32 = 0xffff_1401;
#[cfg(target_arch = "riscv32")]
const ERR_MASK_ENTROPY: u32 = 0xffff_1402;
#[cfg(target_arch = "riscv32")]
const ERR_LOCK_TIMEOUT: u32 = 0xffff_1403;
#[cfg(target_arch = "riscv32")]
const ERR_INSTR_READY_TIMEOUT: u32 = 0xffff_1404;
#[cfg(target_arch = "riscv32")]
const ERR_OPERATION_TIMEOUT: u32 = 0xffff_1405;
#[cfg(target_arch = "riscv32")]
const ERR_FINISH_STATUS: u32 = 0xffff_1406;

#[cfg(target_arch = "riscv32")]
const PKE_POLL_LIMIT: usize = 10_000_000;
#[cfg(target_arch = "riscv32")]
const PKE_ACPU_LOCK_CODE: u8 = 0xaa;
#[cfg(target_arch = "riscv32")]
const PKE_BATCH_START_CODE: u16 = 0x05aa;
#[cfg(target_arch = "riscv32")]
const PKE_FINISH_CODE: u8 = 0x05;

#[cfg(any(test, target_arch = "riscv32"))]
const P256_P: [u8; 32] = P256_FIELD_PRIME;
#[cfg(target_arch = "riscv32")]
const P256_A: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
];
#[cfg(target_arch = "riscv32")]
const P256_B: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];
#[cfg(any(test, target_arch = "riscv32"))]
const P256_GX: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
#[cfg(any(test, target_arch = "riscv32"))]
const P256_GY: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];
#[cfg(target_arch = "riscv32")]
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
#[cfg(target_arch = "riscv32")]
const P256_MONT_A: [u8; 32] = [
    0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
];
#[cfg(target_arch = "riscv32")]
const P256_MONT_B: [u8; 32] = [
    0x76, 0x1b, 0x22, 0xc0, 0x80, 0xc3, 0xc6, 0xac, 0x26, 0xf1, 0x55, 0x0c, 0x23, 0xf4, 0xf7, 0x8f,
    0x3b, 0x1b, 0xfa, 0x97, 0xb2, 0x54, 0xbc, 0xb8, 0xdc, 0x43, 0xd9, 0x9b, 0x5e, 0xe4, 0x86, 0x5f,
];
#[cfg(target_arch = "riscv32")]
const P256_MONT_1_P: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
#[cfg(target_arch = "riscv32")]
const P256_MONT_1_N: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x43, 0x19, 0x05, 0x52, 0x58, 0xe8, 0x61, 0x7b, 0x0c, 0x46, 0x35, 0x3d, 0x03, 0x9c, 0xda, 0xaf,
];
#[cfg(target_arch = "riscv32")]
const P256_RRP: [u8; 32] = [
    0x00, 0x00, 0x00, 0x04, 0xff, 0xff, 0xff, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xfb, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];
#[cfg(target_arch = "riscv32")]
const P256_RRN: [u8; 32] = [
    0x66, 0xe1, 0x2d, 0x94, 0xf3, 0xd9, 0x56, 0x20, 0x28, 0x45, 0xb2, 0x39, 0x2b, 0x6b, 0xec, 0x59,
    0x46, 0x99, 0x79, 0x9c, 0x49, 0xbd, 0x6f, 0xa6, 0x83, 0x24, 0x4c, 0x95, 0xbe, 0x79, 0xee, 0xa2,
];
#[cfg(target_arch = "riscv32")]
const CONST_ZERO: [u8; 32] = [0; 32];
#[cfg(target_arch = "riscv32")]
const CONST_ONE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
#[cfg(target_arch = "riscv32")]
const P256_MONT_PARAM_N: [u32; 2] = [0xccd1_c8aa, 0xee00_bc4f];
#[cfg(target_arch = "riscv32")]
const P256_MONT_PARAM_P: [u32; 2] = [0, 1];

#[cfg(target_arch = "riscv32")]
const PKE_WORK_LEN_256: u32 = 4;
#[cfg(target_arch = "riscv32")]
const PKE_SECTION_M: u32 = 0;
#[cfg(target_arch = "riscv32")]
const PKE_SECTION_CX: u32 = 3;
#[cfg(target_arch = "riscv32")]
const PKE_SECTION_CY: u32 = 6;
#[cfg(target_arch = "riscv32")]
const PKE_SECTION_AZ: u32 = 18;
#[cfg(target_arch = "riscv32")]
const PKE_SECTION_PX: u32 = 21;
#[cfg(target_arch = "riscv32")]
const PKE_SECTION_PY: u32 = 24;
#[cfg(target_arch = "riscv32")]
const PKE_SECTION_GX: u32 = 27;
#[cfg(target_arch = "riscv32")]
const PKE_SECTION_GY: u32 = 30;
#[cfg(target_arch = "riscv32")]
const PKE_SECTION_N: u32 = 57;

#[cfg(target_arch = "riscv32")]
const PKE_RSA_SECTION_N: u32 = 0;
#[cfg(target_arch = "riscv32")]
const PKE_RSA_SECTION_RR: u32 = 32;
#[cfg(target_arch = "riscv32")]
const PKE_RSA_SECTION_CONST_1: u32 = 48;
#[cfg(target_arch = "riscv32")]
const PKE_RSA_SECTION_RESULT: u32 = 64;
#[cfg(target_arch = "riscv32")]
const PKE_RSA_SECTION_T0: u32 = 96;
#[cfg(target_arch = "riscv32")]
const PKE_RSA_SECTION_T1: u32 = 112;
#[cfg(target_arch = "riscv32")]
const PKE_RSA_MOD_MUL_WORD_OFFSET: u32 = 326;
#[cfg(target_arch = "riscv32")]
const PKE_RSA_MOD_MUL_INSTRUCTION_COUNT: u32 = 6;

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct PkeEccCurve {
    p: *const u8,
    a: *const u8,
    b: *const u8,
    gx: *const u8,
    gy: *const u8,
    n: *const u8,
    h: u32,
    ksize: u32,
    ecc_type: u32,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct PkeEccInitParam {
    mont_a: *const u8,
    mont_b: *const u8,
    mont_1_p: *const u8,
    mont_1_n: *const u8,
    rrp: *const u8,
    rrn: *const u8,
    const_1: *const u8,
    const_0: *const u8,
    mont_param_n: *const u32,
    mont_param_p: *const u32,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct RomLib {
    instr_addr: u32,
    instr_num: u32,
}

/// Exclusive WS63 PKE capability.
///
/// Entropy remains a separate capability and is borrowed only while creating
/// a [`Ws63P256Session`]. This keeps `Ws63Crypto::new` from growing another
/// hardware token and makes the mixed suite explicit at the call site.
pub struct Ws63P256<'d> {
    _pke: Pke<'d>,
    #[cfg(target_arch = "riscv32")]
    busy: Cell<bool>,
}

impl<'d> Ws63P256<'d> {
    pub const fn new(pke: Pke<'d>) -> Self {
        Self {
            _pke: pke,
            #[cfg(target_arch = "riscv32")]
            busy: Cell::new(false),
        }
    }

    pub fn session<'a, R: EntropySource>(&'a self, entropy: &'a R) -> Ws63P256Session<'a, 'd, R> {
        Ws63P256Session {
            engine: self,
            entropy,
        }
    }

    #[cfg(target_arch = "riscv32")]
    fn enter(&self) -> Result<PkeBusyGuard<'_>, CryptoError> {
        if self.busy.replace(true) {
            Err(CryptoError::Backend(ERR_BUSY))
        } else {
            Ok(PkeBusyGuard { busy: &self.busy })
        }
    }

    #[cfg(target_arch = "riscv32")]
    fn point_mul_hardware<R: EntropySource>(
        &self,
        entropy: &R,
        point: &P256AffinePoint,
        scalar: &[u8; P256_ELEMENT_BYTES],
        output: &mut P256AffinePoint,
    ) -> Result<(), CryptoError> {
        let group = RustCryptoGroup19::for_group(GROUP_19)?;
        group.point_from_xy(&point.x, &point.y)?;
        if scalar.iter().all(|byte| *byte == 0) || scalar >= &P256_N {
            return Err(CryptoError::InvalidValue);
        }

        let _guard = self.enter()?;
        let mut mask_bytes = [0u8; 4];
        let mut mask = 0;
        for _ in 0..8 {
            entropy.fill_entropy(&mut mask_bytes)?;
            mask = u32::from_le_bytes(mask_bytes);
            if mask != 0 {
                break;
            }
        }
        mask_bytes.zeroize();
        if mask == 0 {
            return Err(CryptoError::Backend(ERR_MASK_ENTROPY));
        }

        let mut locked = false;
        let mut noise = false;
        let result = (|| {
            self.lock()?;
            locked = true;
            self.set_noise(true);
            noise = true;
            self.configure_mask(mask);
            self.load_curve()?;
            self.point_mul_sequence(point, scalar, output)
        })();

        let cleanup = self.cleanup(locked, noise);
        mask.zeroize();
        if result.is_err() {
            output.x.zeroize();
            output.y.zeroize();
        }
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        }
    }

    #[cfg(target_arch = "riscv32")]
    fn point_add_hardware<R: EntropySource>(
        &self,
        entropy: &R,
        a: &P256AffinePoint,
        b: &P256AffinePoint,
        output: &mut P256PointResult,
    ) -> Result<(), CryptoError> {
        let group = RustCryptoGroup19::for_group(GROUP_19)?;
        group.point_from_xy(&a.x, &a.y)?;
        group.point_from_xy(&b.x, &b.y)?;

        // The audited vendor add instruction handles distinct affine inputs;
        // doubling uses the already verified scalar-multiplication sequence.
        // Two validated P-256 points with equal x and different y are inverses.
        if a.x == b.x {
            if a.y != b.y {
                *output = P256PointResult::Infinity;
                return Ok(());
            }
            let mut scalar = [0u8; P256_ELEMENT_BYTES];
            scalar[P256_ELEMENT_BYTES - 1] = 2;
            let mut doubled =
                P256AffinePoint::new([0; P256_ELEMENT_BYTES], [0; P256_ELEMENT_BYTES]);
            let result = self.point_mul_hardware(entropy, a, &scalar, &mut doubled);
            scalar.zeroize();
            match result {
                Ok(()) => {
                    *output = P256PointResult::Affine(doubled);
                    return Ok(());
                }
                Err(error) => {
                    doubled.x.zeroize();
                    doubled.y.zeroize();
                    return Err(error);
                }
            }
        }

        let _guard = self.enter()?;
        let mut mask_bytes = [0u8; 4];
        let mut mask = 0;
        for _ in 0..8 {
            entropy.fill_entropy(&mut mask_bytes)?;
            mask = u32::from_le_bytes(mask_bytes);
            if mask != 0 {
                break;
            }
        }
        mask_bytes.zeroize();
        if mask == 0 {
            return Err(CryptoError::Backend(ERR_MASK_ENTROPY));
        }

        let mut locked = false;
        let mut noise = false;
        let result = (|| {
            self.lock()?;
            locked = true;
            self.set_noise(true);
            noise = true;
            self.configure_mask(mask);
            self.load_curve()?;
            self.point_add_sequence(a, b, output)
        })();

        let cleanup = self.cleanup(locked, noise);
        mask.zeroize();
        if result.is_err() {
            *output = P256PointResult::Infinity;
        }
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        }
    }

    #[cfg(target_arch = "riscv32")]
    fn field_mul_hardware<R: EntropySource>(
        &self,
        entropy: &R,
        a: &P256FieldElement,
        b: &P256FieldElement,
        output: &mut P256FieldElement,
    ) -> Result<(), CryptoError> {
        let _guard = self.enter()?;
        let mut mask_bytes = [0u8; 4];
        let mut mask = 0;
        for _ in 0..8 {
            entropy.fill_entropy(&mut mask_bytes)?;
            mask = u32::from_le_bytes(mask_bytes);
            if mask != 0 {
                break;
            }
        }
        mask_bytes.zeroize();
        if mask == 0 {
            return Err(CryptoError::Backend(ERR_MASK_ENTROPY));
        }

        let mut locked = false;
        let mut noise = false;
        let result = (|| {
            self.lock()?;
            locked = true;
            self.set_noise(true);
            noise = true;
            self.configure_mask(mask);
            self.field_mul_sequence(a, b, output)
        })();

        let cleanup = self.cleanup(locked, noise);
        mask.zeroize();
        if result.is_err() {
            *output = P256FieldElement::ZERO;
        }
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        }
    }

    #[cfg(target_arch = "riscv32")]
    fn configure_mask(&self, mask: u32) {
        let regs = self.regs();
        regs.pke_mask_rng_cfg()
            .write(|w| w.mask_rng_cfg().set_bit());
        regs.pke_dram_mask()
            // SAFETY: every 32-bit mask value is accepted by the PKE DRAM-mask
            // register; zero is rejected before reaching this function.
            .write(|w| unsafe { w.dram_mask().bits(mask) });
    }

    #[cfg(target_arch = "riscv32")]
    fn clear_mask(&self) {
        let regs = self.regs();
        regs.pke_dram_mask()
            // SAFETY: zero is the documented value that disables DRAM masking.
            .write(|w| unsafe { w.dram_mask().bits(0) });
        regs.pke_mask_rng_cfg()
            .write(|w| w.mask_rng_cfg().clear_bit());
    }

    #[cfg(target_arch = "riscv32")]
    fn lock(&self) -> Result<(), CryptoError> {
        let regs = self.regs();
        regs.pke_lock_ctrl()
            .write(|w| w.pke_lock_type().clear_bit().pke_lock().set_bit());
        for _ in 0..PKE_POLL_LIMIT {
            if regs.pke_lock_status().read().pke_lock_stat().bits() == PKE_ACPU_LOCK_CODE {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_LOCK_TIMEOUT))
    }

    #[cfg(target_arch = "riscv32")]
    fn unlock(&self) {
        self.regs()
            .pke_lock_ctrl()
            .write(|w| w.pke_lock_type().set_bit().pke_lock().set_bit());
    }

    #[cfg(target_arch = "riscv32")]
    fn set_noise(&self, enabled: bool) {
        self.regs().pke_noise_en().write(|w| {
            if enabled {
                w.noise_en().set_bit()
            } else {
                w.noise_en().clear_bit()
            }
        });
    }

    #[cfg(target_arch = "riscv32")]
    fn regs(&self) -> &'static ws63_pac::pke::RegisterBlock {
        // SAFETY: construction consumed the unique HAL PKE token and the
        // returned block is used only while this capability is borrowed.
        unsafe { &*Pke::ptr() }
    }

    #[cfg(target_arch = "riscv32")]
    fn load_curve(&self) -> Result<(), CryptoError> {
        let curve = p256_curve();
        let initial = p256_initial_parameters();
        let function: unsafe extern "C" fn(*const PkeEccInitParam, *const PkeEccCurve) -> i32 =
            // SAFETY: the address and RV32 C ABI signature come from the
            // vendor security ROM table for HAL_PKE_SET_ECC_PARAM.
            unsafe { core::mem::transmute(security::HAL_PKE_SET_ECC_PARAM) };
        // SAFETY: both C-layout parameter blocks and all pointers reachable
        // through them remain valid for the duration of the ROM call.
        rom_status(unsafe { function(&raw const initial, &raw const curve) })
    }

    #[cfg(target_arch = "riscv32")]
    fn point_mul_sequence(
        &self,
        point: &P256AffinePoint,
        scalar: &[u8; 32],
        output: &mut P256AffinePoint,
    ) -> Result<(), CryptoError> {
        self.select_prime_field()?;
        let (mut mont_x, mut mont_y) = self.montgomery_affine(point)?;

        self.set_ram(PKE_SECTION_PX, &mont_x);
        self.set_ram(PKE_SECTION_PY, &mont_y);
        self.set_ram(PKE_SECTION_M, &P256_P);
        self.batch(177, 3)?;
        self.batch(180, 2)?;

        let mut naf = [0i8; 257];
        let naf_len = scalar_to_naf(scalar, &mut naf);
        for digit in naf[..naf_len.saturating_sub(1)].iter().rev() {
            match digit {
                1 => self.batch(0, 40)?,
                -1 => self.batch(40, 40)?,
                _ => self.batch(0, 22)?,
            }
        }
        naf.zeroize();
        mont_x.zeroize();
        mont_y.zeroize();

        self.jacobian_to_affine()?;
        self.batch(165, 6)?;
        self.get_ram(PKE_SECTION_CX, &mut output.x);
        self.get_ram(PKE_SECTION_CY, &mut output.y);

        let group = RustCryptoGroup19::for_group(GROUP_19)?;
        group.point_from_xy(&output.x, &output.y)?;
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    fn point_add_sequence(
        &self,
        a: &P256AffinePoint,
        b: &P256AffinePoint,
        output: &mut P256PointResult,
    ) -> Result<(), CryptoError> {
        self.select_prime_field()?;
        let (mut a_x, mut a_y) = self.montgomery_affine(a)?;
        let (mut b_x, mut b_y) = self.montgomery_affine(b)?;

        self.set_ram(PKE_SECTION_PX, &a_x);
        self.set_ram(PKE_SECTION_PY, &a_y);
        self.set_ram(PKE_SECTION_GX, &b_x);
        self.set_ram(PKE_SECTION_GY, &b_y);
        self.batch(125, 18)?;

        let mut z = [0u8; P256_ELEMENT_BYTES];
        self.get_ram(PKE_SECTION_AZ, &mut z);
        if z.iter().all(|byte| *byte == 0) {
            *output = P256PointResult::Infinity;
            a_x.zeroize();
            a_y.zeroize();
            b_x.zeroize();
            b_y.zeroize();
            z.zeroize();
            return Ok(());
        }
        z.zeroize();

        // The add instruction leaves A in Jacobian form. Move it into the C
        // workspace consumed by the shared Jacobian-to-affine sequence.
        self.batch(182, 3)?;
        self.jacobian_to_affine()?;
        self.batch(165, 6)?;

        let mut affine = P256AffinePoint::new([0; P256_ELEMENT_BYTES], [0; P256_ELEMENT_BYTES]);
        self.get_ram(PKE_SECTION_CX, &mut affine.x);
        self.get_ram(PKE_SECTION_CY, &mut affine.y);
        let group = RustCryptoGroup19::for_group(GROUP_19)?;
        let validation = group.point_from_xy(&affine.x, &affine.y);

        a_x.zeroize();
        a_y.zeroize();
        b_x.zeroize();
        b_y.zeroize();
        validation?;
        *output = P256PointResult::Affine(affine);
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    fn field_mul_sequence(
        &self,
        a: &P256FieldElement,
        b: &P256FieldElement,
        output: &mut P256FieldElement,
    ) -> Result<(), CryptoError> {
        self.set_montgomery_parameter(P256_MONT_PARAM_P[1], P256_MONT_PARAM_P[0])?;
        self.set_ram(PKE_RSA_SECTION_N, &P256_P);
        // `update_rsa_modulus()` in the vendor driver computes and writes this
        // section before invoking `instr_rsa_mod_mul`. The first two ROM
        // instructions consume R^2 to transform both operands to Montgomery
        // form, so a fixed-prime adapter must reproduce that indirect side
        // effect explicitly.
        self.set_ram(PKE_RSA_SECTION_RR, &P256_RRP);
        self.set_ram(PKE_RSA_SECTION_T0, a.as_be_bytes());
        self.set_ram(PKE_RSA_SECTION_T1, b.as_be_bytes());
        self.set_ram(PKE_RSA_SECTION_CONST_1, &CONST_ONE);
        self.batch(
            PKE_RSA_MOD_MUL_WORD_OFFSET,
            PKE_RSA_MOD_MUL_INSTRUCTION_COUNT,
        )?;

        let mut encoded = [0u8; P256_ELEMENT_BYTES];
        self.get_ram(PKE_RSA_SECTION_RESULT, &mut encoded);
        let result = P256FieldElement::try_from_be_bytes(encoded);
        encoded.zeroize();
        match result {
            Ok(result) => {
                *output = result;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(target_arch = "riscv32")]
    fn select_prime_field(&self) -> Result<(), CryptoError> {
        self.set_ram(PKE_SECTION_N, &P256_P);
        self.batch(197, 1)?;
        self.set_montgomery_parameter(P256_MONT_PARAM_P[1], P256_MONT_PARAM_P[0])
    }

    #[cfg(target_arch = "riscv32")]
    fn montgomery_affine(
        &self,
        point: &P256AffinePoint,
    ) -> Result<([u8; P256_ELEMENT_BYTES], [u8; P256_ELEMENT_BYTES]), CryptoError> {
        self.set_ram(PKE_SECTION_PX, &point.x);
        self.set_ram(PKE_SECTION_PY, &point.y);
        self.set_ram(PKE_SECTION_M, &P256_P);
        self.batch(163, 2)?;
        let mut x = [0u8; P256_ELEMENT_BYTES];
        let mut y = [0u8; P256_ELEMENT_BYTES];
        // `instr_ecfp_mont_p_2` transforms P in place. CX/CY are populated
        // only by a subsequent affine-to-Jacobian instruction.
        self.get_ram(PKE_SECTION_PX, &mut x);
        self.get_ram(PKE_SECTION_PY, &mut y);
        Ok((x, y))
    }

    #[cfg(target_arch = "riscv32")]
    fn jacobian_to_affine(&self) -> Result<(), CryptoError> {
        self.batch(143, 5)?;
        let mut exponent = P256_P;
        subtract_one(&mut exponent);
        subtract_one(&mut exponent);
        let mut started = false;
        for byte in exponent {
            for shift in [6, 4, 2, 0] {
                let pair = (byte >> shift) & 0x3;
                if !started && pair == 0 {
                    continue;
                }
                started = true;
                match pair {
                    0 => self.batch(148, 2)?,
                    1 => self.batch(148, 3)?,
                    2 => self.batch(151, 3)?,
                    _ => self.batch(154, 3)?,
                }
            }
        }
        self.batch(157, 4)
    }

    #[cfg(target_arch = "riscv32")]
    fn batch(&self, word_offset: u32, instruction_count: u32) -> Result<(), CryptoError> {
        let block = RomLib {
            instr_addr: security::PKE_INSTRUCTION_ROM_START as u32 + word_offset * 4,
            instr_num: instruction_count,
        };
        let regs = self.regs();
        // SAFETY: work length 4 is the documented 256-bit PKE encoding.
        regs.pke_work_len()
            .write(|w| unsafe { w.work_len().bits(PKE_WORK_LEN_256) });
        let mut ready = false;
        for _ in 0..PKE_POLL_LIMIT {
            if regs.pke_instr_rdy().read().batch_instr_rdy().bit_is_set() {
                ready = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ready {
            return Err(CryptoError::Backend(ERR_INSTR_READY_TIMEOUT));
        }
        // SAFETY: the immutable instruction-ROM address is 32-bit aligned and
        // `instr_num * 4` is the exact byte length of the audited batch.
        regs.pke_instr_addr_low()
            .write(|w| unsafe { w.instr_addr_low().bits(block.instr_addr) });
        regs.pke_instr_addr_hig()
            // SAFETY: WS63 exposes a 32-bit PKE instruction-ROM address space.
            .write(|w| unsafe { w.instr_addr_hig().bits(0) });
        regs.pke_instr_len()
            // SAFETY: the audited instruction count cannot overflow this field.
            .write(|w| unsafe { w.instr_len().bits(block.instr_num * 4) });

        // Clear the old completion latch before starting the next batch.
        regs.pke_int_nomask_status()
            // SAFETY: one is the documented W1C request for the finish latch.
            .write(|w| unsafe { w.finish_int_nomask().bits(1) });
        // SAFETY: 0x5AA is the vendor-defined PKE batch-start command.
        regs.pke_start()
            .write(|w| unsafe { w.bits(u32::from(PKE_BATCH_START_CODE)) });
        for _ in 0..PKE_POLL_LIMIT {
            if regs.pke_busy().read().pke_busy().bit_is_clear() {
                let status = regs
                    .pke_int_nomask_status()
                    .read()
                    .finish_int_nomask()
                    .bits();
                if status != PKE_FINISH_CODE {
                    return Err(CryptoError::Backend(ERR_FINISH_STATUS));
                }
                regs.pke_int_nomask_status()
                    // SAFETY: writing the observed finish code clears the latch.
                    .write(|w| unsafe { w.finish_int_nomask().bits(PKE_FINISH_CODE) });
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_OPERATION_TIMEOUT))
    }

    #[cfg(target_arch = "riscv32")]
    fn set_ram(&self, section: u32, data: &[u8; 32]) {
        let function: unsafe extern "C" fn(u32, *const u8, u32, u32) =
            // SAFETY: the address and four-argument RV32 C ABI signature come
            // from the vendor security ROM table for HAL_PKE_SET_RAM.
            unsafe { core::mem::transmute(security::HAL_PKE_SET_RAM) };
        // SAFETY: `data` is readable for both reported lengths and the ROM call
        // is synchronous, so the pointer cannot outlive the borrowed array.
        unsafe { function(section, data.as_ptr(), data.len() as u32, data.len() as u32) };
    }

    #[cfg(target_arch = "riscv32")]
    fn get_ram(&self, section: u32, data: &mut [u8; 32]) {
        let function: unsafe extern "C" fn(u32, *mut u8, u32) =
            // SAFETY: the address and three-argument RV32 C ABI signature come
            // from the vendor security ROM table for HAL_PKE_GET_RAM.
            unsafe { core::mem::transmute(security::HAL_PKE_GET_RAM) };
        // SAFETY: `data` is writable for the reported length and remains
        // exclusively borrowed for the synchronous ROM call.
        unsafe { function(section, data.as_mut_ptr(), data.len() as u32) };
    }

    #[cfg(target_arch = "riscv32")]
    fn set_montgomery_parameter(&self, low: u32, high: u32) -> Result<(), CryptoError> {
        let regs = self.regs();
        // SAFETY: Montgomery parameters are full-width register values derived
        // from the pinned P-256 vendor curve constants.
        regs.pke_mont_para0()
            .write(|w| unsafe { w.mont_para0().bits(low) });
        regs.pke_mont_para1()
            // SAFETY: this is the second full-width word of the same parameter.
            .write(|w| unsafe { w.mont_para1().bits(high) });
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    fn cleanup(&self, locked: bool, noise: bool) -> Result<(), CryptoError> {
        let mut cleanup_error = None;
        if locked {
            if let Err(error) = self.clean_ram() {
                cleanup_error = Some(error);
            }
            self.clear_mask();
        }
        if noise {
            self.set_noise(false);
        }
        if locked {
            self.unlock();
        }
        cleanup_error.map_or(Ok(()), Err)
    }

    #[cfg(target_arch = "riscv32")]
    fn clean_ram(&self) -> Result<(), CryptoError> {
        let regs = self.regs();
        regs.pke_dram_clr().write(|w| w.dram_clr().set_bit());
        for _ in 0..PKE_POLL_LIMIT {
            if regs.pke_busy().read().pke_busy().bit_is_clear() {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(CryptoError::Backend(ERR_OPERATION_TIMEOUT))
    }
}

pub struct Ws63P256Session<'a, 'd, R> {
    engine: &'a Ws63P256<'d>,
    entropy: &'a R,
}

impl<R: EntropySource> TryP256PointMul for Ws63P256Session<'_, '_, R> {
    fn point_mul(
        &self,
        point: &P256AffinePoint,
        scalar: &[u8; P256_ELEMENT_BYTES],
        output: &mut P256AffinePoint,
    ) -> Result<(), CryptoError> {
        #[cfg(target_arch = "riscv32")]
        {
            self.engine
                .point_mul_hardware(self.entropy, point, scalar, output)
        }
        #[cfg(not(target_arch = "riscv32"))]
        {
            let _ = (self.engine, self.entropy, point, scalar, output);
            Err(CryptoError::Unsupported)
        }
    }
}

impl<R: EntropySource> TryP256PointAdd for Ws63P256Session<'_, '_, R> {
    fn point_add(
        &self,
        a: &P256AffinePoint,
        b: &P256AffinePoint,
        output: &mut P256PointResult,
    ) -> Result<(), CryptoError> {
        #[cfg(target_arch = "riscv32")]
        {
            self.engine.point_add_hardware(self.entropy, a, b, output)
        }
        #[cfg(not(target_arch = "riscv32"))]
        {
            let _ = (self.engine, self.entropy, a, b, output);
            Err(CryptoError::Unsupported)
        }
    }
}

impl<R: EntropySource> TryP256FieldMul for Ws63P256Session<'_, '_, R> {
    fn field_mul(
        &self,
        a: &P256FieldElement,
        b: &P256FieldElement,
        output: &mut P256FieldElement,
    ) -> Result<(), CryptoError> {
        #[cfg(target_arch = "riscv32")]
        {
            self.engine.field_mul_hardware(self.entropy, a, b, output)
        }
        #[cfg(not(target_arch = "riscv32"))]
        {
            let _ = (self.engine, self.entropy, a, b, output);
            Err(CryptoError::Unsupported)
        }
    }
}

#[cfg(target_arch = "riscv32")]
struct PkeBusyGuard<'a> {
    busy: &'a Cell<bool>,
}

#[cfg(target_arch = "riscv32")]
impl Drop for PkeBusyGuard<'_> {
    fn drop(&mut self) {
        self.busy.set(false);
    }
}

#[cfg(target_arch = "riscv32")]
fn p256_curve() -> PkeEccCurve {
    PkeEccCurve {
        p: P256_P.as_ptr(),
        a: P256_A.as_ptr(),
        b: P256_B.as_ptr(),
        gx: P256_GX.as_ptr(),
        gy: P256_GY.as_ptr(),
        n: P256_N.as_ptr(),
        h: 1,
        ksize: 32,
        ecc_type: 6,
    }
}

#[cfg(target_arch = "riscv32")]
fn p256_initial_parameters() -> PkeEccInitParam {
    PkeEccInitParam {
        mont_a: P256_MONT_A.as_ptr(),
        mont_b: P256_MONT_B.as_ptr(),
        mont_1_p: P256_MONT_1_P.as_ptr(),
        mont_1_n: P256_MONT_1_N.as_ptr(),
        rrp: P256_RRP.as_ptr(),
        rrn: P256_RRN.as_ptr(),
        const_1: CONST_ONE.as_ptr(),
        const_0: CONST_ZERO.as_ptr(),
        mont_param_n: P256_MONT_PARAM_N.as_ptr(),
        mont_param_p: P256_MONT_PARAM_P.as_ptr(),
    }
}

#[cfg(any(test, target_arch = "riscv32"))]
fn scalar_to_naf(scalar: &[u8; 32], output: &mut [i8; 257]) -> usize {
    let mut value = [0u8; 33];
    value[1..].copy_from_slice(scalar);
    let mut count = 0;
    while value.iter().any(|byte| *byte != 0) {
        let digit = if value[32] & 1 == 1 {
            2 - i8::try_from(value[32] & 3).unwrap_or(0)
        } else {
            0
        };
        output[count] = digit;
        match digit {
            1 => subtract_one(&mut value),
            -1 => add_one(&mut value),
            _ => {}
        }
        shift_right_one(&mut value);
        count += 1;
    }
    value.zeroize();
    count
}

#[cfg(any(test, target_arch = "riscv32"))]
fn add_one(value: &mut [u8]) {
    for byte in value.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            return;
        }
    }
}

#[cfg(any(test, target_arch = "riscv32"))]
fn subtract_one(value: &mut [u8]) {
    for byte in value.iter_mut().rev() {
        let (next, borrow) = byte.overflowing_sub(1);
        *byte = next;
        if !borrow {
            return;
        }
    }
}

#[cfg(any(test, target_arch = "riscv32"))]
fn shift_right_one(value: &mut [u8]) {
    let mut carry = 0;
    for byte in value {
        let next = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = next;
    }
}

#[cfg(target_arch = "riscv32")]
fn rom_status(status: i32) -> Result<(), CryptoError> {
    if status == 0 {
        Ok(())
    } else {
        Err(CryptoError::Backend(status as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn naf_round_trips_representative_scalars() {
        for scalar in [1u32, 2, 3, 7, 15, 0x8000_0001, u32::MAX] {
            let mut bytes = [0u8; 32];
            bytes[28..].copy_from_slice(&scalar.to_be_bytes());
            let mut digits = [0i8; 257];
            let length = scalar_to_naf(&bytes, &mut digits);
            let mut reconstructed = 0i64;
            for digit in digits[..length].iter().rev() {
                reconstructed = reconstructed * 2 + i64::from(*digit);
            }
            assert_eq!(reconstructed as u64, u64::from(scalar));
            assert!(digits[..length].iter().all(|digit| matches!(digit, -1..=1)));
        }
    }

    #[test]
    fn p256_constants_match_group_19() {
        let group = RustCryptoGroup19::for_group(GROUP_19).unwrap();
        let generator = group.generator();
        let (x, y) = group.point_to_xy(&generator).unwrap();
        assert_eq!(x, P256_GX);
        assert_eq!(y, P256_GY);
        assert_eq!(P256_P, P256_FIELD_PRIME);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn vendor_abi_layout_matches_rv32() {
        assert_eq!(core::mem::size_of::<PkeEccCurve>(), 36);
        assert_eq!(core::mem::size_of::<PkeEccInitParam>(), 40);
        assert_eq!(core::mem::size_of::<RomLib>(), 8);
    }
}
