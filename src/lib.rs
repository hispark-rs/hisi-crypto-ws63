#![no_std]
#![doc = include_str!("../README.md")]

#[cfg(any(feature = "pbkdf2", feature = "hal-trng"))]
use hisi_crypto::CryptoError;
#[cfg(feature = "hal-trng")]
use hisi_crypto::EntropySource;
#[cfg(feature = "pbkdf2")]
use hisi_crypto::Pbkdf2HmacSha1;

#[cfg(feature = "hal-trng")]
use hisi_hal::{peripherals::Trng, trng::TrngDriver};

#[cfg(feature = "pbkdf2")]
const HMAC_SHA1: u32 = 0x10f6_90a0;

#[cfg(feature = "pbkdf2")]
#[repr(C)]
struct Pbkdf2Parameters {
    hash_type: u32,
    password: *mut u8,
    password_len: u32,
    salt: *mut u8,
    salt_len: u32,
    iterations: u16,
}

/// Exclusive access contract for the WS63 global cipher service.
///
/// The type is intentionally neither `Copy` nor constructible through a safe
/// API. A future HAL-backed constructor will consume dedicated cipher/TRNG
/// resources once those ownership tokens exist.
pub struct Ws63Crypto {
    _private: (),
}

/// Exclusive WS63 hardware entropy source backed by the HAL TRNG driver.
///
/// Construction consumes the unique TRNG peripheral token. This prevents a
/// second safe owner from racing the FIFO and avoids the implicit global UAPI
/// contract used by the legacy vendor runtime.
#[cfg(feature = "hal-trng")]
pub struct Ws63Entropy<'d> {
    driver: TrngDriver<'d>,
}

#[cfg(feature = "hal-trng")]
impl<'d> Ws63Entropy<'d> {
    /// Claim the WS63 TRNG peripheral through the HAL ownership model.
    pub fn new(trng: Trng<'d>) -> Self {
        Self {
            driver: TrngDriver::new(trng),
        }
    }
}

impl Ws63Crypto {
    /// Constructs the backend after the caller proves global exclusivity.
    ///
    /// # Safety
    ///
    /// Exactly one `Ws63Crypto` may exist in a firmware. The vendor cipher and
    /// TRNG services must be initialized, and no other runtime may use them
    /// concurrently outside the service's own serialization contract.
    pub const unsafe fn assume_exclusive() -> Self {
        Self { _private: () }
    }
}

#[cfg(feature = "pbkdf2")]
impl Pbkdf2HmacSha1 for Ws63Crypto {
    fn derive_32(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        if iterations == 0 {
            return Err(CryptoError::InvalidLength);
        }
        let password_len = u32::try_from(password.len()).map_err(|_| CryptoError::InvalidLength)?;
        let salt_len = u32::try_from(salt.len()).map_err(|_| CryptoError::InvalidLength)?;
        let parameters = Pbkdf2Parameters {
            hash_type: HMAC_SHA1,
            password: password.as_ptr().cast_mut(),
            password_len,
            salt: salt.as_ptr().cast_mut(),
            salt_len,
            iterations: u16::try_from(iterations).map_err(|_| CryptoError::InvalidLength)?,
        };

        #[cfg(target_arch = "riscv32")]
        {
            // SAFETY: slices keep every pointer valid for the synchronous UAPI
            // call; lengths match those allocations and `output` is 32 bytes.
            let result = unsafe {
                uapi_drv_cipher_pbkdf2(&parameters, output.as_mut_ptr(), output.len() as u32)
            };
            if result == 0 {
                Ok(())
            } else {
                Err(CryptoError::Backend(result))
            }
        }
        #[cfg(not(target_arch = "riscv32"))]
        {
            let _ = (parameters, output);
            Err(CryptoError::Unsupported)
        }
    }
}

#[cfg(feature = "hal-trng")]
impl EntropySource for Ws63Entropy<'_> {
    fn fill_entropy(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        self.driver
            .fill_bytes(output)
            .map_err(|_| CryptoError::Backend(0xffff_1001))
    }
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    #[cfg(feature = "pbkdf2")]
    fn uapi_drv_cipher_pbkdf2(
        parameters: *const Pbkdf2Parameters,
        output: *mut u8,
        output_len: u32,
    ) -> u32;
}

#[cfg(all(target_arch = "riscv32", feature = "pbkdf2"))]
const _: () = assert!(core::mem::size_of::<Pbkdf2Parameters>() == 24);

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "pbkdf2")]
    fn backend() -> Ws63Crypto {
        // SAFETY: each host test owns its local non-functional backend value.
        unsafe { Ws63Crypto::assume_exclusive() }
    }

    #[cfg(feature = "pbkdf2")]
    #[test]
    fn rejects_zero_and_oversized_iterations_before_uapi() {
        let mut output = [0; 32];
        assert_eq!(
            backend().derive_32(b"password", b"salt", 0, &mut output),
            Err(CryptoError::InvalidLength)
        );
        assert_eq!(
            backend().derive_32(b"password", b"salt", 65536, &mut output),
            Err(CryptoError::InvalidLength)
        );
    }
}
