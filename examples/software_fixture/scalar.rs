//! Test-only scalar generation keeps the old nonzero rejection contract.
use age_plugin_tpm_wsl::invalid;
use p256::elliptic_curve::Generate;
use std::io;

pub(super) fn generate() -> io::Result<p256::SecretKey> {
    p256::NonZeroScalar::try_generate()
        .map(p256::SecretKey::from)
        .map_err(|_| invalid("fixture scalar generation failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::{TryCryptoRng, TryRng};

    /// Deterministic test input only; never used by the fixture executable.
    struct ScriptedRng {
        draws: usize,
        fail: bool,
    }
    impl TryRng for ScriptedRng {
        type Error = std::io::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("sampler must request full scalar bytes")
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("sampler must request full scalar bytes")
        }
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            self.draws += 1;
            if self.fail {
                return Err(std::io::Error::other("controlled RNG failure"));
            }
            output.fill(0);
            if self.draws > 1 {
                *output.last_mut().unwrap() = 1;
            }
            Ok(())
        }
    }
    impl TryCryptoRng for ScriptedRng {}

    #[test]
    fn library_nonzero_sampler_retries_zero_before_returning_a_fixture_key() {
        let mut rng = ScriptedRng {
            draws: 0,
            fail: false,
        };
        let scalar = p256::NonZeroScalar::try_generate_from_rng(&mut rng).unwrap();
        let private = p256::SecretKey::from(scalar);
        assert_eq!(rng.draws, 2);
        let bytes = private.to_bytes();
        assert!(bytes[..31].iter().all(|byte| *byte == 0));
        assert_eq!(bytes[31], 1);
        assert!(p256::SecretKey::from_slice(&bytes).is_ok());
    }

    #[test]
    fn nonzero_sampler_propagates_rng_failure_without_a_key() {
        let mut rng = ScriptedRng {
            draws: 0,
            fail: true,
        };
        let result = p256::NonZeroScalar::try_generate_from_rng(&mut rng);
        assert_eq!(result.unwrap_err().to_string(), "controlled RNG failure");
        assert_eq!(rng.draws, 1);
    }
}
