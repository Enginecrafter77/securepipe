use anyhow::anyhow;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurePipeMode {
    ENCRYPTING,
    DECRYPTING,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecurePipeConfig {
    pub mode: SecurePipeMode,
    pub use_compression: bool,
}

impl SecurePipeConfig {
    pub fn new(mode: SecurePipeMode, use_compression: bool) -> Self {
        Self {
            mode,
            use_compression,
        }
    }

    pub fn check_peer_compatible(
        &self,
        other_peer_config: &SecurePipeConfig,
    ) -> anyhow::Result<()> {
        if self.mode == other_peer_config.mode {
            return Err(anyhow!(match &self.mode {
                SecurePipeMode::ENCRYPTING => "Both peers running in encrypting mode.",
                SecurePipeMode::DECRYPTING => "Both peers running in decrypting mode.",
            }));
        }
        if self.use_compression && !other_peer_config.use_compression {
            return Err(anyhow!("Remote peer has not enabled compression"));
        }
        if !self.use_compression && other_peer_config.use_compression {
            return Err(anyhow!("Remote peer has requires compression"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::connection::config::{SecurePipeConfig, SecurePipeMode};

    #[test]
    fn test_compatible_enc2enc() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, false);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, false);
        assert!(cfg1.check_peer_compatible(&cfg2).is_err());
    }

    #[test]
    fn test_compatible_dec2dec() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, false);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, false);
        assert!(cfg1.check_peer_compatible(&cfg2).is_err());
    }

    #[test]
    fn test_compatible_enc2dec() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, false);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, false);
        assert!(cfg1.check_peer_compatible(&cfg2).is_ok());
    }

    #[test]
    fn test_compatible_dec2enc() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, false);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, false);
        assert!(cfg1.check_peer_compatible(&cfg2).is_ok());
    }

    #[test]
    fn test_compatible_zenc2zenc() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, true);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, true);
        assert!(cfg1.check_peer_compatible(&cfg2).is_err());
    }

    #[test]
    fn test_compatible_zdec2zdec() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, true);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, true);
        assert!(cfg1.check_peer_compatible(&cfg2).is_err());
    }

    #[test]
    fn test_compatible_zenc2zdec() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, true);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, true);
        assert!(cfg1.check_peer_compatible(&cfg2).is_ok());
    }

    #[test]
    fn test_compatible_zdec2zenc() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, true);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, true);
        assert!(cfg1.check_peer_compatible(&cfg2).is_ok());
    }

    #[test]
    fn test_compatible_zenc2dec() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, true);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, false);
        assert!(cfg1.check_peer_compatible(&cfg2).is_err());
    }

    #[test]
    fn test_compatible_enc2zdec() {
        let cfg1 = SecurePipeConfig::new(SecurePipeMode::ENCRYPTING, false);
        let cfg2 = SecurePipeConfig::new(SecurePipeMode::DECRYPTING, true);
        assert!(cfg1.check_peer_compatible(&cfg2).is_err());
    }
}
