use k256::{PublicKey, SecretKey};

pub use super::keypair::Keypair;

/// Represents different types of keys to be loaded into the Keycard
#[derive(Debug, Clone)]
pub enum KeyPair {
    /// Legacy keypair with optional public key and required private key
    Legacy {
        /// The public key (optional when loading)
        public_key: PublicKey,
        /// The private key
        private_key: SecretKey,
    },
    
    /// Extended keypair with optional public key, required private key, and chain code
    Extended {
        /// The public key (optional when loading)
        public_key: PublicKey,
        /// The private key
        private_key: SecretKey,
        /// The chain code (32 bytes)
        chain_code: [u8; 32],
    },
    
    /// BIP39 seed (64 bytes)
    Seed([u8; 64]),
}

impl KeyPair {
    /// Create a new legacy keypair
    pub fn new_legacy(public_key: PublicKey, private_key: SecretKey) -> Self {
        Self::Legacy {
            public_key,
            private_key,
        }
    }
    
    /// Create a new extended keypair
    pub fn new_extended(public_key: PublicKey, private_key: SecretKey, chain_code: [u8; 32]) -> Self {
        Self::Extended {
            public_key,
            private_key,
            chain_code,
        }
    }
    
    /// Create a new keypair from a BIP39 seed
    pub fn from_seed(seed: [u8; 64]) -> Self {
        Self::Seed(seed)
    }
}