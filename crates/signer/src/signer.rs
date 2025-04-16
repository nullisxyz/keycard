use std::sync::Arc;

use alloy_consensus::SignableTransaction;
use alloy_network::{AnyNetwork, EthereumWallet, IntoWallet};
use alloy_primitives::{address, Address, ChainId, Signature, B256};
use alloy_signer::{sign_transaction_with_chain_id, Result, Signer};
use async_trait::async_trait;
use nexum_apdu_core::prelude::*;
use nexum_keycard::{KeyPath, Keycard, KeycardSCP};
use tokio::sync::Mutex;

// Temporary remove Debug derive since Keycard doesn't implement Debug
pub struct KeycardSigner<T>
where
    T: CardTransport,
{
    inner: Arc<Mutex<Keycard<CardExecutor<KeycardSCP<T>>>>>,
    pub(crate) chain_id: Option<ChainId>,
    pub(crate) address: Address,
}

impl<T> std::fmt::Debug for KeycardSigner<T>
where
    T: CardTransport,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeycardSigner")
            .field("chain_id", &self.chain_id)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl<T> KeycardSigner<T>
where
    T: CardTransport,
{
    pub fn new(keycard: Arc<Mutex<Keycard<CardExecutor<KeycardSCP<T>>>>>) -> Self {
        let address = address!("0xf888b1c80d40c08e53e4f3446ae2dac72fe0f31c");
        Self {
            inner: keycard,
            chain_id: None,
            address,
        }
    }
}

#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T> Signer for KeycardSigner<T>
where
    T: CardTransport,
{
    #[inline]
    async fn sign_hash(&self, data: &B256) -> Result<Signature> {
        // Convert the B256 to a byte slice for KeyCard's sign method
        let data_bytes: &[u8] = data.as_slice();
        
        // Get the keycard signature
        let keycard_signature = self.inner
            .lock()
            .await
            .sign(data_bytes, KeyPath::Current, None)
            .map_err(|e| alloy_signer::Error::Other(Box::new(e)))?;
            
        // Convert nexum_keycard::Signature to alloy_primitives::Signature
        // Extract the r, s, v components
        let r_bytes = keycard_signature.r();
        let s_bytes = keycard_signature.s();
        let v = keycard_signature.recid().recovery_byte();
        
        // Create an alloy_primitives::Signature from r, s, v
        let r = B256::from_slice(r_bytes);
        let s = B256::from_slice(s_bytes);
        
        // Create the signature with the components
        Ok(Signature::from_bytes_with_v(&[r.0, s.0, [v]].concat()).unwrap())
    }

    #[inline]
    fn address(&self) -> Address {
        self.address
    }

    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    #[inline]
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<T> alloy_network::TxSigner<Signature> for KeycardSigner<T>
where
    T: CardTransport,
{
    fn address(&self) -> Address {
        self.address
    }

    #[inline]
    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> Result<Signature> {
        sign_transaction_with_chain_id!(self, tx, self.sign_hash(&tx.signature_hash()).await)
    }
}

impl<T> IntoWallet for KeycardSigner<T>
where
    T: CardTransport + 'static,
{
    type NetworkWallet = EthereumWallet;

    fn into_wallet(self) -> Self::NetworkWallet {
        EthereumWallet::from(self)
    }
}

impl<T> IntoWallet<AnyNetwork> for KeycardSigner<T>
where
    T: CardTransport + 'static,
{
    type NetworkWallet = EthereumWallet;

    fn into_wallet(self) -> Self::NetworkWallet {
        EthereumWallet::from(self)
    }
}
