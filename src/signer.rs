//! ROAST Signer
//!
//! Manage a FROST key in order to send nonces and signature shares upon request from a ROAST coordinator.
use std::collections::BTreeMap;

use frost_core::SigningPackage;
use frost_ed25519::keys::{SecretShare};
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Ed25519Sha512, Identifier};
use frost_ed25519::round1::{SigningCommitments, SigningNonces};
use frost_ed25519::rand_core::{CryptoRng, RngCore};


use crate::threshold_scheme::ThresholdScheme;

pub struct RoastSigner<'a, S: ThresholdScheme<K> + Send + Sync + 'static, K: Clone + Send + Sync + 'static> {
    threshold_scheme: S,
    joint_key: K,
    my_index: Identifier,
    secret_share: SecretShare,
    message: &'a [u8],
    my_nonces: Vec<SigningNonces>,
}

impl<'a, S: ThresholdScheme<K> + Clone + Send + Sync + 'static, K: Clone + Send + Sync + 'static> RoastSigner<'a, S, K> {
    pub fn new(
        nonce_rng: &mut (impl RngCore + CryptoRng),
        threshold_scheme: S,
        joint_key: K,
        my_index: Identifier,
        secret_share: SecretShare,
        message: &'a [u8],
    ) -> (RoastSigner<'a, S, K>, SigningCommitments) {
        //let initial_nonce = threshold_scheme.gen_nonce(nonce_rng);
        let key_package = &frost_ed25519::keys::KeyPackage::try_from(secret_share.clone()).unwrap();
        let (initial_nonce, commitments) = frost_ed25519::round1::commit(key_package.signing_share(), nonce_rng);
        let my_nonces = vec![initial_nonce.clone()];

        (
            RoastSigner {
                threshold_scheme,
                joint_key,
                my_index,
                secret_share,
                message,
                my_nonces,
            },
            commitments,
        )
    }

    pub fn sign(
        &mut self,
        nonce_rng: &mut (impl RngCore + CryptoRng),
        signing_package: SigningPackage<Ed25519Sha512>,
    ) -> (SignatureShare, SigningCommitments) {
        let my_nonce = self
            .my_nonces
            .pop()
            .expect("some nonce available for signing");
         let key_package = &frost_ed25519::keys::KeyPackage::try_from(self.secret_share.clone()).unwrap();
 
         let signature_share = frost_ed25519::round2::sign(&signing_package, &my_nonce, &key_package)
             .expect("signature share creation failed");

        let key_package = &frost_ed25519::keys::KeyPackage::try_from(self.secret_share.clone()).unwrap();
        let (nonce, commitments) = frost_ed25519::round1::commit(key_package.signing_share(), nonce_rng);
        self.my_nonces.push(nonce.clone());
        (signature_share, commitments)
    }
}
