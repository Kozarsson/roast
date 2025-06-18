//! ROAST Signer
//!
//! Manage a FROST key in order to send nonces and signature shares upon request from a ROAST coordinator.
use std::collections::BTreeMap;

use frost_ed25519::keys::{SecretShare};
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Identifier};
use frost_ed25519::round1::{SigningCommitments, SigningNonces};
use old_rand::{CryptoRng, RngCore};

use crate::threshold_scheme::ThresholdScheme;

pub struct RoastSigner<'a, S: ThresholdScheme<K>, K: Clone> {
    threshold_scheme: S,
    joint_key: K,
    my_index: Identifier,
    secret_share: SecretShare,
    message: &'a [u8],
    my_nonces: Vec<SigningNonces>,
}

impl<'a, S: ThresholdScheme<K> + Clone, K: Clone> RoastSigner<'a, S, K> {
    /// Create a new [`RoastSigner`] session for a particular message
    ///
    /// A new [`RoastSigner`] should be created for each message the group wants to sign.
    /// The frost protocol instance's noncegen (NG) will be used to generate nonces.
    /// This noncegen must be chosen carefully (including between sessions) to ensure
    /// that nonces are never reused. See *[secp256kfun FROST]* for more info.
    ///
    /// [secp256kfun FROST]: <https://docs.rs/schnorr_fun/latest/schnorr_fun/frost/index.html>
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

    /// Create a new nonce using the [`Frost`]'s internal noncegen
    // pub fn new_nonce(&mut self, nonce_rng: &mut (impl RngCore + CryptoRng)) -> SigningKey {
    //     let nonce = self.threshold_scheme.gen_nonce(nonce_rng);
    //     self.my_nonces.push(nonce.clone());
    //     nonce
    // }

    /// Sign the message with a nonce set
    ///
    /// Also generates a new nonce to share and use for the next signing round
    pub fn sign(
        &mut self,
        nonce_rng: &mut (impl RngCore + CryptoRng),
        commitments_map: BTreeMap<Identifier,SigningCommitments>,
    ) -> (SignatureShare, SigningCommitments) {
        let my_nonce = self
            .my_nonces
            .pop()
            .expect("some nonce available for signing");
        // let sig = self.threshold_scheme.sign(
        //     self.joint_key.clone(),
        //     nonce_set,
        //     self.my_index,
        //     &self.secret_share,
        //     my_nonce,
        //     self.message,
        // );
         let key_package = &frost_ed25519::keys::KeyPackage::try_from(self.secret_share.clone()).unwrap();
 
         let signing_package = frost_ed25519::SigningPackage::new(commitments_map, self.message.clone());
 
         let signature_share = frost_ed25519::round2::sign(&signing_package, &my_nonce, &key_package)
             .expect("signature share creation failed");

        let key_package = &frost_ed25519::keys::KeyPackage::try_from(self.secret_share.clone()).unwrap();
        let (nonce, commitments) = frost_ed25519::round1::commit(key_package.signing_share(), nonce_rng);
        //let nonce = self.new_nonce(nonce_rng);
        self.my_nonces.push(nonce.clone());
        (signature_share, commitments)
    }
}