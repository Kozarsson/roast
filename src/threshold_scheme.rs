use std::collections::BTreeMap;

use frost_ed25519::{
    Signature, Identifier,
    round1::SigningCommitments,
    round2::SignatureShare,
};

/// A trait for threshold signature schemes
pub trait ThresholdScheme<PK> {
    /// Generate a new nonce for signing
   // fn gen_nonce<R: RngCore + CryptoRng>(&self, nonce_rng: &mut R) -> SigningKey;

    /// Sign a message using a threshold signature scheme
    // fn sign(
    //     &self,
    //     joint_key: PK,
    //     nonces: Vec<(Identifier, VerifyingKey)>,
    //     my_identifier: Identifier,
    //     secret_share: &frost_ed25519::keys::SecretShare,
    //     secret_nonce: SigningNonces,
    //     message: &[u8],
    // ) -> SignatureShare;

    /// Verify a signature share
    fn verify_signature_share(
        &self,
        joint_key: PK,
        commitments: BTreeMap<Identifier, SigningCommitments>,
        signer_identifier: Identifier,
        signature_share: SignatureShare,
        message: &[u8],
    ) -> bool;

    /// Combine signature shares into a final signature
    fn combine_signature_shares(
        &self,
        joint_key: PK,
        commitments: BTreeMap<Identifier, SigningCommitments>,
        signature_shares: BTreeMap<Identifier, SignatureShare>,
        message: &[u8],
    ) -> Signature;
}