use std::collections::BTreeMap;

use frost_ed25519::{
    Signature, Identifier,
    round1::SigningCommitments,
    round2::SignatureShare,
    keys::PublicKeyPackage,
};

use frost_core;
use crate::threshold_scheme::ThresholdScheme;

#[derive(Clone)]
pub struct Frost {
    // Add any necessary state here
}

impl Frost {
    pub fn new() -> Self {
        Self {}
    }

    // pub fn simulate_keygen<R: RngCore + CryptoRng>(
    //     &self,
    //     _threshold: usize,
    //     n_parties: usize,
    //     rng: &mut R,
    // ) -> (VerifyingKey, Vec<SigningKey>) {
    //     // Generate a random keypair for the joint key
    //     let joint_keypair = SigningKey::generate(rng);
    //     let joint_key = joint_keypair.verifying_key();

    //     // Generate secret shares using Shamir's Secret Sharing
    //     // This is a simplified version - in practice you'd want to use a proper
    //     // threshold secret sharing scheme
    //     let mut secret_shares = Vec::with_capacity(n_parties);
    //     for _ in 0..n_parties {
    //         secret_shares.push(SigningKey::generate(rng));
    //     }

    //     (joint_key, secret_shares)
    // }

    // Helper function to combine nonces
   // fn combine_nonces(nonces: &[(usize, VerifyingKey)]) -> VerifyingKey {
        // In a real implementation, you would properly combine the nonces
        // For now, we'll just return the first nonce
      //  nonces[0].1
   // }
}

impl ThresholdScheme<PublicKeyPackage> for Frost {
    // fn gen_nonce<R: RngCore + CryptoRng>(&self, nonce_rng: &mut R) -> SigningKey {
    //     SigningKey::generate(nonce_rng)
    // }

    // fn sign(
    //     &self,
    //     _joint_key: VerifyingKey,
    //     nonces: Vec<(usize, VerifyingKey)>,
    //     _my_index: usize,
    //     secret_share: &SecretShare,
    //     secret_nonce: SigningNonces,
    //     message: &[u8],
    // ) -> SignatureShare {
    //     // Combine nonces
    //    // let combined_nonce = Self::combine_nonces(&nonces);
        
    //     // Create a context that includes both the message and the combined nonce
    //     // let mut ctx = Sha512::new();
    //     // ctx.update(message);
    //     // ctx.update(combined_nonce.to_bytes());
    //     // let context = ctx.finalize();

    //     // Sign the context with the secret share
    //    // secret_share.sign(&context)
    //    let identifier = Identifier::try_from((my_index + 1) as u32)
    //    .expect("Invalid identifier (should be >= 1)");

    //     let mut commitments = std::collections::BTreeMap::new();
    //     commitments.insert(identifier, secret_nonce.commitments().clone());

    //     let signing_package = frost_ed25519::SigningPackage::new(commitments, message);

    //     let key_package = frost_ed25519::keys::KeyPackage::try_from(secret_share.clone())
    //         .expect("invalid secret share");

    //     frost_ed25519::round2::sign(&signing_package, &secret_nonce, &key_package)
    //         .expect("signature share creation failed")
    // }

    fn verify_signature_share(
        &self,
        joint_key: PublicKeyPackage,
        commitments: BTreeMap<Identifier, SigningCommitments>,
        signer_identifier: Identifier,
        signature_share: SignatureShare,
        message: &[u8],
    ) -> bool {
        let signing_package = frost_ed25519::SigningPackage::new(commitments, message);
        let verifying_key = joint_key.verifying_key();
        let verifying_share = joint_key.verifying_shares().get(&signer_identifier).unwrap();
        frost_core::verify_signature_share(signer_identifier,&verifying_share,&signature_share,&signing_package,&verifying_key).is_ok()
    }

    fn combine_signature_shares(
        &self,
        joint_key: PublicKeyPackage,
        commitments: BTreeMap<Identifier, SigningCommitments>,
        signature_shares: BTreeMap<Identifier, SignatureShare>,
        message: &[u8],
    ) -> Signature {
        // Create a signing package from the commitments and message
        let signing_package = frost_ed25519::SigningPackage::new(commitments, message);

        // Combine the signature shares
        frost_ed25519::aggregate(&signing_package, &signature_shares, &joint_key)
            .expect("Failed to combine signature shares")
    }
}
