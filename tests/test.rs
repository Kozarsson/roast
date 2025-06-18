#[cfg(feature = "frost")]
mod tests {
    use std::collections::BTreeMap;

    use frost_ed25519::round1::SigningCommitments;
    use frost_ed25519::Identifier;
    use frost_ed25519::Signature;

    use roast::coordinator;
    use roast::signer;
    use roast::frost::Frost;
    use roast::signer::RoastSigner;

    #[test]
    fn test_t_of_n_basic() {
        let frost = Frost::new();
        let mut rng = old_rand::thread_rng();

        let n = 7;
        let t = 5;

        let (shares, pubkey_package) = frost_ed25519::keys::generate_with_dealer(
            n,
            t,
            frost_ed25519::keys::IdentifierList::Default,
            &mut rng,
        ).unwrap();
        //let (pubkey_package, secret_shares) = frost.simulate_keygen(2, 3, &mut rng);
        println!("key generated");

        let message = b"test message";
        let roast = coordinator::Coordinator::new(frost, pubkey_package.clone(), message, t as usize, n as usize);

        let mut signers: BTreeMap<Identifier,RoastSigner<_,_>> = BTreeMap::new();
        let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for (identifier, secret_share) in shares {
            let (signer, commitment) = signer::RoastSigner::new(
                &mut rng,
                Frost::new(),
                pubkey_package.clone(),
                identifier,
                secret_share,
                message,
            );
            signers.insert(identifier, signer);
            commitments.insert(identifier, commitment);
        }
        
        let mut received_nonces: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        let mut nonce_response: Option<BTreeMap<Identifier, SigningCommitments>> = None;
        
        for (id, commitment) in &commitments {
            let response = roast.receive(*id, None, commitment.clone()).unwrap();
        
            if let Some(nonce_set) = response.nonce_set.clone() {
                nonce_response = Some(nonce_set);
            }
        }
        
        let sign_session_nonces = nonce_response.expect("Did not receive enough nonces");

        let mut final_signature: Option<Signature> = None;
        
        for (id, signer) in &mut signers {
            if !sign_session_nonces.iter().any(|(i, _)| i == id) {
                continue; 
            }
        
            let (sig_share, new_nonce) = signer.sign(&mut rng, sign_session_nonces.clone());
            println!("make partial sig {:?}",id);
            let response = roast.receive(*id, Some(sig_share), new_nonce).unwrap();
        
            if let Some(sig) = response.combined_signature {
                final_signature = Some(sig);
                break;
            }
        }
        
        let final_sig = final_signature.expect("should have combined signature");
       assert!(pubkey_package.verifying_key().verify(message, &final_sig).is_ok());
        
    }

    // fn t_of_n_sequential(
    //     threshold: usize,
    //     n_parties: usize,
    //     n_malicious: usize,
    //     rng: &mut (impl RngCore + CryptoRng),
    // ) {
    //     println!(
    //         "Testing {}-of-{} with {} malicious:",
    //         threshold, n_parties, n_malicious
    //     );
    //     let frost = Frost::new();
    //     let (shares, pubkey_package) = frost::keys::generate_with_dealer(
    //         n_parties,
    //         threshold,
    //         frost::keys::IdentifierList::Default,
    //         &mut rng,
    //     )?;
    //    // let (pubkey_package, secret_shares) = frost.simulate_keygen(threshold, n_parties, rng);

    //     let message = b"test message";
    //     let roast = coordinator::Coordinator::new(
    //         frost,
    //         pubkey_package.clone(),
    //         message,
    //         threshold,
    //         n_parties,
    //     );

    //     // use a boolean mask for which participants are malicious
    //     let mut malicious_mask = vec![true; n_malicious];
    //     malicious_mask.append(&mut vec![false; n_parties - n_malicious]);
    //     // shuffle the mask for random signers
    //     malicious_mask.shuffle(rng);

    //     let malicious_indexes: Vec<_> = malicious_mask
    //         .iter()
    //         .enumerate()
    //         .filter(|(_, is_signer)| **is_signer)
    //         .map(|(i, _)| i)
    //         .collect();

    //     // Create each signer session and create an initial nonce
    //     let (mut signers, mut nonces): (Vec<_>, Vec<_>) = shares
    //         .into_iter()
    //         .enumerate()
    //         .map(|(i, share)| {
    //             signer::RoastSigner::new(
    //                 rng,
    //                 Frost::new(),
    //                 pubkey_package.clone(),
    //                 i,
    //                 share,
    //                 message,
    //             )
    //         })
    //         .unzip();

    //     let mut sig_shares = vec![];
    //     let mut nonce_set: Vec<Option<Vec<(usize, VerifyingKey)>>> = vec![None; n_parties + 1];
    //     let mut finished_signature = None;
    //     let mut n_rounds = 0;

    //     while finished_signature.is_none() {
    //         n_rounds += 1;
    //         for signer_index in 0..n_parties {
    //             // Check to see if this signer has recieved any nonces
    //             let (sig, new_nonce) = match nonce_set[signer_index].clone() {
    //                 // If the signer has a nonce shared, sign and send sig as well as a new nonce
    //                 Some(signing_nonces) => {
    //                     let (mut sig, nonce) = signers[signer_index].sign(rng, signing_nonces);
    //                     // If we are malcious, send a bogus signature to disrupt signing process
    //                     if malicious_indexes.contains(&signer_index) {
    //                         sig = SigningKey::generate(rng).sign(message);
    //                     }
    //                     (Some(sig), nonce)
    //                 }
    //                 // Otherwise, just create a new nonce
    //                 None => (None, signers[signer_index].new_nonce(rng).verifying_key()),
    //             };
    //             // Send signature and our next nonce to ROAST
    //             let response = roast.receive(signer_index, sig, new_nonce).unwrap();
    //             nonces[signer_index] = new_nonce;

    //             if response.combined_signature.is_some() {
    //                 finished_signature = response.combined_signature;
    //                 break;
    //             }

    //             for index in response.recipients {
    //                 nonce_set[index] = response.nonce_set.clone();
    //             }

    //             if sig.is_some() {
    //                 sig_shares.push(sig);
    //             }
    //         }
    //     }
    //     assert!(finished_signature.is_some());
    //     let final_sig = finished_signature.expect("should have combined signature");
    //     assert!(pubkey_package.verify(message, &final_sig).is_ok());
    // }

    // #[test]
    // fn roast_5_of_10_5_malicious() {
    //     let mut rng = OsRng;
    //     t_of_n_sequential(5, 10, 5, &mut rng);
    // }

    // #[test]
    // fn test_t_of_n_no_malicious() {
    //     let mut rng = OsRng;
    //     for n_parties in 2..6 {
    //         for threshold in 2..=n_parties {
    //             t_of_n_sequential(threshold, n_parties, 0, &mut rng);
    //         }
    //     }
    // }

    // #[test]
    // fn test_t_of_n_with_malicious() {
    //     let mut rng = OsRng;
    //     for n_parties in 2..6 {
    //         for threshold in 2..=n_parties {
    //             for n_malicious in 0..=(n_parties - threshold) {
    //                 t_of_n_sequential(threshold, n_parties, n_malicious, &mut rng);
    //             }
    //         }
    //     }
    // }
}