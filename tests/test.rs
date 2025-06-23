#[cfg(feature = "frost")]
mod tests {
    use std::collections::{BTreeMap,HashMap};
    use std:: sync ::Arc;
    use frost_ed25519::SigningPackage;
    use frost_ed25519::keys::IdentifierList;
    use rand::rngs::OsRng;  
    use rand::seq::SliceRandom;
    use roast::coordinator::RoastResponse;
    use roast::coordinator::{Coordinator, Req, Resp};
    use tokio::{sync::mpsc, task};

    use frost_ed25519::round1::SigningCommitments;
    use frost_ed25519::Identifier;
    use frost_ed25519::Signature;
    use frost_ed25519::round2::SignatureShare;
    use frost_ed25519::Ed25519Sha512;
    use frost_ed25519::Ed25519ScalarField;
    use frost_ed25519::Field;

    use roast::coordinator;
    use roast::signer;
    use roast::frost::Frost;
    use roast::signer::RoastSigner;

    async fn async_t_of_n_sequential(threshold: u16, n_parties: u16, n_malicious: u16) {
        let message = b"test message";
    
        let mut rng = OsRng;
        let frost = Frost::new();
        let (shares, pubkey_package) = frost_ed25519::keys::generate_with_dealer(
            n_parties, threshold, IdentifierList::Default, &mut rng,
        ).unwrap();
    
        // start Coordinator 
        let coord = Arc::new(Coordinator::new(frost.clone(), pubkey_package.clone(), message, threshold as usize, n_parties as usize));
        let (req_tx, req_rx) = mpsc::unbounded_channel::<Req>();
        let mut resp_txs: HashMap<Identifier, mpsc::UnboundedSender<Resp>> = HashMap::new();
        let mut resp_rxs: HashMap<Identifier, mpsc::UnboundedReceiver<Resp>> = HashMap::new();
        for ((id, _), _) in shares.iter().zip(0..) {
            let (tx, rx) = mpsc::unbounded_channel::<Resp>();
            resp_txs.insert(*id, tx);
            resp_rxs.insert(*id, rx);
        }
        let resp_txs = Arc::new(resp_txs);
        let (term_tx, _) = tokio::sync::broadcast::channel::<Signature>(1);
    
        // serve loop for coordinator
        {
            let coord = coord.clone();
            let resp_txs = resp_txs.clone();
            let term_tx = term_tx.clone();
            task::spawn(async move {
                coord.serve(req_rx, resp_txs,term_tx).await;
            });
        }
    
        // Prepare Signer instance and initial commitment
        let mut signer_map = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        let mut mask = vec![true; n_malicious as usize];
        mask.append(&mut vec![false; (n_parties - n_malicious) as usize]);
        mask.shuffle(&mut rng);
    
        for ((id, secret), byz) in shares.into_iter().zip(mask) {
            let (signer, commit) = RoastSigner::new(&mut rng, frost.clone(), pubkey_package.clone(), id, secret, message);
            signer_map.insert(id, (signer, byz));
            commitments.insert(id, commit);
        }
    
        //Start each signer in parallel
        let mut handles = Vec::new();
        for (id, (mut signer, is_byz)) in signer_map {
            let req_tx = req_tx.clone();
            let mut resp_rx = resp_rxs.remove(&id).unwrap();
            let pubkey = pubkey_package.clone();
            let msg = message.clone();
            let initial_commit = commitments[&id].clone();
            let term_tx_copy = term_tx.clone();
            let handle = task::spawn(async move {

                let mut term_rx = term_tx_copy.subscribe();
                req_tx.send((id, None, initial_commit)).unwrap();
                
                let mut pkg: SigningPackage = loop {
                    if let Some(Resp { recipients, nonce_set: Some(ns), .. }) = resp_rx.recv().await {
                        if recipients.contains(&id) {
                            break ns;
                        }
                    }
                };
    
                //  sigining session
                loop {
                    println!("make partial signature {:?}",&id);
                    let (share, new_commit) = signer.sign(&mut rng, pkg.clone());
                    let share_opt = Some(share.clone());
                    if is_byz{
                       // malicious behavior
                        type C = Ed25519Sha512; 
                        let random_scalar =
                            <<frost_ed25519::Ed25519Sha512 as frost_ed25519::Ciphersuite>::Group as frost_ed25519::Group>::Field::random(
                            &mut rng,
                        );
                        let scalar_bytes = Ed25519ScalarField::serialize(&random_scalar);
                        let sig_share = SignatureShare::deserialize(&scalar_bytes)
                        .expect("serialization/deserialization should succeed");
                        req_tx.send((id, Some(sig_share), new_commit)).unwrap();
                    }else{
                        req_tx.send((id, share_opt, new_commit)).unwrap();
                    }
                    tokio::select! {
                        Ok(sig) = term_rx.recv() => {
                            assert!(pubkey.verifying_key().verify(&msg, &sig).is_ok());
                                break;
                            }
                        maybe_resp = resp_rx.recv() => {
                            if let Some(Resp { recipients, nonce_set: Some(ns), combined_signature: _ , .. }) = maybe_resp {
                                    if recipients.contains(&id) {
                                        pkg = ns;
                                        continue;
                                }
                            }
                        }
                    }
                }
            });
            handles.push(handle);
        }
    
        for h in handles {
            h.await.unwrap();
        }
        println!("All sessions completed successfully");
    }
    

    #[test]
    fn roast_7_of_10_3_malicious() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async_t_of_n_sequential(7, 10, 3));
    }

 }
