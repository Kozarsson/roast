//! ROAST Coordinator (async + channels)

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::Arc,
};

use tokio::{sync::{RwLock, Mutex, mpsc::{UnboundedReceiver, UnboundedSender}, broadcast::{Sender as BroadcastSender}},task};
use frost_ed25519::{
    round1::SigningCommitments, round2::SignatureShare, Identifier, Signature, SigningPackage
};
use crate::{threshold_scheme::ThresholdScheme};

pub type Req = (Identifier, Option<SignatureShare>, SigningCommitments);
pub type Resp = RoastResponse;

pub struct Coordinator<'a, S, K> {
    pub threshold_scheme: S,
    pub pubkey_package: K,
    n_signers: usize,
    threshold: usize,
    state: Arc<RwLock<RoastState<'a>>>,
}

#[derive(Debug)]
pub struct RoastState<'a> {
    message: &'a [u8],
    responsive_signers: HashSet<Identifier>,
    malicious_signers: HashSet<Identifier>,
    session_counter: usize,
    latest_commitments: BTreeMap<Identifier, SigningCommitments>,
    sessions: HashMap<usize, Arc<Mutex<RoastSignSession>>>,
    signer_session_map: HashMap<Identifier, usize>,
}

#[derive(Debug)]
pub struct RoastSignSession {
    pub signers: HashSet<Identifier>,
    nonces: BTreeMap<Identifier, SigningCommitments>,
    sig_shares: BTreeMap<Identifier, SignatureShare>,
}

#[derive(Debug, Clone)]
pub struct RoastResponse {
    pub recipients: Vec<Identifier>,
    pub combined_signature: Option<Signature>,
    pub nonce_set: Option<SigningPackage>,
}

#[derive(Debug, Clone)]
pub enum RoastError {
    TooFewHonest,
}

impl fmt::Display for RoastError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Too few honest signers")
    }
}

impl<'a, S: ThresholdScheme<K> + Send + Sync + 'static, K: Clone + Send + Sync + 'static> Coordinator<'a, S, K> {
    pub fn new(
        threshold_scheme: S,
        pubkey_package: K,
        message: &'a [u8],
        threshold: usize,
        n_signers: usize,
    ) -> Self {
        let state = RoastState {
            message,
            responsive_signers: HashSet::new(),
            malicious_signers: HashSet::new(),
            latest_commitments: BTreeMap::new(),
            sessions: HashMap::new(),
            signer_session_map: HashMap::new(),
            session_counter: 0,
        };
        Self {
            threshold_scheme,
            pubkey_package,
            n_signers,
            threshold,
            state: Arc::new(RwLock::new(state)),
        }
    }

    pub async fn receive(
        &self,
        index: Identifier,
        signature_share: Option<SignatureShare>,
        new_commitment: SigningCommitments,
    ) -> Result<RoastResponse, RoastError> {
        let mut st = self.state.write().await;

        if st.malicious_signers.contains(&index) {
            return Ok(RoastResponse {
                recipients: vec![index],
                combined_signature: None,
                nonce_set: None,
            });
        }

        // 2) unsolicited nonce → malicious
        if signature_share.is_none() && st.responsive_signers.contains(&index) {
            st.malicious_signers.insert(index);
            if st.malicious_signers.len() > self.n_signers - self.threshold {
                return Err(RoastError::TooFewHonest);
            }
            return Ok(RoastResponse {
                recipients: vec![index],
                combined_signature: None,
                nonce_set: None,
            });
        }

        if let Some(&sid) = st.signer_session_map.get(&index) {
            let nonces = {
                let sess = st.sessions.get(&sid).unwrap().lock().await;
                sess.nonces.clone()
            };
            println!(
                "Party {:?} sent partial signature for session {}",
                index, &sid
            );
            let share = signature_share.clone().expect("expected share");
            if !self.threshold_scheme.verify_signature_share(
                self.pubkey_package.clone(),
                nonces.clone(),
                index,
                share.clone(),
                st.message,
            ) {
                st.malicious_signers.insert(index);
                println!("mark as malicious node {:?} ",index);
                if st.malicious_signers.len() > self.n_signers - self.threshold {
                    return Err(RoastError::TooFewHonest);
                }
                return Ok(RoastResponse {
                    recipients: Vec::new(),
                    combined_signature: None,
                    nonce_set: None,
                });
            }
      
            let mut sess = st.sessions.get(&sid).unwrap().lock().await;
            sess.sig_shares.insert(index, share.clone());
            if sess.sig_shares.len() == self.threshold {
             
                let sig = self.threshold_scheme.combine_signature_shares(
                    self.pubkey_package.clone(),
                    nonces.clone(),
                    sess.sig_shares.clone(),
                    st.message,
                );
                return Ok(RoastResponse {
                    recipients: (0..self.n_signers)
                        .map(|i| Identifier::try_from((i + 1) as u16).unwrap())
                        .collect(),
                    combined_signature: Some(sig),
                    nonce_set: None,
                });
            }
        }


        st.latest_commitments.insert(index, new_commitment);
        st.responsive_signers.insert(index);
        println!("mark as responsive {:?}",index);

        if st.responsive_signers.len() >= self.threshold {
            st.session_counter += 1;
            let sid = st.session_counter;
            let nonces_map = std::mem::take(&mut st.latest_commitments);
            let signers: Vec<_> = st.responsive_signers.drain().collect();
            println!("We now have threshold number of responsive signers!");
            
            let session = Arc::new(Mutex::new(RoastSignSession {
                signers: signers.iter().cloned().collect(),
                nonces: nonces_map.clone(),
                sig_shares: BTreeMap::new(),
            }));
            for &id in &signers {
                st.signer_session_map.insert(id, sid);
            }
            st.sessions.insert(sid, session.clone());

            let pkg = SigningPackage::new(nonces_map, st.message.clone());
            return Ok(RoastResponse {
                recipients: signers.clone(),
                combined_signature: None,
                nonce_set: Some(pkg),
            });
        }

        Ok(RoastResponse {
            recipients: Vec::new(),
            combined_signature: None,
            nonce_set: None,
        })
    }

    pub async fn serve(
        self: Arc<Self>,
        mut req_rx: UnboundedReceiver<Req>,
        resp_txs: std::sync::Arc<std::collections::HashMap<Identifier, UnboundedSender<Resp>>>,
        term_tx: BroadcastSender<Signature>,
    ) {
        while let Some((id, share, commit)) = req_rx.recv().await {
            match self.receive(id, share, commit).await {
                Ok(resp) => {
                    if let Some(sig) = resp.combined_signature.clone() {
                            let _ = term_tx.send(sig);
                    }else{
                        for &rec in &resp.recipients {
                            if let Some(tx) = resp_txs.get(&rec) {
                                    let _ = tx.send(resp.clone());
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[Coordinator] {}", e);
                }
            }
        }
    }
}
