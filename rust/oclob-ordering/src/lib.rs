//! Certificate-first total ordering for secret-shared orders.

#![forbid(unsafe_code)]

use oclob_core::application_crypto::{Signature, Signer, SigningKey, VerifyingKey};
use oclob_core::{Digest32, OrderCommitment};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const VOTE_DOMAIN: &[u8] = b"OCLOB:ORDER-VOTE:v2";
const CERTIFICATE_DOMAIN: &[u8] = b"OCLOB:ORDER-CERTIFICATE:v2";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteePolicy {
    pub nodes: usize,
    pub max_corrupt_nodes: usize,
    pub reconstruction_quorum: usize,
    pub ordering_quorum: usize,
    pub settlement_authorization_quorum: usize,
}

impl CommitteePolicy {
    pub const fn seven_node() -> Self {
        Self {
            nodes: 7,
            max_corrupt_nodes: 2,
            reconstruction_quorum: 3,
            ordering_quorum: 5,
            settlement_authorization_quorum: 3,
        }
    }

    pub fn validate(self) -> Result<(), OrderingError> {
        if self.nodes != 7
            || self.max_corrupt_nodes != 2
            || self.reconstruction_quorum != self.max_corrupt_nodes + 1
            || self.ordering_quorum <= 2 * self.max_corrupt_nodes
            || self.ordering_quorum > self.nodes
            || self.settlement_authorization_quorum != self.reconstruction_quorum
        {
            return Err(OrderingError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderVote {
    pub node_id: u16,
    pub statement_digest: Digest32,
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct OrderingNode {
    id: u16,
    key: SigningKey,
    voted: BTreeMap<u64, Digest32>,
}

impl OrderingNode {
    pub fn new(id: u16, key: SigningKey) -> Result<Self, OrderingError> {
        if id == 0 {
            return Err(OrderingError::InvalidNode);
        }
        Ok(Self {
            id,
            key,
            voted: BTreeMap::new(),
        })
    }

    pub const fn id(&self) -> u16 {
        self.id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    pub fn vote(
        &mut self,
        market_id: &str,
        sequence: u64,
        commitment: OrderCommitment,
        previous_certificate: Digest32,
        expires_at: u64,
        now: u64,
    ) -> Result<OrderVote, OrderingError> {
        if sequence == 0
            || market_id.is_empty()
            || market_id.len() > 64
            || commitment.0 == [0; 32]
            || (sequence == 1) != (previous_certificate == [0; 32])
            || now > expires_at
        {
            return Err(OrderingError::InvalidVote);
        }
        let statement = vote_digest(
            market_id,
            sequence,
            commitment,
            previous_certificate,
            expires_at,
        );
        if let Some(existing) = self.voted.get(&sequence) {
            if existing != &statement {
                return Err(OrderingError::Equivocation);
            }
        }
        let signature = self
            .key
            .try_sign(&statement)
            .map_err(|_| OrderingError::InvalidVote)?
            .to_bytes();
        self.voted.insert(sequence, statement);
        Ok(OrderVote {
            node_id: self.id,
            statement_digest: statement,
            signature,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderCertificate {
    pub market_id: String,
    pub sequence: u64,
    pub commitment: OrderCommitment,
    pub previous_certificate: Digest32,
    pub expires_at: u64,
    pub votes: Vec<OrderVote>,
}

impl OrderCertificate {
    pub fn digest(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(CERTIFICATE_DOMAIN);
        put_bytes(&mut hash, self.market_id.as_bytes());
        hash.update(self.sequence.to_be_bytes());
        hash.update(self.commitment.0);
        hash.update(self.previous_certificate);
        hash.update(self.expires_at.to_be_bytes());
        let mut votes = self.votes.iter().collect::<Vec<_>>();
        votes.sort_by_key(|vote| vote.node_id);
        for vote in votes {
            hash.update(vote.node_id.to_be_bytes());
            hash.update(vote.statement_digest);
            put_bytes(&mut hash, &vote.signature);
        }
        hash.finalize().into()
    }

    pub fn verify(
        &self,
        policy: CommitteePolicy,
        keys: &BTreeMap<u16, VerifyingKey>,
        now: u64,
    ) -> Result<(), OrderingError> {
        policy.validate()?;
        if self.sequence == 0
            || self.market_id.is_empty()
            || self.market_id.len() > 64
            || self.commitment.0 == [0; 32]
            || (self.sequence == 1) != (self.previous_certificate == [0; 32])
            || now > self.expires_at
        {
            return Err(OrderingError::InvalidVote);
        }
        if self.votes.len() < policy.ordering_quorum {
            return Err(OrderingError::InsufficientQuorum);
        }
        let wanted = vote_digest(
            &self.market_id,
            self.sequence,
            self.commitment,
            self.previous_certificate,
            self.expires_at,
        );
        let mut distinct = BTreeSet::new();
        for vote in &self.votes {
            if !distinct.insert(vote.node_id) || vote.statement_digest != wanted {
                return Err(OrderingError::InvalidVote);
            }
            let key = keys.get(&vote.node_id).ok_or(OrderingError::InvalidNode)?;
            let signature = Signature::try_from(vote.signature.as_slice())
                .map_err(|_| OrderingError::InvalidVote)?;
            key.verify_strict(&wanted, &signature)
                .map_err(|_| OrderingError::InvalidVote)?;
        }
        if distinct.len() < policy.ordering_quorum {
            return Err(OrderingError::InsufficientQuorum);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct OrderingCommittee {
    policy: CommitteePolicy,
    nodes: Vec<OrderingNode>,
    keys: BTreeMap<u16, VerifyingKey>,
    log: OrderingLog,
}

impl OrderingCommittee {
    pub fn deterministic_for_demo() -> Result<Self, OrderingError> {
        let policy = CommitteePolicy::seven_node();
        policy.validate()?;
        let nodes = (1..=policy.nodes)
            .map(|id| OrderingNode::new(id as u16, SigningKey::from_bytes(&[id as u8; 64])))
            .collect::<Result<Vec<_>, _>>()?;
        let keys = nodes
            .iter()
            .map(|node| (node.id(), node.verifying_key()))
            .collect();
        Ok(Self {
            policy,
            nodes,
            keys,
            log: OrderingLog::default(),
        })
    }

    pub fn certify(
        &mut self,
        market_id: &str,
        commitment: OrderCommitment,
        expires_at: u64,
        now: u64,
    ) -> Result<OrderCertificate, OrderingError> {
        if self.log.contains(commitment) {
            return Err(OrderingError::Replay);
        }
        let sequence = self.log.next_sequence();
        let previous = self.log.head();
        let votes = self
            .nodes
            .iter_mut()
            .take(self.policy.ordering_quorum)
            .map(|node| node.vote(market_id, sequence, commitment, previous, expires_at, now))
            .collect::<Result<Vec<_>, _>>()?;
        let certificate = OrderCertificate {
            market_id: market_id.to_owned(),
            sequence,
            commitment,
            previous_certificate: previous,
            expires_at,
            votes,
        };
        self.log
            .append(certificate.clone(), self.policy, &self.keys, now)?;
        Ok(certificate)
    }

    pub const fn policy(&self) -> CommitteePolicy {
        self.policy
    }

    pub fn transition_signers(&self) -> Vec<(u16, &SigningKey)> {
        self.nodes
            .iter()
            .map(|node| (node.id(), node.signing_key()))
            .collect()
    }

    pub fn verifying_keys(&self) -> BTreeMap<u16, VerifyingKey> {
        self.keys.clone()
    }
}

#[derive(Clone, Default)]
pub struct OrderingLog {
    certificates: Vec<OrderCertificate>,
    commitments: BTreeSet<OrderCommitment>,
}

impl OrderingLog {
    pub fn contains(&self, commitment: OrderCommitment) -> bool {
        self.commitments.contains(&commitment)
    }

    pub fn next_sequence(&self) -> u64 {
        self.certificates.len() as u64 + 1
    }

    pub fn head(&self) -> Digest32 {
        self.certificates
            .last()
            .map(OrderCertificate::digest)
            .unwrap_or([0; 32])
    }

    pub fn append(
        &mut self,
        certificate: OrderCertificate,
        policy: CommitteePolicy,
        keys: &BTreeMap<u16, VerifyingKey>,
        now: u64,
    ) -> Result<(), OrderingError> {
        certificate.verify(policy, keys, now)?;
        if certificate.sequence != self.next_sequence()
            || certificate.previous_certificate != self.head()
        {
            return Err(OrderingError::BrokenChain);
        }
        if !self.commitments.insert(certificate.commitment) {
            return Err(OrderingError::Replay);
        }
        self.certificates.push(certificate);
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum OrderingError {
    #[error("the OCLOB committee policy is not the frozen 7-node profile")]
    InvalidPolicy,
    #[error("unknown or invalid ordering node")]
    InvalidNode,
    #[error("invalid or expired order vote")]
    InvalidVote,
    #[error("the ordering quorum was not reached")]
    InsufficientQuorum,
    #[error("an orderer attempted to vote twice for different statements")]
    Equivocation,
    #[error("the certificate does not extend the current chain")]
    BrokenChain,
    #[error("the same order commitment was already ordered")]
    Replay,
}

pub fn vote_digest(
    market_id: &str,
    sequence: u64,
    commitment: OrderCommitment,
    previous_certificate: Digest32,
    expires_at: u64,
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(VOTE_DOMAIN);
    put_bytes(&mut hash, market_id.as_bytes());
    hash.update(sequence.to_be_bytes());
    hash.update(commitment.0);
    hash.update(previous_certificate);
    hash.update(expires_at.to_be_bytes());
    hash.finalize().into()
}

fn put_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_votes_extend_one_chain() {
        let mut committee = OrderingCommittee::deterministic_for_demo().unwrap();
        let first = committee
            .certify("JGB10Y-JPY", OrderCommitment([9; 32]), 2_000, 1_000)
            .unwrap();
        let second = committee
            .certify("JGB10Y-JPY", OrderCommitment([8; 32]), 2_000, 1_000)
            .unwrap();
        assert_eq!(first.votes.len(), 5);
        assert_eq!(second.previous_certificate, first.digest());
    }

    #[test]
    fn replay_is_rejected_before_it_can_poison_the_next_sequence() {
        let mut committee = OrderingCommittee::deterministic_for_demo().unwrap();
        let commitment = OrderCommitment([9; 32]);
        committee
            .certify("JGB10Y-JPY", commitment, 2_000, 1_000)
            .unwrap();
        assert!(matches!(
            committee.certify("JGB10Y-JPY", commitment, 2_000, 1_000),
            Err(OrderingError::Replay)
        ));
        let next = committee
            .certify("JGB10Y-JPY", OrderCommitment([8; 32]), 2_000, 1_000)
            .unwrap();
        assert_eq!(next.sequence, 2);
    }

    #[test]
    fn certificate_needs_five_distinct_valid_votes() {
        let mut committee = OrderingCommittee::deterministic_for_demo().unwrap();
        let certificate = committee
            .certify("JGB10Y-JPY", OrderCommitment([7; 32]), 2_000, 1_000)
            .unwrap();
        let keys = committee.verifying_keys();
        let mut insufficient = certificate.clone();
        insufficient.votes.truncate(4);
        assert_eq!(
            insufficient.verify(committee.policy(), &keys, 1_000),
            Err(OrderingError::InsufficientQuorum)
        );
        let mut corrupted = certificate;
        corrupted.votes[0].signature[0] ^= 1;
        assert_eq!(
            corrupted.verify(committee.policy(), &keys, 1_000),
            Err(OrderingError::InvalidVote)
        );
    }

    #[test]
    fn one_node_refuses_two_statements_for_one_sequence() {
        let mut node = OrderingNode::new(1, SigningKey::from_bytes(&[1; 64])).unwrap();
        node.vote(
            "JGB10Y-JPY",
            1,
            OrderCommitment([1; 32]),
            [0; 32],
            2_000,
            1_000,
        )
        .unwrap();
        assert_eq!(
            node.vote(
                "JGB10Y-JPY",
                1,
                OrderCommitment([2; 32]),
                [0; 32],
                2_000,
                1_000,
            ),
            Err(OrderingError::Equivocation)
        );
    }
}
