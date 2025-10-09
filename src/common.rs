use bytes::Bytes;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use iroh::NodeId;

use serde::{Deserialize, Serialize};

use thiserror::Error;

use tokio::time::Instant;
use tracing::error;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Node {
    pub name: String,
    pub node_id: NodeId,
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub node_id: NodeId,
    pub last_seen: Instant,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedMessage {
    from: VerifyingKey,
    data: Bytes,
    signature: Signature,
}

impl SignedMessage {
    pub fn sign_and_encode(
        secret_key: &SigningKey,
        node: &Node,
    ) -> IrohGossipDiscoveryResult<Bytes> {
        let data: Bytes = postcard::to_stdvec(node)
            .map_err(|e| GossipDiscoveryError::Serialization(e.to_string()))?
            .into();
        let signature = secret_key.sign(&data);
        let from: VerifyingKey = secret_key.verifying_key();

        let signed_message = Self {
            from,
            data,
            signature,
        };

        let encoded = postcard::to_stdvec(&signed_message)
            .map_err(|e| GossipDiscoveryError::Serialization(e.to_string()))?;
        Ok(encoded.into())
    }

    pub fn verify_and_decode(bytes: &[u8]) -> IrohGossipDiscoveryResult<(VerifyingKey, Node)> {
        let signed_message: Self = postcard::from_bytes(bytes)
            .map_err(|e| GossipDiscoveryError::Deserialization(e.to_string()))?;
        let key: VerifyingKey = signed_message.from;

        key.verify(&signed_message.data, &signed_message.signature)
            .map_err(|e| GossipDiscoveryError::SignatureVerification(e.to_string()))?;

        let node: Node = postcard::from_bytes(&signed_message.data)
            .map_err(|e| GossipDiscoveryError::Deserialization(e.to_string()))?;
        Ok((signed_message.from, node))
    }
}

#[derive(Error, Debug)]
pub enum GossipDiscoveryError {
    #[error("Gossip error: {0}")]
    Gossip(#[from] iroh_gossip::net::Error),
    #[error("Channel send error")]
    ChannelSend,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Signature verification error: {0}")]
    SignatureVerification(String),
    #[error("NodeId mismatch: expected {expected}, got {actual}")]
    NodeIdMismatch { expected: NodeId, actual: NodeId },
}

pub type IrohGossipDiscoveryResult<T> = std::result::Result<T, GossipDiscoveryError>;
