use bytes::Bytes;
use dashmap::DashMap;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::StreamExt;

use iroh::{NodeId, PublicKey};
use iroh_gossip::{
    net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender},
    proto::TopicId,
};

use serde::{Deserialize, Serialize};

use std::sync::Arc;
use thiserror::Error;

use tokio::sync::mpsc::{error::TryRecvError, UnboundedReceiver, UnboundedSender};
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, error, info, warn};

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
struct SignedMessage {
    from: VerifyingKey,
    data: Bytes,
    signature: Signature,
}

impl SignedMessage {
    pub fn sign_and_encode(secret_key: &SigningKey, node: &Node) -> Result<Bytes> {
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

    pub fn verify_and_decode(bytes: &[u8]) -> Result<(VerifyingKey, Node)> {
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

pub type Result<T> = std::result::Result<T, GossipDiscoveryError>;

pub struct GossipDiscoveryBuilder {
    expiration_timeout: Option<Duration>,
}

impl GossipDiscoveryBuilder {
    pub fn new() -> Self {
        Self {
            expiration_timeout: None,
        }
    }

    pub fn with_expiration_timeout(mut self, timeout: Duration) -> Self {
        self.expiration_timeout = Some(timeout);
        self
    }

    pub async fn build_with_peers(
        self,
        gossip: Gossip,
        topic_id: TopicId,
        peers: Vec<NodeId>,
        endpoint: &iroh::Endpoint,
    ) -> Result<(GossipDiscoverySender, GossipDiscoveryReceiver)> {
        // - First node (empty peers): use subscribe() only
        // - Other nodes (with peers): use subscribe_and_join()
        info!(topic_id = ?topic_id, peers = ?peers, "Attempting to subscribe to gossip");
        let (sender, receiver) = gossip.subscribe(topic_id, peers)?.split();
        info!(topic_id = ?topic_id, "Subscribed to gossip topic");

        let (peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel();
        let neighbor_map = Arc::new(DashMap::new());

        // Derive a secret key from the endpoint's node secret key
        // This ensures the signing key corresponds to the node's identity
        let node_secret = endpoint.secret_key();
        let secret_key_bytes = node_secret.to_bytes();
        let secret_key = SigningKey::from_bytes(&secret_key_bytes);
        let discovery_sender = GossipDiscoverySender {
            peer_rx,
            sender,
            secret_key,
        };

        let expiration_timeout = self.expiration_timeout.unwrap_or(Duration::from_secs(30));

        let discovery_receiver = GossipDiscoveryReceiver {
            neighbor_map: Arc::clone(&neighbor_map),
            peer_tx,
            receiver,
            expiration_timeout,
        };

        // Start the cleanup task
        GossipDiscoveryReceiver::start_cleanup_task(neighbor_map, expiration_timeout);

        Ok((discovery_sender, discovery_receiver))
    }
}

pub struct GossipDiscoverySender {
    pub peer_rx: UnboundedReceiver<NodeId>,
    pub sender: GossipSender,
    pub secret_key: SigningKey,
}

impl GossipDiscoverySender {
    /// Add external peers to the gossip network
    pub async fn add_peers(&mut self, peers: Vec<NodeId>) -> Result<()> {
        if !peers.is_empty() {
            info!(
                peer_count = peers.len(),
                "Adding external peers to gossip network"
            );
            self.sender.join_peers(peers).await?;
        }
        Ok(())
    }

    /// Add a single external peer to the gossip network  
    pub async fn add_peer(&mut self, peer: NodeId) -> Result<()> {
        self.add_peers(vec![peer]).await
    }

    pub async fn gossip(&mut self, node: Node, update_rate: Duration) -> Result<()> {
        let mut i = node.count;

        loop {
            // Check for new peers to join
            match self.peer_rx.try_recv() {
                Ok(peer) => {
                    info!(%peer, "Joining new peer");
                    if let Err(e) = self.sender.join_peers(vec![peer]).await {
                        error!(%e, "Failed to join peer");
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    warn!("peer_rx channel's sending half has been disconnected!");
                }
            }

            let update_node = Node {
                name: node.name.clone(),
                node_id: node.node_id,
                count: i,
            };

            // Sign and encode the message
            let bytes = SignedMessage::sign_and_encode(&self.secret_key, &update_node)?;

            if let Err(e) = self.sender.broadcast(bytes).await {
                error!(%e, "Failed to broadcast");
            }

            i += 1;
            sleep(update_rate).await;
        }
    }
}

pub struct GossipDiscoveryReceiver {
    pub neighbor_map: Arc<DashMap<String, NodeInfo>>,
    pub peer_tx: UnboundedSender<NodeId>,
    pub receiver: GossipReceiver,
    pub expiration_timeout: Duration,
}

impl GossipDiscoveryReceiver {
    pub async fn update_map(&mut self) -> Result<()> {
        while let Some(res) = self.receiver.next().await {
            match res {
                Ok(Event::Gossip(GossipEvent::Received(msg))) => {
                    // Verify and decode the signed message
                    let (_, value) = match SignedMessage::verify_and_decode(&msg.content) {
                        Ok(result) => result,
                        Err(e) => {
                            warn!(%e, "Failed to verify message signature, ignoring");
                            continue;
                        }
                    };

                    // Handle updating map
                    self._execute_update_map(value)?;
                }
                Ok(_) => {}
                Err(e) => {
                    error!(%e, "Error receiving gossip");
                }
            }
        }

        info!("Finished GossipDiscoveryReceiver update map, exiting");
        Ok(())
    }

    fn _execute_update_map(&self, value: Node) -> Result<()> {
        if value.name.is_empty() {
            // Ignore nodes who have empty names
            info!(name = value.name, node_id = %value.node_id, "Ignoring peer with no name")
        } else {
            if !self._is_neighbor(&value.name, &value.node_id) {
                // Send new peer to sender for joining
                self.peer_tx
                    .send(value.node_id)
                    .map_err(|_| GossipDiscoveryError::ChannelSend)?;
                info!(name = %value.name, node_id = %value.node_id, "Discovered new peer");
            } else {
                info!(
                    name = value.name,
                    node_id = %value.node_id,
                    "Ignoring existing peer"
                );
            }

            self.neighbor_map.insert(
                value.name.clone(),
                NodeInfo {
                    node_id: value.node_id,
                    last_seen: Instant::now(),
                },
            );
            debug!(peer_count = self.neighbor_map.len(), "Address book updated");
        }

        Ok(())
    }

    fn _is_neighbor(&self, name: &str, node_id: &PublicKey) -> bool {
        // We need to check two conditions to determine whether the specified
        // node is an existing neighbor:
        //
        // 1. Is there a neighbor with the same name already? This is a
        //    unique identifier associated with a node, but not unique per
        //    execution
        // 2. If there is a neighbor, check to see if the node id is identical.
        //    If the node id is not identical, then this is a new peer
        match self.neighbor_map.get(name) {
            Some(node_info) => node_info.node_id.eq(&node_id),
            None => false,
        }
    }

    pub fn get_neighbors(&self) -> Vec<(String, NodeId)> {
        self.neighbor_map
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().node_id))
            .collect()
    }

    pub fn cleanup_expired_nodes(&self) -> usize {
        GossipDiscoveryReceiver::_cleanup_expired_nodes(&self.neighbor_map, self.expiration_timeout)
    }

    pub fn start_cleanup_task(
        neighbor_map: Arc<DashMap<String, NodeInfo>>,
        expiration_timeout: Duration,
    ) {
        let cleanup_interval = expiration_timeout / 3; // Check every 1/3 of timeout period

        tokio::spawn(async move {
            loop {
                sleep(cleanup_interval).await;

                let expired_count = GossipDiscoveryReceiver::_cleanup_expired_nodes(
                    &neighbor_map,
                    expiration_timeout,
                );

                if expired_count > 0 {
                    info!(count = expired_count, "Cleaned up expired nodes");
                }
            }
        });
    }

    fn _cleanup_expired_nodes(
        neighbor_map: &Arc<DashMap<String, NodeInfo>>,
        expiration_timeout: Duration,
    ) -> usize {
        let now = Instant::now();
        let mut expired_count = 0;

        // Collect expired node names first to avoid holding locks
        let expired_nodes: Vec<String> = neighbor_map
            .iter()
            .filter_map(|entry| {
                if now.duration_since(entry.value().last_seen) > expiration_timeout {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove expired nodes
        for node_name in expired_nodes {
            if let Some((_, node_info)) = neighbor_map.remove(&node_name) {
                info!(name = %node_name, node_id = %node_info.node_id, "Expired node");
                expired_count += 1;
            }
        }

        expired_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create valid NodeIds for testing
    fn create_test_node_id(seed: u8) -> NodeId {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        NodeId::from(signing_key.verifying_key())
    }

    // Helper to create a GossipDiscoveryReceiver for testing
    async fn create_test_receiver(
        neighbor_map: Arc<DashMap<String, NodeInfo>>,
    ) -> (GossipDiscoveryReceiver, UnboundedReceiver<NodeId>) {
        // Create a test endpoint
        let endpoint = iroh::Endpoint::builder()
            .discovery_n0()
            .bind()
            .await
            .expect("Failed to create test endpoint");

        // Create gossip instance
        let gossip = Gossip::builder()
            .spawn(endpoint.clone())
            .await
            .expect("Failed to spawn gossip");

        // Create a test topic
        let topic_id = TopicId::from([0u8; 32]);

        // Subscribe to get a receiver
        let (_, receiver) = gossip
            .subscribe(topic_id, vec![])
            .expect("Failed to subscribe")
            .split();

        let (peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel();

        (
            GossipDiscoveryReceiver {
                neighbor_map,
                peer_tx,
                receiver,
                expiration_timeout: Duration::from_secs(30),
            },
            peer_rx,
        )
    }

    #[test]
    fn test_cleanup_expired_nodes_empty_map() {
        let neighbor_map = Arc::new(DashMap::new());
        let expiration_timeout = Duration::from_secs(10);

        let expired_count =
            GossipDiscoveryReceiver::_cleanup_expired_nodes(&neighbor_map, expiration_timeout);

        assert_eq!(expired_count, 0);
        assert_eq!(neighbor_map.len(), 0);
    }

    #[test]
    fn test_cleanup_expired_nodes_no_expired() {
        let neighbor_map = Arc::new(DashMap::new());
        let expiration_timeout = Duration::from_secs(10);

        // Add fresh nodes
        let node_id = create_test_node_id(1);
        neighbor_map.insert(
            "alice".to_string(),
            NodeInfo {
                node_id,
                last_seen: Instant::now(),
            },
        );

        let node_id2 = create_test_node_id(2);
        neighbor_map.insert(
            "bob".to_string(),
            NodeInfo {
                node_id: node_id2,
                last_seen: Instant::now(),
            },
        );

        let expired_count =
            GossipDiscoveryReceiver::_cleanup_expired_nodes(&neighbor_map, expiration_timeout);

        assert_eq!(expired_count, 0);
        assert_eq!(neighbor_map.len(), 2);
        assert!(neighbor_map.contains_key("alice"));
        assert!(neighbor_map.contains_key("bob"));
    }

    #[test]
    fn test_cleanup_expired_nodes_all_expired() {
        let neighbor_map = Arc::new(DashMap::new());
        let expiration_timeout = Duration::from_millis(100);

        // Add nodes with old timestamps
        let old_instant = Instant::now() - Duration::from_secs(1);

        let node_id = create_test_node_id(1);
        neighbor_map.insert(
            "alice".to_string(),
            NodeInfo {
                node_id,
                last_seen: old_instant,
            },
        );

        let node_id2 = create_test_node_id(2);
        neighbor_map.insert(
            "bob".to_string(),
            NodeInfo {
                node_id: node_id2,
                last_seen: old_instant,
            },
        );

        let expired_count =
            GossipDiscoveryReceiver::_cleanup_expired_nodes(&neighbor_map, expiration_timeout);

        assert_eq!(expired_count, 2);
        assert_eq!(neighbor_map.len(), 0);
    }

    #[test]
    fn test_cleanup_expired_nodes_boundary_case() {
        let neighbor_map = Arc::new(DashMap::new());
        let expiration_timeout = Duration::from_millis(100);

        // Add node that's exactly at the expiration boundary
        let boundary_instant = Instant::now() - Duration::from_millis(100);
        let node_id = create_test_node_id(1);
        neighbor_map.insert(
            "alice".to_string(),
            NodeInfo {
                node_id,
                last_seen: boundary_instant,
            },
        );

        // Small sleep to ensure we're past the boundary
        std::thread::sleep(Duration::from_millis(10));

        let expired_count =
            GossipDiscoveryReceiver::_cleanup_expired_nodes(&neighbor_map, expiration_timeout);

        assert_eq!(expired_count, 1);
        assert_eq!(neighbor_map.len(), 0);
    }

    #[test]
    fn test_cleanup_expired_nodes_multiple_expired() {
        let neighbor_map = Arc::new(DashMap::new());
        let expiration_timeout = Duration::from_millis(50);

        // Add multiple expired nodes
        let old_instant = Instant::now() - Duration::from_secs(1);

        for i in 0..5 {
            let node_id = create_test_node_id(i);
            neighbor_map.insert(
                format!("node_{}", i),
                NodeInfo {
                    node_id,
                    last_seen: old_instant,
                },
            );
        }

        // Add some fresh nodes
        for i in 5..8 {
            let node_id = create_test_node_id(i);
            neighbor_map.insert(
                format!("node_{}", i),
                NodeInfo {
                    node_id,
                    last_seen: Instant::now(),
                },
            );
        }

        assert_eq!(neighbor_map.len(), 8);

        let expired_count =
            GossipDiscoveryReceiver::_cleanup_expired_nodes(&neighbor_map, expiration_timeout);

        assert_eq!(expired_count, 5);
        assert_eq!(neighbor_map.len(), 3);

        // Verify remaining nodes
        for i in 5..8 {
            assert!(neighbor_map.contains_key(&format!("node_{}", i)));
        }
    }

    #[test]
    fn test_cleanup_expired_nodes_returns_correct_count() {
        let neighbor_map = Arc::new(DashMap::new());
        let expiration_timeout = Duration::from_millis(100);

        // Add expired nodes
        let old_instant = Instant::now() - Duration::from_secs(1);
        for i in 0..10 {
            let node_id = create_test_node_id(i);
            neighbor_map.insert(
                format!("expired_{}", i),
                NodeInfo {
                    node_id,
                    last_seen: old_instant,
                },
            );
        }

        let expired_count =
            GossipDiscoveryReceiver::_cleanup_expired_nodes(&neighbor_map, expiration_timeout);

        assert_eq!(expired_count, 10);
        assert_eq!(neighbor_map.len(), 0);
    }

    #[tokio::test]
    async fn test_is_neighbor_empty_map() {
        let neighbor_map = Arc::new(DashMap::new());
        let (receiver, _peer_rx) = create_test_receiver(neighbor_map).await;
        let node_id = create_test_node_id(1);
        assert!(!receiver._is_neighbor("alice", &node_id));
    }

    #[tokio::test]
    async fn test_is_neighbor_name_not_found() {
        let neighbor_map = Arc::new(DashMap::new());

        // Add a neighbor with a different name
        let bob_node_id = create_test_node_id(1);
        neighbor_map.insert(
            "bob".to_string(),
            NodeInfo {
                node_id: bob_node_id,
                last_seen: Instant::now(),
            },
        );

        let (receiver, _peer_rx) = create_test_receiver(neighbor_map).await;
        let alice_node_id = create_test_node_id(2);
        assert!(!receiver._is_neighbor("alice", &alice_node_id));
    }

    #[tokio::test]
    async fn test_is_neighbor_name_found_same_node_id() {
        let neighbor_map = Arc::new(DashMap::new());

        let alice_node_id = create_test_node_id(1);
        neighbor_map.insert(
            "alice".to_string(),
            NodeInfo {
                node_id: alice_node_id,
                last_seen: Instant::now(),
            },
        );

        let (receiver, _peer_rx) = create_test_receiver(neighbor_map).await;
        // Same name, same node_id
        assert!(receiver._is_neighbor("alice", &alice_node_id));
    }

    #[tokio::test]
    async fn test_is_neighbor_name_found_different_node_id() {
        let neighbor_map = Arc::new(DashMap::new());

        // Add alice with node_id 1
        let alice_node_id_1 = create_test_node_id(1);
        neighbor_map.insert(
            "alice".to_string(),
            NodeInfo {
                node_id: alice_node_id_1,
                last_seen: Instant::now(),
            },
        );

        let (receiver, _peer_rx) = create_test_receiver(neighbor_map).await;
        // Same name but different node_id (restarted node scenario)
        let alice_node_id_2 = create_test_node_id(2);
        assert!(!receiver._is_neighbor("alice", &alice_node_id_2));
    }

    #[tokio::test]
    async fn test_is_neighbor_multiple_neighbors() {
        let neighbor_map = Arc::new(DashMap::new());

        // Add multiple neighbors
        let alice_node_id = create_test_node_id(1);
        let bob_node_id = create_test_node_id(2);
        let charlie_node_id = create_test_node_id(3);

        neighbor_map.insert(
            "alice".to_string(),
            NodeInfo {
                node_id: alice_node_id,
                last_seen: Instant::now(),
            },
        );
        neighbor_map.insert(
            "bob".to_string(),
            NodeInfo {
                node_id: bob_node_id,
                last_seen: Instant::now(),
            },
        );
        neighbor_map.insert(
            "charlie".to_string(),
            NodeInfo {
                node_id: charlie_node_id,
                last_seen: Instant::now(),
            },
        );

        let (receiver, _peer_rx) = create_test_receiver(neighbor_map).await;
        // Check all existing neighbors return true
        assert!(receiver._is_neighbor("alice", &alice_node_id));
        assert!(receiver._is_neighbor("bob", &bob_node_id));
        assert!(receiver._is_neighbor("charlie", &charlie_node_id));

        // Check non-existent neighbor returns false
        let dave_node_id = create_test_node_id(4);
        assert!(!receiver._is_neighbor("dave", &dave_node_id));
    }

    #[tokio::test]
    async fn test_is_neighbor_case_sensitive_name() {
        let neighbor_map = Arc::new(DashMap::new());

        let alice_node_id = create_test_node_id(1);
        neighbor_map.insert(
            "alice".to_string(),
            NodeInfo {
                node_id: alice_node_id,
                last_seen: Instant::now(),
            },
        );

        let (receiver, _peer_rx) = create_test_receiver(neighbor_map).await;
        // Exact match should work
        assert!(receiver._is_neighbor("alice", &alice_node_id));

        // Different case should not match
        assert!(!receiver._is_neighbor("Alice", &alice_node_id));
        assert!(!receiver._is_neighbor("ALICE", &alice_node_id));
    }

    #[tokio::test]
    async fn test_execute_update_map_empty_name() {
        let neighbor_map = Arc::new(DashMap::new());
        let (receiver, mut peer_rx) = create_test_receiver(neighbor_map.clone()).await;

        let node = Node {
            name: "".to_string(),
            node_id: create_test_node_id(1),
            count: 0,
        };

        receiver._execute_update_map(node.clone()).unwrap();

        // Node should be inserted despite empty name
        assert_eq!(neighbor_map.len(), 0);
        assert!(!neighbor_map.contains_key(""));

        // Verify no message sent to peer_tx
        assert!(peer_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_execute_update_map_new_peer() {
        let neighbor_map = Arc::new(DashMap::new());
        let (receiver, mut peer_rx) = create_test_receiver(neighbor_map.clone()).await;

        let node = Node {
            name: "alice".to_string(),
            node_id: create_test_node_id(1),
            count: 0,
        };

        receiver._execute_update_map(node.clone()).unwrap();

        // Verify node added to map
        assert_eq!(neighbor_map.len(), 1);
        let entry = neighbor_map.get("alice").unwrap();
        assert_eq!(entry.node_id, node.node_id);

        // Verify peer_tx received the node_id
        assert_eq!(peer_rx.try_recv().unwrap(), node.node_id);
    }

    #[tokio::test]
    async fn test_execute_update_map_existing_peer_updates_timestamp() {
        let neighbor_map = Arc::new(DashMap::new());
        let node_id = create_test_node_id(1);

        // Insert initial entry with old timestamp
        let old_timestamp = Instant::now() - Duration::from_secs(10);
        neighbor_map.insert(
            "alice".to_string(),
            NodeInfo {
                node_id,
                last_seen: old_timestamp,
            },
        );

        let (receiver, mut peer_rx) = create_test_receiver(neighbor_map.clone()).await;

        let node = Node {
            name: "alice".to_string(),
            node_id,
            count: 5,
        };

        let before_update = Instant::now();
        receiver._execute_update_map(node).unwrap();
        let after_update = Instant::now();

        // Verify map still has one entry
        assert_eq!(neighbor_map.len(), 1);

        // Verify timestamp was updated
        let entry = neighbor_map.get("alice").unwrap();
        assert!(entry.last_seen >= before_update);
        assert!(entry.last_seen <= after_update);
        assert!(entry.last_seen > old_timestamp);

        // Verify no peer_tx message sent (already a neighbor)
        assert!(peer_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_execute_update_map_same_name_different_node_id() {
        let neighbor_map = Arc::new(DashMap::new());

        // Insert alice with node_id 1
        let old_node_id = create_test_node_id(1);
        neighbor_map.insert(
            "alice".to_string(),
            NodeInfo {
                node_id: old_node_id,
                last_seen: Instant::now(),
            },
        );

        let (receiver, mut peer_rx) = create_test_receiver(neighbor_map.clone()).await;

        // Try to add alice with node_id 2 (restarted node scenario)
        let new_node_id = create_test_node_id(2);
        let node = Node {
            name: "alice".to_string(),
            node_id: new_node_id,
            count: 0,
        };

        receiver._execute_update_map(node.clone()).unwrap();

        // Should update the map with new node_id
        assert_eq!(neighbor_map.len(), 1);
        let entry = neighbor_map.get("alice").unwrap();
        assert_eq!(entry.node_id, new_node_id);

        // Verify peer_tx received the new node_id (since it's a different node)
        assert_eq!(peer_rx.try_recv().unwrap(), new_node_id);
    }

    #[tokio::test]
    async fn test_execute_update_map_channel_send_error() {
        let neighbor_map = Arc::new(DashMap::new());

        // Create endpoint and gossip
        let endpoint = iroh::Endpoint::builder()
            .discovery_n0()
            .bind()
            .await
            .expect("Failed to create test endpoint");

        let gossip = Gossip::builder()
            .spawn(endpoint.clone())
            .await
            .expect("Failed to spawn gossip");

        let topic_id = TopicId::from([0u8; 32]);
        let (_, receiver_stream) = gossip
            .subscribe(topic_id, vec![])
            .expect("Failed to subscribe")
            .split();

        // Create channel but immediately drop receiver to cause send error
        let (peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel();
        drop(peer_rx);

        let receiver = GossipDiscoveryReceiver {
            neighbor_map,
            peer_tx,
            receiver: receiver_stream,
            expiration_timeout: Duration::from_secs(30),
        };

        let node = Node {
            name: "alice".to_string(),
            node_id: create_test_node_id(1),
            count: 0,
        };

        // Should return ChannelSend error
        let result = receiver._execute_update_map(node);
        assert!(result.is_err());
        match result.unwrap_err() {
            GossipDiscoveryError::ChannelSend => {}
            _ => panic!("Expected ChannelSend error"),
        }
    }
}
