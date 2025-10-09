use dashmap::DashMap;
use ed25519_dalek::SigningKey;

use iroh::NodeId;
use iroh_gossip::{net::Gossip, proto::TopicId};

use std::sync::Arc;

use tokio::time::Duration;
use tracing::info;

use crate::{
    common::IrohGossipDiscoveryResult, receiver::GossipDiscoveryReceiver,
    sender::GossipDiscoverySender,
};

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
    ) -> IrohGossipDiscoveryResult<(GossipDiscoverySender, GossipDiscoveryReceiver)> {
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

        let discovery_receiver = GossipDiscoveryReceiver::new(
            Arc::clone(&neighbor_map),
            peer_tx,
            receiver,
            expiration_timeout,
        );

        // Start the cleanup task
        GossipDiscoveryReceiver::start_cleanup_task(neighbor_map, expiration_timeout);

        Ok((discovery_sender, discovery_receiver))
    }
}
