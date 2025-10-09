use ed25519_dalek::SigningKey;

use iroh::NodeId;
use iroh_gossip::net::GossipSender;

use tokio::sync::mpsc::{error::TryRecvError, UnboundedReceiver};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

use crate::common::{IrohGossipDiscoveryResult, Node, SignedMessage};

pub struct GossipDiscoverySender {
    pub peer_rx: UnboundedReceiver<NodeId>,
    pub sender: GossipSender,
    pub secret_key: SigningKey,
}

impl GossipDiscoverySender {
    /// Add external peers to the gossip network
    pub async fn add_peers(&mut self, peers: Vec<NodeId>) -> IrohGossipDiscoveryResult<()> {
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
    pub async fn add_peer(&mut self, peer: NodeId) -> IrohGossipDiscoveryResult<()> {
        self.add_peers(vec![peer]).await
    }

    pub async fn gossip(
        &mut self,
        node: Node,
        update_rate: Duration,
    ) -> IrohGossipDiscoveryResult<()> {
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
