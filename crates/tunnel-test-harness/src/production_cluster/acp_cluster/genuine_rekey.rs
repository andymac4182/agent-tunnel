//! Case `genuine-peer-key-rotation` (task rows M8-C24, M8-05 discriminator 1,
//! M7-C150): the owner relay **genuinely re-keys** its private HTTP/3 peer
//! identity while an ACP SSE stream and a flooded forwarded stream are live on
//! the non-owner ingress, and stays `Ready` throughout.
//!
//! The case beside it, `peer-key-rotation` (M8-C16), withdraws the owner's
//! own serving key for a phantom successor, so the owner fails closed; that
//! was the only shape available while a relay bound one serving identity for
//! the life of its process (M8-C28).  With the product change of M8-C45 the
//! owner can hold a successor, serve it, and let the predecessor drain.  This
//! case drives the whole procedure through the product's own
//! `PeerRekey` state machine and its tick loop, the one `tunnel-relay serve`
//! runs:
//!
//! 1. **stage** a second certificate for the owner's node, issued under the
//!    same peer CA, and show it is not served while no record approves it;
//! 2. **publish** the owner's signed record approving both keys, through the
//!    same Redis publisher and checkpoint authority as every other record;
//! 3. with a held ACP turn and a flooded, unread forwarded stream live on the
//!    ingress, **let the owner switch** once its convergence hold elapses, and
//!    show both streams still serving afterwards and a fresh handshake to the
//!    owner presenting the successor and not the predecessor;
//! 4. **withdraw** the predecessor, and show the ingress attributes the held
//!    stream's teardown to the key (`membership_revoked`) while the owner
//!    stays Ready, latches no `membership_revoked` of its own, and retires the
//!    predecessor because it was withdrawn;
//! 5. complete a fresh ACP turn across the rotated route, then make the
//!    successor the fixture's own identity for the owner and re-sign every
//!    record, so every later case meets a cluster serving on it.  (A retired
//!    key cannot be restaged, so the owner is not rotated back.)

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::time::{sleep, timeout};
use tunnel_relay::MembershipReadiness;
use tunnel_relay::peer_rekey::{PeerRekeyPhase, PeerRekeyRetirement};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerDestination, PeerTransportLimits,
    load_peer_client_config_from_pem,
};

use super::{
    AcpClusterEvidence, Gate, INGRESS_NODE, INTERRUPTION_BOUND, InvalidationLedger,
    KEY_STAGE_BOUND, TARGET_NODE, install_reason_recorder, method_of, stop_reason_for,
    target_peer_spki,
};
use crate::{HarnessError, Result};

/// How long after the switch the live streams are watched before anything
/// else happens: two of the fixture's 1 s reconcile intervals, so "still
/// serving" is not "no relay has looked yet".
const SWITCH_SETTLE: Duration = Duration::from_secs(2);

/// Bound on the owner's convergence hold plus its tick, with headroom.
const SWITCH_BOUND: Duration = Duration::from_secs(20);

impl Gate<'_> {
    pub(super) async fn case_genuine_key_rotation(
        &mut self,
        evidence: &mut AcpClusterEvidence,
    ) -> Result<()> {
        let old_spki = target_peer_spki(self.cluster)?;
        let successor = self.rekey_successor.clone();
        let new_spki = successor
            .spki_fingerprint_sha256()
            .map_err(|error| HarnessError::Pki(error.to_string()))?;
        let ledger = Arc::new(InvalidationLedger::default());
        for relay in &self.cluster.relays {
            install_reason_recorder(relay, &ledger);
        }

        // The owner's own readiness, sampled for the whole case by a watcher
        // rather than at a few chosen instants, so an excursion that is over
        // by the next check is still seen.
        let owner_membership = Arc::clone(&self.cluster.relay(TARGET_NODE)?.membership);
        let owner_unready = Arc::new(AtomicBool::new(false));
        let watching = Arc::new(AtomicBool::new(true));
        let watcher = {
            let owner_unready = Arc::clone(&owner_unready);
            let watching = Arc::clone(&watching);
            tokio::spawn(async move {
                while watching.load(Ordering::Acquire) {
                    if !matches!(owner_membership.readiness(), MembershipReadiness::Ready) {
                        owner_unready.store(true, Ordering::Release);
                    }
                    sleep(Duration::from_millis(25)).await;
                }
            })
        };
        let rekey = Arc::clone(&self.cluster.relay(TARGET_NODE)?.rekey);
        // The product's tick loop is started only once the live streams are
        // open (step 3): the overlap publish is a record-version bump, which
        // tears down live peer admissions by itself (M7-C80), so the streams
        // must be opened after it and the switch must come after them.
        let tick_cancel = tokio_util::sync::CancellationToken::new();
        let mut tick_task = None;

        let outcome = async {
            // ---- 1. stage, and show nothing serves it yet ----------------
            let staged = rekey
                .stage_pem(
                    self.successor_chain_pem().as_bytes(),
                    successor.private_key_pem.as_bytes(),
                )
                .map_err(|error| HarnessError::Process(format!("staging the successor: {error}")))?;
            let before = rekey.tick().await;
            evidence.genuine_staged_not_served = staged == new_spki
                && before.phase == PeerRekeyPhase::Staged
                && before.serving_spki == old_spki
                && before.staged_approval == Some("absent");

            // ---- 2. publish the overlap ------------------------------------
            let staged_now = Utc::now();
            let overlap_version = self.next_record_version();
            self.publish_owner_keys(overlap_version, &[&old_spki, &new_spki], staged_now)
                .await?;
            evidence.genuine_overlap_staged = self
                .converge_owner_keys(overlap_version, &[&old_spki, &new_spki])
                .await?;
            if !evidence.genuine_overlap_staged {
                return Err(HarnessError::Timeout(format!(
                    "the genuine rotation's overlap did not reach every verifier within {KEY_STAGE_BOUND:?}"
                )));
            }
            let overlap_seen = Instant::now();
            self.settle_after_publish().await?;

            // ---- 3. live streams across the switch -------------------------
            let held_label = "genuine-rekey-held";
            let conversation = self.open_connection().await?;
            let (session, stream) = self
                .open_session(&conversation, "genuine-rekey-new", &[])
                .await?;
            let status = self
                .prompt(&conversation, &session, held_label, "permission")
                .await?;
            if status != http::StatusCode::ACCEPTED {
                return Err(HarnessError::Http(format!(
                    "the genuine rotation's held prompt answered {status}, not 202"
                )));
            }
            stream
                .wait_for("the genuine rotation's callback", |value| {
                    (method_of(value) == Some("session/request_permission")).then_some(true)
                })
                .await?;
            // The forwarded stream: a session nobody reads, flooded, so its
            // response direction backs up through device, owner and ingress
            // while the owner switches identity underneath it.
            let flooded = self.open_connection().await?;
            let flooded_session = self
                .create_session(&flooded, "genuine-rekey-flooded", &[])
                .await?;
            let mut parked = self.open_unread_stream(&flooded, &flooded_session).await?;
            let _ = self
                .prompt(&flooded, &flooded_session, "genuine-rekey-flood", "updates:4000")
                .await?;
            // Both streams are live; only now may the owner switch.
            let streams_live = Instant::now();
            tick_task = Some(rekey.spawn(tick_cancel.clone()));

            let deadline = Instant::now() + SWITCH_BOUND;
            loop {
                let snapshot = rekey.snapshot();
                if snapshot.phase == PeerRekeyPhase::Overlap && snapshot.serving_spki == new_spki {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(HarnessError::Timeout(format!(
                        "the owner did not switch to the approved successor within {SWITCH_BOUND:?} (phase {}, approval {:?}, refusal {:?})",
                        snapshot.phase.label(),
                        snapshot.staged_approval,
                        snapshot.last_refusal
                    )));
                }
                sleep(Duration::from_millis(50)).await;
            }
            evidence.genuine_switched = true;
            evidence.genuine_switch_after_overlap_ms = overlap_seen.elapsed().as_millis();
            evidence.genuine_switch_after_streams_ms = streams_live.elapsed().as_millis();
            sleep(SWITCH_SETTLE).await;
            evidence.genuine_switch_left_acp_serving = !stream.has_errored() && !stream.has_ended();
            evidence.genuine_switch_left_forward_serving = matches!(
                timeout(Duration::from_secs(5), http_body_util::BodyExt::frame(&mut parked)).await,
                Ok(Some(Ok(_)))
            );

            // A fresh handshake to the owner presents the successor, and a
            // dialer that approves only the predecessor is refused.
            evidence.genuine_successor_presented =
                self.owner_presents(&new_spki).await.unwrap_or(false);
            evidence.genuine_predecessor_not_presented =
                !self.owner_presents(&old_spki).await.unwrap_or(true);

            // ---- 4. withdraw the predecessor -------------------------------
            ledger.clear();
            let withdraw_version = self.next_record_version();
            self.publish_owner_keys(withdraw_version, &[&new_spki], staged_now)
                .await?;
            if !self.converge_owner_keys(withdraw_version, &[&new_spki]).await? {
                return Err(HarnessError::Timeout(
                    "the predecessor's withdrawal did not reach every verifier".into(),
                ));
            }
            let deadline = Instant::now() + INTERRUPTION_BOUND;
            while Instant::now() < deadline && !(stream.has_errored() || stream.has_ended()) {
                sleep(Duration::from_millis(100)).await;
            }
            evidence.genuine_interrupted = stream.has_errored();
            let picker = stop_reason_for(held_label);
            evidence.genuine_no_stop_reason =
                !stream.seen().iter().any(|value| picker(value).is_some());
            let deadline = Instant::now() + SWITCH_BOUND;
            while Instant::now() < deadline && rekey.phase() != PeerRekeyPhase::Stable {
                sleep(Duration::from_millis(50)).await;
            }
            let after = rekey.snapshot();
            evidence.genuine_retired_by_withdrawal = after.phase == PeerRekeyPhase::Stable
                && after.last_retirement == Some(PeerRekeyRetirement::Withdrawn)
                && after.serving_spki == new_spki;
            evidence.genuine_ingress_reasons = ledger.labels_for(INGRESS_NODE, TARGET_NODE);
            evidence.genuine_owner_reasons = ledger.labels_for(TARGET_NODE, INGRESS_NODE);
            stream.break_now();
            conversation.connection_stream.break_now();
            conversation.consumer.shutdown();
            drop(parked);
            flooded.connection_stream.break_now();
            flooded.consumer.shutdown();

            // ---- 5. the rotated cluster serves a whole turn ------------------
            self.settle_after_publish().await?;
            let after_conversation = self.open_connection().await?;
            let (after_session, after_stream) = self
                .open_session(&after_conversation, "genuine-rekey-after", &[])
                .await?;
            let status = self
                .prompt(&after_conversation, &after_session, "genuine-rekey-after", "ok")
                .await?;
            evidence.genuine_post_rotation_turn = status == http::StatusCode::ACCEPTED
                && after_stream
                    .wait_for(
                        "a whole turn across the rotated route",
                        stop_reason_for("genuine-rekey-after"),
                    )
                    .await?
                    == "end_turn";
            after_stream.break_now();
            after_conversation.connection_stream.break_now();
            after_conversation.consumer.shutdown();
            evidence.genuine_owner_unready = owner_unready.load(Ordering::Acquire);

            // ---- restore: a second genuine rotation, back -------------------
            evidence.genuine_resigned_on_successor = self
                .adopt_successor(&new_spki)
                .await?;
            Ok::<(), HarnessError>(())
        }
        .await;

        tick_cancel.cancel();
        if let Some(task) = tick_task {
            let _ = task.await;
        }
        watching.store(false, Ordering::Release);
        let _ = watcher.await;
        outcome?;

        eprintln!(
            "ACP cluster genuine peer-key rotation: staged_not_served={} switched={} switch_after_overlap_ms={} \
             acp_survived_switch={} forward_survived_switch={} successor_presented={} predecessor_not_presented={} \
             interrupted={} no_stop_reason={} ingress_reasons={:?} owner_reasons={:?} owner_unready={} \
             retired_by_withdrawal={} post_rotation_turn={} resigned_on_successor={}",
            evidence.genuine_staged_not_served,
            evidence.genuine_switched,
            evidence.genuine_switch_after_overlap_ms,
            evidence.genuine_switch_left_acp_serving,
            evidence.genuine_switch_left_forward_serving,
            evidence.genuine_successor_presented,
            evidence.genuine_predecessor_not_presented,
            evidence.genuine_interrupted,
            evidence.genuine_no_stop_reason,
            evidence.genuine_ingress_reasons,
            evidence.genuine_owner_reasons,
            evidence.genuine_owner_unready,
            evidence.genuine_retired_by_withdrawal,
            evidence.genuine_post_rotation_turn,
            evidence.genuine_resigned_on_successor,
        );

        // Hand every later case the cluster it expects.
        self.wait_owner_membership_ready().await?;
        for relay in self.cluster.relays.iter().filter(|r| r.running.is_some()) {
            super::publish_verified_pins(&relay.membership, &relay.pins)?;
        }
        self.wait_peers_ready().await?;
        self.settle_key_rotation_route().await?;
        evidence.key_rotation_route_probes = self.key_rotation_route_probes;
        Ok(())
    }

    /// Settle the cluster after a membership publish, before anything is
    /// measured.
    ///
    /// A publish is a record-version bump, which invalidates every live peer
    /// admission (M7-C80); a relay whose invalidation callback runs while its
    /// runtime is momentarily not Ready publishes an empty pin set and marks it
    /// pending (M7-C81).  Measured: without this, the first `initialize` after
    /// the overlap publish answered `502` in three of five runs at load ~8,
    /// after a `key-rotation pin publication failed closed` warning.  This is
    /// the same restore sequence the phantom-successor case ends with, and it
    /// runs only between publishes and measurements, never across a stream
    /// under test.
    async fn settle_after_publish(&mut self) -> Result<()> {
        self.wait_owner_membership_ready().await?;
        for relay in self.cluster.relays.iter().filter(|r| r.running.is_some()) {
            super::publish_verified_pins(&relay.membership, &relay.pins)?;
        }
        self.wait_peers_ready().await?;
        self.settle_key_rotation_route().await
    }

    fn successor_chain_pem(&self) -> String {
        let node = self
            .cluster
            .fixture
            .nodes
            .iter()
            .find(|node| node.node_id == TARGET_NODE)
            .map(|node| node.peer_ca_pem().to_owned())
            .unwrap_or_default();
        format!("{}{}", self.rekey_successor.certificate_pem, node)
    }

    /// Dial the owner's approved peer endpoint afresh -- a new QUIC/TLS
    /// handshake, never a pooled connection -- as the ingress relay, and
    /// report whether a dialer approving only `spki` is admitted.
    async fn owner_presents(&self, spki: &str) -> Result<bool> {
        let ingress = self
            .cluster
            .fixture
            .nodes
            .iter()
            .find(|node| node.node_id == INGRESS_NODE)
            .ok_or_else(|| {
                HarnessError::InvalidInput("the ingress node fixture is missing".into())
            })?;
        let config = load_peer_client_config_from_pem(
            ingress.peer_certificate_chain_pem().as_bytes(),
            ingress.peer_certificate.private_key_pem.as_bytes(),
            ingress.peer_ca_pem().as_bytes(),
        )
        .map_err(|error| HarnessError::Pki(format!("probe client TLS: {error}")))?;
        let mut endpoint = quinn::Endpoint::client(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(HarnessError::Io)?;
        endpoint.set_default_client_config(config);
        let pin = spki_from_hex(spki)?;
        let client = PeerClient::new(
            endpoint,
            ApprovedPeerPins::new([pin])
                .map_err(|error| HarnessError::Process(format!("probe pins: {error}")))?,
            PeerTransportLimits::default(),
        )
        .map_err(|error| HarnessError::Process(format!("probe client: {error}")))?;
        let address = self
            .cluster
            .peer_proxies
            .get(TARGET_NODE)
            .ok_or_else(|| HarnessError::InvalidInput("the owner peer proxy is missing".into()))?
            .address();
        let destination = PeerDestination::new(address, "localhost");
        let presented = match timeout(Duration::from_secs(10), client.connect(destination)).await {
            Ok(Ok(handle)) => handle.peer_identity().spki_sha256() == pin,
            Ok(Err(_)) | Err(_) => false,
        };
        let _ = client.shutdown().await;
        Ok(presented)
    }

    /// Make the rotated identity the cluster's own for every later case.
    ///
    /// A retired key cannot be restaged (M8-C45 review), so the owner is not
    /// rotated back.  Instead the fixture adopts the successor: the owner
    /// node's certificate and the membership re-signer's pinned SPKI for it
    /// become the successor's, exactly what an operator does after a
    /// rotation (operator.md section 3.4, step 5).  A full re-sign of every
    /// record through the ordinary re-signer then proves the cluster serves
    /// on the successor alone: every relay Ready and the ingress route
    /// answering.
    async fn adopt_successor(&mut self, successor_spki: &str) -> Result<bool> {
        let successor = self.rekey_successor.clone();
        let node = self
            .cluster
            .fixture
            .nodes
            .iter_mut()
            .find(|node| node.node_id == TARGET_NODE)
            .ok_or_else(|| {
                HarnessError::InvalidInput("the owner node fixture is missing".into())
            })?;
        node.peer_certificate = successor;
        let mut adopted = false;
        for (identity, _) in &mut self.cluster.membership_resign_inputs.nodes {
            if identity.node_id == TARGET_NODE {
                identity.peer_spki_sha256 = successor_spki.to_owned();
                adopted = true;
            }
        }
        if !adopted || target_peer_spki(self.cluster)? != successor_spki {
            return Ok(false);
        }
        self.cluster.resign_membership_now().await?;
        self.membership_signed_at = Instant::now();
        self.membership_resigns += 1;
        self.settle_after_publish().await?;
        let rekey = &self.cluster.relay(TARGET_NODE)?.rekey;
        Ok(rekey.snapshot().serving_spki == successor_spki
            && matches!(
                self.cluster.relay(TARGET_NODE)?.membership.readiness(),
                MembershipReadiness::Ready
            ))
    }
}

fn spki_from_hex(hex: &str) -> Result<tunnel_transport::SpkiSha256> {
    let mut bytes = [0_u8; 32];
    if hex.len() != 64 {
        return Err(HarnessError::InvalidInput(
            "an SPKI digest is 64 hex digits".into(),
        ));
    }
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| HarnessError::InvalidInput("an SPKI digest is hex".into()))?;
    }
    Ok(tunnel_transport::SpkiSha256::from_bytes(bytes))
}
