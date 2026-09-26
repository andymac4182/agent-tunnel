use std::{process::ExitCode, time::Duration};
use tunnel_test_harness::{
    ClusterFixture, FixturePki, HarnessError, acceptance, acceptance_command_exit_code,
    cluster_acceptance, cluster_transport, m2_acceptance, redis_lane_restart, redis_restart,
    redis_tls,
};

#[tokio::main]
pub(crate) async fn main() -> ExitCode {
    // The process-wide `rustls` provider is chosen here, explicitly, rather
    // than inferred from which provider features happen to be enabled across
    // the whole dependency graph (task row M8-C09). An error means something
    // installed one before this line, which is fatal: whatever that is has
    // decided this process's cryptography.
    if let Err(error) = tunnel_transport::install_process_crypto_provider() {
        eprintln!("tunnel: {error}");
        return ExitCode::FAILURE;
    }
    debug_assert!(tunnel_transport::process_provider_is_ring());
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command] if command == "verify" => {
            match tokio::time::timeout(Duration::from_secs(180), acceptance::verify()).await {
                Ok(result) => result,
                Err(_) => Err(HarnessError::Timeout(
                    "M1 acceptance exceeded 180 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m2" => {
            match m2_outer_timeout(Duration::from_secs(300), Duration::from_secs(270)) {
                Ok(budget) => match tokio::time::timeout(budget, m2_acceptance::verify()).await {
                    Ok(result) => result,
                    Err(_) => Err(HarnessError::Timeout(
                        "M2 accelerated acceptance exceeded its bounded outer timeout".to_owned(),
                    )),
                },
                Err(error) => Err(error),
            }
        }
        [command] if command == "verify-m2-default" => {
            match m2_outer_timeout(Duration::from_secs(1_020), Duration::from_secs(1_020)) {
                Ok(budget) => {
                    match tokio::time::timeout(budget, m2_acceptance::verify_default()).await {
                        Ok(result) => result,
                        Err(_) => Err(HarnessError::Timeout(
                            "M2 default-interval acceptance exceeded its bounded outer timeout"
                                .to_owned(),
                        )),
                    }
                }
                Err(error) => Err(error),
            }
        }
        [command] if command == "verify-m2-faults" => {
            match m2_outer_timeout(Duration::from_secs(300), Duration::from_secs(270)) {
                Ok(budget) => {
                    match tokio::time::timeout(budget, m2_acceptance::verify_faults()).await {
                        Ok(result) => result,
                        Err(_) => Err(HarnessError::Timeout(
                            "M2 targeted-fault acceptance exceeded its bounded outer timeout"
                                .to_owned(),
                        )),
                    }
                }
                Err(error) => Err(error),
            }
        }
        [command] if command == "verify-m7-transport" => {
            match FixturePki::new()
                .and_then(|pki| ClusterFixture::new(&pki).map(|fixture| (pki, fixture)))
            {
                Ok((pki, fixture)) => cluster_transport::verify(&fixture, &pki)
                    .await
                    .and_then(|evidence| {
                        require_m7_transport_evidence(&evidence)?;
                        println!(
                            "M7 transport passed: duplex={} role_rejection={} pin_rejection={} oversized_chunk_rejected={} truncation={} idle_timeout={} cancellation={} active_stream_pin_revocation_closed={} sibling_isolation={} budget_reclamation={} udp_blackhole_restored={} no_tcp_fallback={} zero_rtt_not_admitted={} joined_shutdown={}",
                            evidence.response_before_request_end
                                && evidence.body_before_request_end,
                            evidence.wrong_role_rejected,
                            evidence.wrong_pin_rejected,
                            evidence.oversized_chunk_rejected,
                            evidence.response_head_truncation_rejected
                                && evidence.response_body_truncation_rejected,
                            evidence.idle_blackhole_closed,
                            evidence.saturated_lane_cancellation_bounded,
                            evidence.active_stream_pin_revocation_closed,
                            evidence.shared_stream_isolated,
                            evidence.body_budget_reclamation_verified,
                            evidence.udp_blackhole_restored,
                            evidence.no_tcp_fallback,
                            evidence.zero_rtt_not_admitted,
                            evidence.client_shutdown_joined && evidence.server_shutdown_joined,
                        );
                        Ok(())
                    }),
                Err(error) => Err(error),
            }
        }
        [command] if command == "verify-m7-redis-tls" => {
            let redis_url =
                std::env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
                    env_var: "TEST_REDIS_URL",
                    guidance: "set it to a disposable loopback redis:// URL".to_owned(),
                });
            match redis_url {
                Ok(redis_url) => {
                    match tokio::time::timeout(
                        Duration::from_secs(30),
                        redis_tls::verify(&redis_url),
                    )
                    .await
                    {
                        Ok(result) => result.and_then(|evidence| {
                            require_m7_redis_tls_evidence(&evidence)?;
                            println!(
                                "M7 Redis TLS passed: authenticated_catalog_connection={} wrong_ca_rejected={} wrong_server_name_rejected={} wrong_client_identity_rejected={}",
                                evidence.authenticated_catalog_connection,
                                evidence.wrong_ca_rejected,
                                evidence.wrong_server_name_rejected,
                                evidence.wrong_client_identity_rejected,
                            );
                            Ok(())
                        }),
                        Err(_) => Err(HarnessError::Timeout(
                            "M7 Redis TLS acceptance exceeded 30 seconds".to_owned(),
                        )),
                    }
                }
                Err(error) => Err(error),
            }
        }
        [command] if command == "verify-m7-production" => {
            match tokio::time::timeout(
                Duration::from_secs(300),
                tunnel_test_harness::production_cluster::verify(),
            )
            .await
            {
                Ok(result) => result.map(|evidence| {
                    println!(
                        "M7 production passed: relays={} tenants={} ingress_relays={} rotations={} ordered_records={} cli={} tenant_isolation={} authorization_negatives={} stale_owner={} key_revocation={} owner_death={}",
                        evidence.relay_count,
                        evidence.tenant_count,
                        evidence.device_ingress_relays,
                        evidence.replacement_generations,
                        evidence.ordered_records,
                        evidence.cli_control_data_sockets,
                        evidence.same_uuid_tenant_isolation_verified,
                        evidence.authorization_negatives_rejected,
                        evidence.stale_owner_rejected,
                        evidence.key_revocation_rejected,
                        evidence.owner_death_interrupted,
                    );
                    let isolation = &evidence.tenant_isolation;
                    println!(
                        "M7 production concurrent tenant isolation: shared_device={} shared_service={} distinct_tenants={} distinct_credentials={} concurrent_owner_samples={} distinct_owner_nodes={} distinct_owner_sessions={} tenant_a_exact_canaries={} tenant_b_exact_canaries={} distinct_canaries={} cross_tenant_canary_absent={} tenant_a_rotations={} tenant_b_rotations={}",
                        isolation.shared_device_identifier,
                        isolation.shared_service_identifier,
                        isolation.distinct_tenant_scopes,
                        isolation.distinct_device_credentials,
                        isolation.concurrent_owner_samples,
                        isolation.distinct_owner_nodes,
                        isolation.distinct_owner_sessions,
                        isolation.tenant_a_exact_canaries,
                        isolation.tenant_b_exact_canaries,
                        isolation.distinct_canaries,
                        isolation.cross_tenant_canary_absent,
                        isolation.tenant_a_rotations,
                        isolation.tenant_b_rotations,
                    );
                    let race = &evidence.owner_race;
                    println!(
                        "M7 production duplicate owner race: concurrent_launches={} one_atomic_winner={} control_conflict_delta={} control_conflict_delta_after_settle={} loser_owner_busy={} loser_non_success={} winner_token_unchanged={} winner_canary={} tenant_sibling_preserved={} same_identifier_owner_unchanged={} same_identifier_canary={} winner_epoch={} successor_epoch={} successor_higher_epoch={} epochs_above_js_safe_bound={} stale_cleanup_rejected={} successor_canary={} elapsed_ms={}",
                        race.concurrent_launches,
                        race.one_atomic_winner,
                        race.control_conflict_delta,
                        race.control_conflict_delta_after_settle,
                        race.loser_terminal_owner_busy,
                        race.loser_exit_non_success,
                        race.winner_token_unchanged,
                        race.winner_canary_preserved,
                        race.tenant_sibling_preserved,
                        race.same_identifier_tenant_owner_unchanged,
                        race.same_identifier_tenant_canary_preserved,
                        race.winner_epoch,
                        race.successor_epoch,
                        race.successor_higher_epoch,
                        race.epochs_above_js_safe_bound,
                        race.stale_cleanup_rejected,
                        race.successor_canary,
                        race.elapsed_ms,
                    );
                    let liveness = &evidence.liveness;
                    println!(
                        "M7 production heartbeat/liveness/shutdown: owner_lease_ms={} heartbeat_window_ms=[{},{}] heartbeat_owner_tokens={} heartbeat_round_trips={} heartbeat_intervals={} longest_heartbeat_run={} observed_interval_ms=[{},{}] intervals_within_bounds={} livez={}/{} readyz_ready={} readyz_unready={}/{} live_while_unready={} cli_shutdown_join_ms={} cli_shutdown_bound_ms={} cli_shutdown_within_bound={} cli_shutdown_graceful_exit={} cli_shutdown_owner_released={}",
                        liveness.owner_lease_ms,
                        liveness.heartbeat_minimum_interval_ms,
                        liveness.heartbeat_maximum_interval_ms,
                        liveness.heartbeat_owner_tokens,
                        liveness.heartbeat_round_trips,
                        liveness.heartbeat_intervals,
                        liveness.longest_heartbeat_run_intervals,
                        liveness.observed_minimum_interval_ms,
                        liveness.observed_maximum_interval_ms,
                        liveness.heartbeat_intervals_within_bounds,
                        liveness.livez_live,
                        liveness.livez_probes,
                        liveness.readyz_ready,
                        liveness.readyz_unready,
                        liveness.readyz_probes,
                        liveness.liveness_up_while_readiness_false,
                        liveness.cli_shutdown_join_ms,
                        liveness.cli_shutdown_join_bound_ms,
                        liveness.cli_shutdown_joined_within_bound,
                        liveness.cli_shutdown_graceful_exit,
                        liveness.cli_shutdown_owner_released,
                    );
                }),
                Err(_) => Err(HarnessError::Process(
                    "M7 production acceptance exceeded 300 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-i08-partial-response-rotation" => {
            tunnel_test_harness::production_cluster::verify_i08_partial_response_rotation()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_i08_partial_response_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 I08 partial-response rotation passed: relays={} ingress={} owner={} session={} epoch={} stream={} operation={} fid={} synthetic_operation={} request_record_bytes={} response_record_bytes={} response_frames={} resume_unit={} byte_cursor_resume_supported={} responses_delivered={} checksums_matched={} multi_chunk={} bracketing_commit={} partial_resume_offsets={:?} cursor_gaps={} duplicated_bytes={} rotations_retaining_replay={} rotations={} adapter_shutdown_phase={} adapter_shutdown_in_overlap={} adapter_shutdown_graceful={} post_shutdown_outcome={} socket_high_water={} cleanup_joined={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.public_ingress_relay,
                        evidence.owner_relay,
                        evidence.session_id,
                        evidence.epoch,
                        evidence.stream_id,
                        evidence.tunnel_operation_id,
                        evidence.synthetic_fid,
                        evidence.synthetic_operation_id,
                        evidence.request_record_bytes,
                        evidence.response_record_bytes,
                        evidence.response_frames,
                        evidence.resume_unit,
                        evidence.byte_cursor_resume_supported,
                        evidence.responses_delivered,
                        evidence.responses_checksum_matched,
                        evidence.responses_multi_chunk,
                        evidence.responses_bracketing_commit,
                        evidence.partial_resume_offsets,
                        evidence.cursor_gaps,
                        evidence.duplicated_bytes,
                        evidence.rotations_retaining_replay,
                        evidence.rotations.len(),
                        evidence.adapter_shutdown_phase,
                        evidence.adapter_shutdown_in_overlap,
                        evidence.adapter_shutdown_graceful,
                        evidence.post_shutdown_outcome,
                        evidence.socket_high_water,
                        evidence.cleanup_joined,
                        evidence.elapsed_ms,
                    );
                    for rotation in &evidence.rotations {
                        println!(
                            "M7 I08 partial rotation: number={} old_generation={} new_generation={} relay_fence={} relay_ack={} connector_fence={} connector_ack={} candidate_ready={} commit_accepted={} old_closed={} replay_frames={}",
                            rotation.rotation,
                            rotation.attempt.old_generation,
                            rotation.attempt.new_generation,
                            rotation.relay_fence_sequence,
                            rotation.relay_ack_sequence,
                            rotation.connector_fence_sequence,
                            rotation.connector_ack_sequence,
                            rotation.candidate_ready,
                            rotation.commit_accepted,
                            rotation.old_socket_closed,
                            rotation.replay_frames,
                        );
                    }
                    Ok(())
                })
        }
        [command] if command == "verify-m7-i08-synthetic-rotation" => {
            tunnel_test_harness::production_cluster::verify_i08_synthetic_rotation()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_i08_evidence(&evidence)?;
                    println!(
                        "M7 I08 synthetic echo rotation passed: relays={} ingress={} owner={} cli={} session={} epoch={} stream={} operation={} fid={} synthetic_operation={} records={} checksums={} rotations={} socket_high_water={} replay_frames={} cleanup_joined={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.public_ingress_relay,
                        evidence.owner_relay,
                        evidence.actual_cli_process,
                        evidence.session_id,
                        evidence.epoch,
                        evidence.stream_id,
                        evidence.tunnel_operation_id,
                        evidence.synthetic_fid,
                        evidence.synthetic_operation_id,
                        evidence.records_echoed,
                        evidence.checksums_verified,
                        evidence.rotations.len(),
                        evidence.socket_high_water,
                        evidence.replay_frames,
                        evidence.cleanup_joined,
                        evidence.elapsed_ms,
                    );
                    for rotation in &evidence.rotations {
                        println!(
                            "M7 I08 rotation: number={} owner_id={} attempt_rotation_id={} attempt_session={} attempt_epoch={} old_generation={} new_generation={} old_connection={} new_connection={} generation={} connection={} snapshot={} latch_observed={} relay_fence={} connector_fence={} relay_ack={} connector_ack={} flush={:?} candidate_ready={} commit_sent={} commit_accepted={} old_closed={} runtime_socket_high_water={} replay_frames={}",
                            rotation.rotation,
                            rotation.attempt.owner_id,
                            rotation.attempt.rotation_id,
                            rotation.attempt.session_id,
                            rotation.attempt.epoch,
                            rotation.attempt.old_generation,
                            rotation.attempt.new_generation,
                            rotation.attempt.old_connection_id,
                            rotation.attempt.new_connection_id,
                            rotation.active_generation,
                            rotation.active_connection_id,
                            rotation.snapshot_id,
                            rotation.completed_latch_observed,
                            rotation.relay_fence_digest,
                            rotation.connector_fence_digest,
                            rotation.relay_ack_sequence,
                            rotation.connector_ack_sequence,
                            rotation.writer_barrier_flushed,
                            rotation.candidate_ready,
                            rotation.commit_sent,
                            rotation.commit_accepted,
                            rotation.old_socket_closed,
                            rotation.runtime_socket_high_water,
                            rotation.replay_frames,
                        );
                    }
                    Ok(())
                })
        }
        [command] if command == "verify-m7-i08-goaway-rotation" => {
            // The verifier owns startup, scenario, and bounded cleanup
            // deadlines.  Do not cancel it from an outer timeout and drop its
            // live cluster/process handles before those joins complete.
            tunnel_test_harness::production_cluster::verify_i08_goaway_rotation()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_i08_goaway_rotation_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 I08 GOAWAY rotation passed: scope={} relays={} cli={} owner={} ingress={} tenant={} device={} service={} session={} epoch={} stream={} operation={} candidate_generation={} candidate_connection={} rotation_before={} rotation_after={} goaway_peer={} goaway_connection={} active_stream={} planned_goaway={} admitted_response={} post_goaway_not_dispatched={} ingress_goaway_observed={} post_goaway_dispatch_delta={} later_request_dispatch_delta={} cli_survived={} socket_high_water={} cleanup_joined={} elapsed_ms={}",
                        evidence.scope,
                        evidence.relay_count,
                        evidence.actual_cli_process,
                        evidence.owner_relay,
                        evidence.ingress_relay,
                        evidence.tenant_id,
                        evidence.device_id,
                        evidence.service_id,
                        evidence.session_id,
                        evidence.epoch,
                        evidence.stream_id,
                        evidence.operation_id,
                        evidence.candidate_generation,
                        evidence.candidate_connection_id,
                        evidence.rotation_before,
                        evidence.rotation_after,
                        evidence.goaway_peer_node_id,
                        evidence.goaway_connection_id,
                        evidence.active_stream_observed,
                        evidence.planned_goaway_sent,
                        evidence.admitted_response_completed,
                        evidence.post_goaway_not_dispatched,
                        evidence.ingress_goaway_observed,
                        evidence.post_goaway_dispatch_delta,
                        evidence.later_request_dispatch_delta,
                        evidence.cli_survived,
                        evidence.socket_high_water,
                        evidence.cleanup_joined,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-i08-rotation-faults" => {
            tunnel_test_harness::production_cluster::verify_i08_rotation_faults()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_i08_rotation_fault_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 I08 rotation fault passed: relays={} cli={} planned_retirements={} planned_generation={} planned_connection={} planned_fence_ack={} planned_old_closed={} planned_alive={} planned_no_retry={} fault_relay={} fault_route={} fault_generation={} fault_connection={} fault_closed={} control_route_open={} outcome={} failure_code={:?} failure_retryable={:?} recovery_trigger={:?} same_session_recovered={} recovered_generation={:?} control_stable={} stream_stable={} post_owner_snapshot={} post_terminal={} post_stream_state={} post_owner_released={} post_dispatch_count={} ordered_records={} goaway_tested={} goaway_separate={} cleanup_joined={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.actual_cli_process,
                        evidence.planned_rotations,
                        evidence.planned_generation,
                        evidence.planned_connection_id,
                        evidence.planned_fence_acknowledged,
                        evidence.planned_old_carrier_closed,
                        evidence.planned_process_stayed_alive,
                        evidence.planned_no_whole_session_retry,
                        evidence.unexpected_fault_relay,
                        evidence.unexpected_fault_route_index,
                        evidence.unexpected_fault_generation,
                        evidence.unexpected_fault_connection_id,
                        evidence.unexpected_active_carrier_closed,
                        evidence.control_route_remained_open,
                        evidence.unexpected_outcome,
                        evidence.unexpected_failure_code,
                        evidence.unexpected_failure_retryable,
                        evidence.unexpected_failure_trigger,
                        evidence.same_session_recovered,
                        evidence.recovered_generation,
                        evidence.control_socket_stable,
                        evidence.stream_identity_stable,
                        evidence.post_fault_owner_snapshot_observed,
                        evidence.post_fault_session_terminal_observed,
                        evidence.post_fault_stream_state_observed,
                        evidence.post_fault_catalog_owner_released,
                        evidence.post_fault_dispatch_count,
                        evidence.ordered_records,
                        evidence.goaway_tested,
                        evidence.goaway_is_separate_scope,
                        evidence.cleanup_joined,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-i08-recovery-attempts" => {
            tunnel_test_harness::production_cluster::verify_i08_recovery_attempts()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_i08_recovery_attempt_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 I08 recovery exhaustion passed: {}",
                        evidence.exhaustion.summary()
                    );
                    println!(
                        "M7 I08 recovery retry passed: {}",
                        evidence.retry_success.summary()
                    );
                    println!(
                        "M7 I08 recovery attempts passed: episodes=2 cleanup_joined={} elapsed_ms={}",
                        evidence.cleanup_joined, evidence.elapsed_ms
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-admission-framing" => {
            tunnel_test_harness::production_cluster::verify_c10_actual_path().await.and_then(|evidence| {
                tunnel_test_harness::production_cluster::validate_c10_actual_path_evidence(&evidence)?;
                println!("M7 admission framing passed: relays={} fresh_control={} fresh_epoch={} empty_single_prefix={} empty_owner_read={} empty_dispatch={:?} unary_exact={} unary_owner_read={} unary_dispatch={:?} truncated_read={} truncated_not_dispatched={} raw_bearer_owner_revalidated={} owner_token_changed_before_101={} owner_change_pre_101_rejected={} owner_change_pre_101_not_dispatched={} owner_change_pre_101_body_not_polled={} cleanup_joined={}", evidence.relay_count, evidence.fresh_control_after_no_live_owner, evidence.fresh_epoch_advanced, evidence.empty_body_single_prefix, evidence.empty_body_owner_read, evidence.empty_body_dispatch_delta, evidence.empty_unary_body_response_exact, evidence.empty_unary_body_owner_read, evidence.empty_unary_body_dispatch_delta, evidence.truncated_body_owner_read, evidence.truncated_body_not_dispatched, evidence.raw_bearer_owner_revalidated, evidence.owner_token_changed_before_101, evidence.owner_change_pre_101_rejected, evidence.owner_change_pre_101_not_dispatched, evidence.owner_change_pre_101_body_not_polled, evidence.cleanup_joined);
                Ok(())
            })
        }
        [command] if command == "verify-m7-ec041-device-attachment" => {
            // The verifier owns its own bounded scenario deadline and joins
            // every socket, barrier and relay in cleanup, so it must not be
            // dropped mid-join by an outer timeout.
            tunnel_test_harness::production_cluster::verify_ec041_device_attachment()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_ec041_device_attachment_evidence(&evidence)?;
                    println!(
                        "M7 EC-041 device attachment race passed: relays={} predecessor_owner={} successor_owner={} full_owner_replaced={} predecessor_gen={} successor_gen={} stale_rejected={} stale_data_ready_absent={} stale_session_unchanged={} distinct_ingress={} winner_count={} loser_count={} data_ready_count={} winner_gen={} winner_carrier_installed={} loser_no_counter_reset={} reuse_rejected={} reuse_data_ready_absent={} control_barrier_held={} control_barrier_hits={} control_owner_changed_while_held={} control_interloper_owner={} control_revalidated={} control_outcome={:?} control_single_owner={} control_no_stale_welcome={} winner_stream_count={} winner_cursors_advanced={} winner_cursors_unchanged={} loser_no_stream_row={} cleanup_joined={}",
                        evidence.relay_count,
                        evidence.predecessor_owner_complete,
                        evidence.successor_owner_complete,
                        evidence.full_owner_token_replaced,
                        evidence.predecessor_generation,
                        evidence.successor_generation,
                        evidence.stale_ticket_rejected,
                        evidence.stale_data_ready_absent,
                        evidence.stale_session_state_unchanged,
                        evidence.concurrent_used_distinct_ingress,
                        evidence.concurrent_winner_count,
                        evidence.concurrent_loser_count,
                        evidence.concurrent_data_ready_count,
                        evidence.winner_generation,
                        evidence.winner_carrier_installed,
                        evidence.loser_caused_no_counter_reset,
                        evidence.fresh_ticket_reuse_rejected,
                        evidence.fresh_ticket_reuse_data_ready_absent,
                        evidence.control_attach_barrier_held,
                        evidence.control_attach_barrier_hits,
                        evidence.control_owner_changed_while_held,
                        evidence.control_interloper_owner_node_matched,
                        evidence.control_attach_revalidated,
                        evidence.control_attach_outcome,
                        evidence.control_single_owner_after_race,
                        evidence.control_no_stale_owner_welcome,
                        evidence.winner_stream_count,
                        evidence.winner_stream_cursors_advanced,
                        evidence.winner_stream_cursors_unchanged,
                        evidence.loser_created_no_stream_row,
                        evidence.cleanup_joined,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-ec025-handover" => {
            // The verifier owns its own bounded scenario deadline and joins
            // every connector, barrier and relay in cleanup.
            tunnel_test_harness::production_cluster::verify_ec025_handover()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_ec025_handover_evidence(&evidence)?;
                    println!(
                        "M7 EC-025 cross-relay handover passed: relays={} ingress_not_owner={} owner_unchanged={} baseline_exact_owner={} exact_owner_scope_observed={} barrier_completed_exact_owner={} peer_delay_typed_not_dispatched={} peer_delay_zero_dispatch={} rotation_observed={} across_rotation_no_foreign_dispatch={} across_rotation_completed_or_typed={} across_rotation_completed={} across_rotation_interrupted={} across_rotation_not_dispatched={} trust_crossing_scope_observed={} trust_crossing_healthy_baseline={} trust_crossing_withdrawn_while_held={} trust_crossing_still_held={} trust_crossing_status={} trust_crossing_code={} trust_crossing_execution={} trust_crossing_delta_a={} trust_crossing_delta_b={} trust_crossing_delta_c={} trust_crossing_owner_delta={} trust_crossing_fault_role={} trust_crossing_fault_stage={} trust_crossing_fault_cause={} cleanup_joined={}",
                        evidence.relay_count,
                        evidence.ingress_is_not_owner,
                        evidence.owner_node_unchanged,
                        evidence.baseline_exact_owner_dispatch,
                        evidence.exact_owner_scope_observed,
                        evidence.barrier_completed_exact_owner,
                        evidence.peer_delay_typed_not_dispatched,
                        evidence.peer_delay_zero_dispatch,
                        evidence.rotation_observed,
                        evidence.across_rotation_no_foreign_dispatch,
                        evidence.across_rotation_completed_or_typed,
                        evidence.across_rotation_completed,
                        evidence.across_rotation_interrupted,
                        evidence.across_rotation_not_dispatched,
                        evidence.trust_crossing.scope_observed,
                        evidence.trust_crossing.healthy_baseline_completed,
                        evidence.trust_crossing.withdrawn_while_held,
                        evidence.trust_crossing.still_held_at_withdrawal,
                        evidence.trust_crossing.refusal_status,
                        evidence.trust_crossing.refusal_code.as_deref().unwrap_or("-"),
                        evidence
                            .trust_crossing
                            .refusal_execution
                            .as_deref()
                            .unwrap_or("-"),
                        evidence.trust_crossing.dispatch_delta[0],
                        evidence.trust_crossing.dispatch_delta[1],
                        evidence.trust_crossing.dispatch_delta[2],
                        evidence.trust_crossing.owner_dispatch_delta,
                        evidence.trust_crossing.fault_role.as_deref().unwrap_or("-"),
                        evidence.trust_crossing.fault_stage.as_deref().unwrap_or("-"),
                        evidence.trust_crossing.fault_cause.as_deref().unwrap_or("-"),
                        evidence.cleanup_joined,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-ec023-owner-death" => {
            // The verifier owns its own bounded scenario deadline and joins
            // every connector, barrier and relay in cleanup.
            tunnel_test_harness::production_cluster::verify_ec023_owner_death()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_ec023_owner_death_evidence(&evidence)?;
                    println!(
                        "M7 EC-023 owner death passed: relays={} control_barrier_hit={} control_owner_killed={} control_typed_outcome={} control_no_upgrade={} control_dispatch_delta={} control_owner_cleared={} control_no_stale_session={} control_fresh_identity={} data_barrier_hit={} data_owner_killed={} data_not_dispatched={} data_no_upgrade={} data_dispatch_delta={} data_owner_cleared={} data_no_stale_session={} data_fresh_identity={} fresh_ownership_recovered={} recovery_dispatch_delta={} cleanup_joined={}",
                        evidence.relay_count,
                        evidence.control_admission_barrier_hit,
                        evidence.control_owner_killed,
                        evidence.control_typed_outcome,
                        evidence.control_no_upgrade,
                        evidence.control_dispatch_delta,
                        evidence.control_owner_cleared,
                        evidence.control_no_stale_session,
                        evidence.control_owner_identity_required_fresh,
                        evidence.data_attach_barrier_hit,
                        evidence.data_owner_killed,
                        evidence.data_typed_not_dispatched,
                        evidence.data_no_upgrade,
                        evidence.data_dispatch_delta,
                        evidence.data_owner_cleared,
                        evidence.data_no_stale_session,
                        evidence.data_owner_identity_required_fresh,
                        evidence.fresh_ownership_recovered,
                        evidence.recovery_dispatch_delta,
                        evidence.cleanup_joined,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-admission" => {
            match tokio::time::timeout(
                Duration::from_secs(180),
                tunnel_test_harness::production_cluster::verify_public_admission(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_admission_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 public admission passed: relays={} baseline_target_dispatches={} baseline_sibling_dispatches={} negative_dispatch_delta={} lookup_error_dispatch_delta={} owner_loss_dispatch_delta={} sibling_dispatch_delta_after_owner_loss={} absent_target_rejected={} inactive_target_rejected={} unknown_target_rejected={} selected_owner_unavailable={} route_allowlist_rejected={} forged_identity_headers_ignored={} forged_identity_http_headers_ignored={} forged_identity_http_cross_scope_rejected={} lookup_error_rejected={} sibling_canary_survived={} cleanup_joined={}",
                        evidence.relay_count,
                        evidence.baseline_target_dispatches,
                        evidence.baseline_sibling_dispatches,
                        evidence.negative_dispatch_delta,
                        evidence.lookup_error_dispatch_delta,
                        evidence.owner_loss_dispatch_delta,
                        evidence.sibling_dispatch_delta_after_owner_loss,
                        evidence.absent_target_rejected,
                        evidence.inactive_target_rejected,
                        evidence.unknown_target_rejected,
                        evidence.selected_owner_unavailable,
                        evidence.route_allowlist_rejected,
                        evidence.forged_identity_headers_ignored,
                        evidence.forged_identity_http_headers_ignored,
                        evidence.forged_identity_http_cross_scope_rejected,
                        evidence.lookup_error_rejected,
                        evidence.sibling_canary_survived,
                        evidence.cleanup_joined,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 public admission acceptance exceeded 180 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-i04-fail-closed" => {
            match tokio::time::timeout(
                Duration::from_secs(300),
                tunnel_test_harness::production_cluster::verify_fail_closed_admission(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_fail_closed_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 I04 fail-closed admission passed: relays={} remote_ingress_is_not_owner={} baseline_target_dispatches={} baseline_sibling_dispatches={} body_read_control={} body_read_control_dispatch_delta={} body_read_control_owner_chunk_read_delta={} absent_device={} unknown_service={} inactive_device={} ambiguous_service={} unambiguous_label_status={} unambiguous_label_response_exact={} caller_destination={} ambiguous_stream={} ambiguous_listing_status={} ambiguous_listing_active_echo_services={} ec003_dispatch_delta={} ec003_owner_chunk_read_delta={} remote_route_proved={} forged_endpoint_response_exact={} forged_endpoint_udp_datagrams={} forged_endpoint_tcp_connections={} peer_connection_server_name_from_membership={} preflight_cross_scope={} preflight_dispatch_delta={} preflight_owner_chunk_read_delta={} empty_body_status={} empty_body_response_exact={} empty_body_dispatch_delta={} empty_body_owner_chunk_read_delta={} failed_body={} failed_body_dispatch_delta={} failed_body_owner_chunk_read_delta={} empty_and_failed_body_distinct={} safe_no_body_status={} owner_loss_consumed_mutation={} owner_loss_consumed_mutation_repeat={} owner_loss_safe_unpolled={} owner_loss_failed_body={} owner_loss_safe_methods=[{}] owner_loss_head_mirrors_typed_get={} owner_loss_safe_method_dispatch_delta={} owner_loss_safe_method_owner_chunk_read_delta={} owner_loss_dispatch_delta={} owner_loss_owner_chunk_read_delta={} mutation_reselected={} safe_retry_attempts={} safe_retry_succeeded={} safe_retry_dispatch_delta={} owner_process_killed={} inflight_kill_dispatch_delta={} inflight_kill_outcome_classified={} post_kill_probe={} post_kill_dispatch_delta={} owner_identity_required_fresh={} sibling_dispatch_delta_after_owner_kill={} sibling_canary_survived={} advertised_public_routes={} excluded_public_routes_typed={} route_boundary_dispatch_delta={} excluded_browser_boundary_recorded={} elapsed_ms={} cleanup_joined={}",
                        evidence.relay_count,
                        evidence.remote_ingress_is_not_owner,
                        evidence.baseline_target_dispatches,
                        evidence.baseline_sibling_dispatches,
                        fail_closed_outcome(&evidence.body_read_control),
                        evidence.body_read_control_dispatch_delta,
                        evidence.body_read_control_owner_chunk_read_delta,
                        fail_closed_outcome(&evidence.absent_device),
                        fail_closed_outcome(&evidence.unknown_service),
                        fail_closed_outcome(&evidence.inactive_device),
                        fail_closed_outcome(&evidence.ambiguous_service),
                        evidence.unambiguous_label_status,
                        evidence.unambiguous_label_response_exact,
                        fail_closed_outcome(&evidence.caller_destination),
                        fail_closed_outcome(&evidence.ambiguous_stream),
                        evidence.ambiguous_listing_status,
                        evidence.ambiguous_listing_active_echo_services,
                        evidence.ec003_dispatch_delta,
                        evidence.ec003_owner_chunk_read_delta,
                        evidence.remote_route_proved,
                        evidence.forged_endpoint_response_exact,
                        evidence.forged_endpoint_udp_datagrams,
                        evidence.forged_endpoint_tcp_connections,
                        evidence.peer_connection_server_name_from_membership,
                        fail_closed_outcome(&evidence.preflight_cross_scope),
                        evidence.preflight_dispatch_delta,
                        evidence.preflight_owner_chunk_read_delta,
                        evidence.empty_body_status,
                        evidence.empty_body_response_exact,
                        evidence.empty_body_dispatch_delta,
                        evidence.empty_body_owner_chunk_read_delta,
                        fail_closed_outcome(&evidence.failed_body),
                        evidence.failed_body_dispatch_delta,
                        evidence.failed_body_owner_chunk_read_delta,
                        evidence.empty_and_failed_body_distinct,
                        evidence.safe_no_body_status,
                        fail_closed_outcome(&evidence.owner_loss_consumed_mutation),
                        fail_closed_outcome(&evidence.owner_loss_consumed_mutation_repeat),
                        fail_closed_outcome(&evidence.owner_loss_safe_unpolled),
                        fail_closed_outcome(&evidence.owner_loss_failed_body),
                        evidence
                            .owner_loss_safe_methods
                            .iter()
                            .map(fail_closed_outcome)
                            .collect::<Vec<_>>()
                            .join(","),
                        evidence.owner_loss_head_mirrors_typed_get,
                        evidence.owner_loss_safe_method_dispatch_delta,
                        evidence.owner_loss_safe_method_owner_chunk_read_delta,
                        evidence.owner_loss_dispatch_delta,
                        evidence.owner_loss_owner_chunk_read_delta,
                        evidence.mutation_reselected,
                        evidence.safe_retry_attempts,
                        evidence.safe_retry_succeeded,
                        evidence.safe_retry_dispatch_delta,
                        evidence.owner_process_killed,
                        evidence.inflight_kill_dispatch_delta,
                        evidence.inflight_kill_outcome_classified,
                        fail_closed_outcome(&evidence.post_kill_probe),
                        evidence.post_kill_dispatch_delta,
                        evidence.owner_identity_required_fresh,
                        evidence.sibling_dispatch_delta_after_owner_kill,
                        evidence.sibling_canary_survived,
                        evidence.advertised_public_routes,
                        evidence.excluded_public_routes_typed,
                        evidence.route_boundary_dispatch_delta,
                        evidence.excluded_browser_boundary_recorded,
                        evidence.elapsed_ms,
                        evidence.cleanup_joined,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 I04 fail-closed admission acceptance exceeded 300 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-device-revocation" => {
            tunnel_test_harness::production_cluster::verify_device_revocation().await.and_then(
                |evidence| {
                    tunnel_test_harness::production_cluster::validate_device_revocation_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 live device credential revocation passed: credential_revoked={} existing_stream_terminated={} owner_released={} ingress_rejected={} owner_dispatch_unchanged={} sibling_owner_unchanged={} sibling_stream_survived={} elapsed_ms={}",
                        evidence.credential_revoked,
                        evidence.existing_stream_terminated,
                        evidence.owner_released,
                        evidence.ingress_rejected,
                        evidence.owner_dispatch_unchanged,
                        evidence.sibling_owner_unchanged,
                        evidence.sibling_stream_survived,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                },
            )
        }
        [command] if command == "verify-m7-credential-expiry-rotation" => {
            tunnel_test_harness::production_cluster::verify_credential_expiry_rotation()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_credential_expiry_rotation_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 consumer credential expiry during active rotation passed: relays={} cli_processes={} ingress={} baseline_echo={} rotation_id={} active_at_expiry={} candidate_ready_at_expiry={} old_sockets_open_at_expiry={} session={} epoch={} owner_id={} old_generation={} new_generation={} expiry_ms={} token_expires_unix_ms={} rotation_deadline_ms={} consumer_remaining_ms={} grant_remaining_ms={} device_remaining_ms={} owner_safe_remaining_ms={} rotation_remaining_ms={} delay_injected={} token_identity_exact={} challenge_active_at_expiry={} challenge_started_ms={} challenge_deadline_ms={} challenge_admission_deadline_ms={} post_expiry_probe_attempted={} post_expiry_probe_after_expiry={} post_expiry_probe_at_unix_ms={} post_expiry_probe_outcome={} stream_terminal={} terminal_kind={} cause={} socket_transport_terminal={} ingress_rejected={} ingress_status={} ingress_code={} ingress_execution={} owner_retained={} owner_dispatch_delta={} rotation_completion_latch={} completion_id={} completion_session={} completion_epoch={} completion_owner_id={} rotation_completed_after_expiry={} sibling_owner_retained={} sibling_stream_survived={} sibling_echo={} cleanup_joined={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.actual_cli_processes,
                        evidence.public_ingress,
                        evidence.baseline_echo,
                        evidence.rotation_id,
                        evidence.rotation_active_at_expiry,
                        evidence.rotation_candidate_ready_at_expiry,
                        evidence.rotation_old_sockets_open_at_expiry,
                        evidence.rotation_session_id,
                        evidence.rotation_epoch,
                        evidence.rotation_owner_id,
                        evidence.rotation_old_generation,
                        evidence.rotation_new_generation,
                        evidence.expiry_observed_at_ms,
                        evidence.consumer_token_expires_at_unix_ms,
                        evidence.rotation_deadline_ms,
                        evidence.consumer_remaining_ms,
                        evidence.grant_remaining_ms,
                        evidence.device_credential_remaining_ms,
                        evidence.owner_safe_remaining_ms,
                        evidence.rotation_remaining_ms,
                        evidence.authorization_delay_injected,
                        evidence.token_identity_exact,
                        evidence.challenge_active_at_expiry,
                        evidence.challenge_started_at_ms,
                        evidence.challenge_deadline_ms,
                        evidence.challenge_admission_deadline_ms,
                        evidence.post_expiry_probe_attempted,
                        evidence.post_expiry_probe_after_expiry,
                        evidence.post_expiry_probe_at_unix_ms,
                        evidence.post_expiry_probe_outcome,
                        evidence.expired_stream_terminal,
                        evidence.expired_terminal_kind,
                        evidence.expired_stream_cause,
                        evidence.expired_transport_terminal,
                        evidence.expired_ingress_rejected,
                        evidence.expired_ingress_status,
                        evidence.expired_ingress_code,
                        evidence.expired_ingress_execution,
                        evidence.owner_token_retained,
                        evidence.owner_dispatch_after
                            .saturating_sub(evidence.owner_dispatch_before),
                        evidence.rotation_completion_latch_observed,
                        evidence.rotation_completion_id,
                        evidence.rotation_completion_session_id,
                        evidence.rotation_completion_epoch,
                        evidence.rotation_completion_owner_id,
                        evidence.rotation_completed_after_expiry,
                        evidence.sibling_owner_retained,
                        evidence.sibling_stream_survived,
                        evidence.sibling_echo,
                        evidence.cleanup_joined,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-side-effect" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_side_effect(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_side_effect_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 synthetic ordered-stream side-effect passed: relays={} raw_requests={} effects={} response_attempted={} response_frames_locally_accepted={} consumer_interrupted_or_unknown={} owner_retained={} duplicate_requests={} post_failure_effects={} consumer_terminal={} consumer_observation_elapsed_ms={} consumer_observation_deadline_ms={}",
                        evidence.relay_count,
                        evidence.raw_request_observations,
                        evidence.backend_effect_invocations,
                        evidence.response_send_attempted,
                        evidence.response_frames_sent,
                        evidence.consumer_interrupted_or_unknown,
                        evidence.owner_token_retained_after_failure,
                        evidence.duplicate_request_observations,
                        evidence.post_failure_effect_invocations,
                        evidence.consumer_terminal,
                        evidence.consumer_observation_elapsed_ms,
                        evidence.consumer_observation_deadline_ms,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 synthetic side-effect acceptance exceeded 240 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-side-effect-late" => {
            tunnel_test_harness::production_cluster::verify_side_effect_late()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_late_response_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 late DATA/FIN boundary passed: relays={} owner={} ingress={} tenant={} device={} session={} epoch={} generation={} connection={} stream={} operation={} service={} data_attempts={} data_accepted={} data_rejected={} fin_attempts={} fin_accepted={} fin_rejected={} owner_recv_before={} owner_recv_after={} owner_delivered_before={} owner_delivered_after={} owner_receive_terminal_sequence={} owner_receipt_request_id={} terminal_evidence_source={} terminal_stream_latched={} consumer_terminal={} cleanup_joined={}",
                        evidence.relay_count,
                        evidence.owner_relay,
                        evidence.ingress_relay,
                        evidence.tenant_id,
                        evidence.device_id,
                        evidence.session_id,
                        evidence.epoch,
                        evidence.generation,
                        evidence.connection_id,
                        evidence.stream_id,
                        evidence.operation_id,
                        evidence.service_id,
                        evidence.data_attempts,
                        evidence.data_write_accepted,
                        evidence.data_write_rejected,
                        evidence.fin_attempts,
                        evidence.fin_write_accepted,
                        evidence.fin_write_rejected,
                        evidence.owner_recv_contiguous_before,
                        evidence.owner_recv_contiguous_after,
                        evidence.owner_delivered_contiguous_before,
                        evidence.owner_delivered_contiguous_after,
                        evidence.owner_receive_terminal_sequence,
                        evidence.owner_receipt_request_id,
                        evidence.terminal_evidence_source,
                        evidence.terminal_stream_latched,
                        evidence.consumer_terminal,
                        evidence.cleanup_joined,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-public-abandoned-upgrade" => {
            tunnel_test_harness::production_cluster::verify_public_abandoned_upgrade()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_public_abandoned_upgrade_evidence(
                            &evidence,
                        )?;
                    println!(
                        "M7 public abandoned upgrade passed: scope={} relays={} cli_processes={} owner_local_barrier={} owner_local_hits={} owner_local_response_bytes={} owner_local_no_101={} owner_local_registration={} owner_local_unclaimed={} owner_local_reclaimed={} owner_local_dispatch_delta={} owner_local_capacity_status={} owner_local_capacity_admission_limit={} owner_local_capacity_not_dispatched={} remote_barrier={} remote_hits={} remote_response_bytes={} remote_no_101={} remote_registration={} remote_claimed={} remote_reclaimed={} remote_dispatch_delta={} remote_capacity_status={} remote_capacity_admission_limit={} remote_capacity_not_dispatched={} sibling_baseline={} sibling_recovery={} cleanup_joined={}",
                        evidence.scope,
                        evidence.relay_count,
                        evidence.actual_cli_processes,
                        evidence.owner_local_barrier_reached,
                        evidence.owner_local_barrier_hits,
                        evidence.owner_local_response_bytes_before_close,
                        evidence.owner_local_no_http_101_observed,
                        evidence.owner_local_registration_observed,
                        evidence.owner_local_registration_unclaimed_before_close,
                        evidence.owner_local_registration_reclaimed,
                        evidence.owner_local_application_dispatch_delta,
                        evidence.owner_local_capacity_status,
                        evidence.owner_local_capacity_admission_limit,
                        evidence.owner_local_capacity_not_dispatched,
                        evidence.remote_barrier_reached,
                        evidence.remote_barrier_hits,
                        evidence.remote_response_bytes_before_close,
                        evidence.remote_no_http_101_observed,
                        evidence.remote_registration_observed,
                        evidence.remote_registration_claimed_before_close,
                        evidence.remote_registration_reclaimed,
                        evidence.remote_application_dispatch_delta,
                        evidence.remote_capacity_status,
                        evidence.remote_capacity_admission_limit,
                        evidence.remote_capacity_not_dispatched,
                        evidence.sibling_baseline_echo,
                        evidence.sibling_recovery_echo,
                        evidence.cleanup_joined,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-peer-fragmentation" => {
            match tokio::time::timeout(
                Duration::from_secs(180),
                tunnel_test_harness::peer_fragmentation::verify(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    evidence.validate()?;
                    println!(
                        "M7 peer fragmentation passed: synthetic_identities={} authenticated_http3={} prefix_splits={} body_splits={} coalesced_records={} malformed_cases={} malformed_dispatches={} exact_bytes={} order_preserved={} sibling_progress={} budget_reclaimed={} cleanup_joined={}",
                        evidence.relay_count,
                        evidence.authenticated_http3,
                        evidence.fragmented_prefix_cases,
                        evidence.fragmented_body_cases,
                        evidence.coalesced_records,
                        evidence.malformed_cases,
                        evidence.malformed_dispatches,
                        evidence.exact_bytes,
                        evidence.order_preserved,
                        evidence.sibling_progress,
                        evidence.budget_reclaimed,
                        evidence.cleanup_joined,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 peer-fragmentation acceptance exceeded 180 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-ec044-peer-frames" => {
            match tokio::time::timeout(
                Duration::from_secs(180),
                tunnel_test_harness::peer_frames::verify(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    evidence.validate()?;
                    println!("{}", evidence.evidence_line());
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 EC-044 peer-frame acceptance exceeded 180 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-saturated-peer-frames" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::peer_frames::saturated::verify(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    evidence.validate()?;
                    println!("{}", evidence.evidence_line());
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 saturated peer-frame acceptance exceeded 240 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-concurrent-load" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_concurrent_load(),
            )
            .await
            {
                Ok(result) => result.map(|evidence| {
                    println!("M7 concurrent load passed: {evidence:?}");
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 concurrent load acceptance exceeded 240 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-owner-loss-effect" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_owner_loss_effect(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_fp05_evidence(&evidence)?;
                    println!(
                        "M7 owner-loss effect passed: owner_death={} evidence={evidence:?}",
                        evidence.owner_shutdown && evidence.owner_loss_close_observed,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 owner-loss effect acceptance exceeded 240 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-successor-pending-owner" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_successor_pending_owner(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_successor_pending_owner_evidence(
                        &evidence,
                    )?;
                    println!("M7 successor pending owner passed: {evidence:?}");
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 successor pending owner acceptance exceeded 240 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-owner-local-capacity" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_owner_local_capacity(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_owner_local_capacity_evidence(
                        &evidence,
                    )?;
                    println!("M7 owner-local capacity passed: {evidence:?}");
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 owner-local capacity acceptance exceeded 240 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-peer-capacity" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_peer_capacity(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_peer_capacity_evidence(
                        &evidence,
                    )?;
                    println!("M7 peer capacity passed: {evidence:?}");
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 peer capacity acceptance exceeded 240 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-timing-boundaries" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_timing_boundaries(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_timing_boundary_evidence(
                        &evidence,
                    )?;
                    println!("M7 timing boundaries passed: {evidence:?}");
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 timing boundaries acceptance exceeded 240 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-pending-owner" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_pending_owner(),
            )
            .await
            {
                Ok(result) => result.map(|evidence| {
                    println!(
                        "M7 pending owner passed: relays={} pre_ready_status={} not_dispatched={} retryable={} retry_after_ms={} pre_ready_dispatch_deltas={:?} owner_preserved={} data_attached={} post_ready_status={} post_ready_dispatch_deltas={:?} canary={} cleanup_joined={}",
                        evidence.relay_count,
                        evidence.pre_ready_status,
                        evidence.pre_ready_execution_not_dispatched,
                        evidence.pre_ready_retryable,
                        evidence.pre_ready_retry_after_ms,
                        evidence.pre_ready_dispatch_deltas,
                        evidence.owner_token_preserved_after_release,
                        evidence.data_attached,
                        evidence.post_ready_status,
                        evidence.post_ready_dispatch_deltas,
                        evidence.post_ready_canary_matched,
                        evidence.cleanup_joined,
                    );
                    println!(
                        "M7 pending owner WSS: status={} upgrade_rejected={} application_body_sent={} peer_unavailable={} not_dispatched={} retryable={} retry_after_ms={} retry_after_seconds={} dispatch_deltas={:?}",
                        evidence.pre_ready_wss_status,
                        evidence.pre_ready_wss_upgrade_rejected,
                        evidence.pre_ready_wss_application_body_sent,
                        evidence.pre_ready_wss_peer_unavailable,
                        evidence.pre_ready_wss_execution_not_dispatched,
                        evidence.pre_ready_wss_retryable,
                        evidence.pre_ready_wss_retry_after_ms,
                        evidence.pre_ready_wss_retry_after_header_seconds,
                        evidence.pre_ready_wss_dispatch_deltas,
                    );
                    println!(
                        "M7 pending owner peer body reads: before_ready_http={:?} before_ready_wss={:?} after_ready={:?}",
                        evidence.pre_ready_consumer_chunk_read_deltas,
                        evidence.pre_ready_wss_consumer_chunk_read_deltas,
                        evidence.post_ready_consumer_chunk_read_deltas,
                    );
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 pending-owner acceptance exceeded 240 seconds".into(),
                )),
            }
        }
        [command] if command == "verify-m7-process-pause" => {
            match tokio::time::timeout(
                Duration::from_secs(180),
                tunnel_test_harness::production_cluster::verify_process_pause(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    require_m7_process_pause_evidence(&evidence)?;
                    println!(
                        "M7 process pause passed: relays={} peak_sockets={} elapsed_ms={} interrupted=true joined=true fresh_owner=true recovery=true",
                        evidence.relay_count,
                        evidence.fanout_peak_open,
                        evidence.pause_elapsed_ms,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Process(
                    "M7 process-pause acceptance exceeded 180 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-chaos" => {
            // The chaos scenario owns its own bounded deadline and cleanup
            // joins, like the recovery-attempts gate, so there is no outer
            // tokio timeout that could drop its owned processes and sockets.
            tunnel_test_harness::production_cluster::verify_chaos()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_chaos_evidence(&evidence)?;
                    println!("M7 chaos passed: {}", evidence.summary());
                    Ok(())
                })
        }
        [command] if command == "verify-m7-redis-partition" => {
            match tokio::time::timeout(
                Duration::from_secs(180),
                tunnel_test_harness::production_cluster::verify_redis_partition(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    require_m7_redis_partition_evidence(&evidence)?;
                    println!(
                        "M7 Redis partition passed: relays={} paused_connections={} partition_ms={} admission_rejected={} dispatch_interrupted={} livez_during_partition={} readyz_unready_during_partition={} readyz_ok_after_recovery={} recovery=true",
                        evidence.relay_count,
                        evidence.paused_redis_connections,
                        evidence.partition_elapsed_ms,
                        evidence.partition_admission_rejected,
                        evidence.partition_dispatch_interrupted,
                        evidence.public_livez_ok_during_partition,
                        evidence.public_readyz_unready_during_partition,
                        evidence.public_readyz_ok_after_recovery,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Process(
                    "M7 Redis partition acceptance exceeded 180 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-key-rotation" => {
            match tokio::time::timeout(
                Duration::from_secs(180),
                tunnel_test_harness::production_cluster::verify_key_revocation_during_rotation(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_key_rotation_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 key rotation passed: relays={} phase={} candidate_generation={} pin_revocation={} stream_interrupted={} same_owner_recovery={} fresh_session_recovery={} duplicate_response_rejected={} owner_epoch_advanced={} peak_sockets={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.rotation_phase,
                        evidence.candidate_generation,
                        evidence.pin_revocation_observed,
                        evidence.stream_interrupted,
                        evidence.same_owner_recovery,
                        evidence.fresh_session_recovery,
                        evidence.duplicate_response_rejected,
                        evidence.owner_epoch_advanced,
                        evidence.fanout_peak_open,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 key-rotation acceptance exceeded 180 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-resign-stream" => {
            tunnel_test_harness::production_cluster::verify_resign_stream()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_resign_stream_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 re-sign stream survival passed: relays={} resigns={} burst_versions={} last_record_version={} exchanges_after_resign={} same_stream_survived={} membership_changed_invalidations={} other_invalidations={} pin_samples={} pins_ever_empty={} readiness_recovered_ms={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.resigns,
                        evidence.burst_versions,
                        evidence.last_record_version,
                        evidence.exchanges_after_resign,
                        evidence.same_stream_survived,
                        evidence.membership_changed_invalidations,
                        evidence.other_invalidations,
                        evidence.pin_samples,
                        evidence.pins_ever_empty,
                        evidence.readiness_recovered_ms,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-trust-expiry" => {
            tunnel_test_harness::production_cluster::verify_trust_expiry()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_trust_expiry_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 signed peer trust expiry passed: relays={} record_version={} record_retained={} no_record_change={} membership_unready={} ingress_membership_ready={} route_withdrew={} unrelated_route_survived={} pooled_stream_interrupted={} dispatch_unchanged={} new_admission_rejected={} sibling_stream_survived={} sibling_dispatch_advanced={} reapproved_version={} trust_recovered={} recovery_echo={} peak_sockets={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.signed_record_version_before_expiry,
                        evidence.signed_record_retained_after_key_expiry,
                        evidence.no_record_change_before_expiry,
                        evidence.affected_membership_became_unready,
                        evidence.affected_ingress_membership_remained_ready,
                        evidence.affected_route_readiness_withdrew,
                        evidence.unrelated_route_readiness_survived,
                        evidence.affected_stream_interrupted,
                        evidence.affected_dispatch_unchanged,
                        evidence.affected_new_admission_rejected,
                        evidence.sibling_peer_stream_survived,
                        evidence.sibling_dispatch_advanced,
                        evidence.fresh_approved_record_version,
                        evidence.fresh_approved_trust_recovered,
                        evidence.recovery_echo,
                        evidence.fanout_peak_open,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-membership-hint-drop" => {
            tunnel_test_harness::production_cluster::verify_membership_hint_drop()
                .await
                .and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_membership_hint_drop_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 membership hint drop passed: relays={} overlap_version={} withdrawal_version={} target_hints_dropped={} other_hints_dropped={} publications_in_window={} overlap_converged={} overlap_stream_survived={} key_left_verifier={} overlap_stream_interrupted={} dispatch_unchanged={} withdrawn_admission_refused={} withdrawn_outcome={:?} sibling_stream_survived={} sibling_dispatch_advanced={} refresh_bound_ms={} reconcile_tick_ms={} observed_convergence_ms={} observed_refusal_ms={} recovery_version={} recovery_echo={} peak_sockets={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.overlap_record_version,
                        evidence.withdrawal_record_version,
                        evidence.target_hints_dropped,
                        evidence.other_hints_dropped,
                        evidence.publications_during_drop_window,
                        evidence.overlap_both_keys_converged,
                        evidence.overlap_stream_survived,
                        evidence.withdrawn_key_left_verifier,
                        evidence.overlap_stream_interrupted_after_withdrawal,
                        evidence.target_dispatch_unchanged,
                        evidence.withdrawn_key_admission_refused,
                        evidence.withdrawn_admission_outcome,
                        evidence.sibling_stream_survived,
                        evidence.sibling_dispatch_advanced,
                        evidence.membership_refresh_bound_ms,
                        evidence.reconcile_tick_ms,
                        evidence.observed_convergence_ms,
                        evidence.observed_refusal_ms,
                        evidence.recovery_record_version,
                        evidence.recovery_echo,
                        evidence.fanout_peak_open,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                })
        }
        [command] if command == "verify-m7-owner-contention" => {
            match tokio::time::timeout(
                Duration::from_secs(180),
                tunnel_test_harness::production_cluster::verify_owner_contention(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_ownership_evidence(&evidence)?;
                    println!(
                        "M7 owner contention passed: relays={} concurrent={} single_winner={} actual_conflict={} terminal_loser={} no_reconnect_loop={} original_owner={} sibling={} higher_epoch={} original_epoch={} successor_epoch={} catalog_generation_preserved={} stale_cleanup_rejected={} successor_echo={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.concurrent_launches,
                        evidence.one_atomic_winner,
                        evidence.actual_control_conflict_recorded,
                        evidence.duplicate_terminal_conflict,
                        evidence.duplicate_reconnect_loop_absent,
                        evidence.original_owner_preserved,
                        evidence.sibling_preserved,
                        evidence.successor_higher_epoch,
                        evidence.original_epoch,
                        evidence.successor_epoch,
                        evidence.catalog_generation_preserved,
                        evidence.stale_cleanup_rejected,
                        evidence.successor_echo,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 owner-contention acceptance exceeded 180 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-owner-lease-expiry" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_owner_lease_expiry(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    require_m7_owner_lease_expiry_evidence(&evidence)?;
                    println!(
                        "M7 owner lease expiry passed: relays={} seeded_epoch={} original_epoch={} generation_preserved={} baseline_echo={} paused_connections={} present_after_barrier={} expired_while_partitioned={} absent_after_lease_deadline={} lease_expiry_ms={} lease_deadline_margin_ms={} dispatch_unchanged={} stale_release_refused_after_expiry={} successor_scope={} successor_epoch={} successor_fresh_session={} stale_release_refused_after_successor={} successor_token_unchanged={} successor_echo={} peak_sockets={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.seeded_epoch,
                        evidence.original_epoch,
                        evidence.catalog_generation_preserved,
                        evidence.baseline_echo,
                        evidence.paused_redis_connections,
                        evidence.owner_present_after_barrier,
                        evidence.owner_expired_while_partitioned,
                        evidence.owner_absent_after_lease_deadline,
                        evidence.lease_expiry_elapsed_ms,
                        evidence.lease_deadline_margin_ms,
                        evidence.expired_owner_dispatch_unchanged,
                        evidence.stale_release_refused_after_expiry,
                        evidence.successor_scope_matched,
                        evidence.successor_epoch,
                        evidence.successor_fresh_session,
                        evidence.stale_release_refused_after_successor,
                        evidence.successor_token_unchanged,
                        evidence.successor_echo,
                        evidence.fanout_peak_open,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 owner-lease expiry acceptance exceeded 240 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-peer-readiness" => {
            match tokio::time::timeout(
                Duration::from_secs(180),
                tunnel_test_harness::production_cluster::verify_peer_readiness_loss(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_peer_readiness_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 peer readiness passed: relays={} membership_ready={} baseline_echo={} livez_during_loss={} unready_during_loss={} selected_dispatch_not_advanced={} route_recovered={} readyz_after_recovery={} recovery_echo={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.membership_ready_relays,
                        evidence.baseline_echo,
                        evidence.public_livez_ok_during_loss,
                        evidence.public_readyz_unready_during_loss,
                        evidence.selected_dispatch_not_advanced,
                        evidence.route_recovered,
                        evidence.public_readyz_ok_after_recovery,
                        evidence.recovery_echo,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 peer-readiness acceptance exceeded 180 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-lifecycle" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_lifecycle(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_lifecycle_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 stream lifecycle passed: relays={} non_owner_ingresses={} baseline_streams={} response_path_blocked={} proxy_connection_closed={} queue_observed={} cancellation_joined={} stream_cleaned={} dispatch_stable={} sibling_during={} sibling_after={} fresh_stream={} peak_sockets={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.non_owner_ingress_relays,
                        evidence.baseline_streams,
                        evidence.physical_response_path_blocked,
                        evidence.proxy_connection_closed,
                        evidence.queue_bytes_observed,
                        evidence.cancellation_joined,
                        evidence.stalled_stream_cleaned,
                        evidence.dispatch_stable_after_cleanup,
                        evidence.sibling_canary_during_stall,
                        evidence.sibling_canary_after_cancel,
                        evidence.fresh_authorized_stream,
                        evidence.fanout_peak_open,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 stream lifecycle acceptance exceeded 240 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-pressure" => {
            match tokio::time::timeout(
                Duration::from_secs(180),
                tunnel_test_harness::production_cluster::verify_pressure(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    require_m7_pressure_evidence(&evidence)?;
                    println!(
                        "M7 pressure passed: relays={} baseline_echo={} bulk_attempted={} bulk_records_attempted={} bounded_backpressure={} queue_budget_observed={} sibling_canary={} cancellation_responsive={} cancellation_not_replayed={} recovery_owner_verified={} recovery_echo={} peak_sockets={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.baseline_echo,
                        evidence.bulk_attempted,
                        evidence.bulk_records_attempted,
                        evidence.bounded_backpressure,
                        evidence.queue_budget_observed,
                        evidence.sibling_canary,
                        evidence.cancellation_responsive,
                        evidence.cancellation_not_replayed,
                        evidence.recovery_owner_verified,
                        evidence.recovery_echo,
                        evidence.fanout_peak_open,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Process(
                    "M7 pressure acceptance exceeded 180 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-remote-body-limits" => {
            match tokio::time::timeout(
                Duration::from_secs(200),
                tunnel_test_harness::production_cluster::verify_remote_body_limits(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_remote_body_limit_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M7 remote body limits passed: relays={} non_owner_ingress={} body_limit_bytes={} maximum_body_exact={} maximum_body_repeated_exact={} maximum_body_owner_dispatches={} maximum_body_other_dispatches={} zero_body_exact={} zero_body_owner_dispatches={} zero_body_other_dispatches={} over_limit_closed={} over_limit_close_ms={} over_limit_owner_reads={} over_limit_dispatches={} split_over_limit_closed={} split_over_limit_close_ms={} split_over_limit_owner_reads={} split_over_limit_dispatches={} truncated_held_open={} truncated_owner_read={} truncated_dispatches={} coalesced_exact={} coalesced_owner_dispatches={} coalesced_other_dispatches={} coalesced_over_budget_closed={} coalesced_over_budget_close_ms={} coalesced_over_budget_owner_reads={} coalesced_over_budget_dispatches={} sibling_refreshed_before_rejections={} sibling_stream_survived={} idle_remote_closed={} idle_remote_close_ms={} peer_idle_timeout_ms={} cleanup_joined={}",
                        evidence.relay_count,
                        evidence.non_owner_ingress,
                        evidence.body_limit_bytes,
                        evidence.maximum_body_exact,
                        evidence.maximum_body_repeated_exact,
                        evidence.maximum_body_owner_dispatches,
                        evidence.maximum_body_other_dispatches,
                        evidence.zero_body_exact,
                        evidence.zero_body_owner_dispatches,
                        evidence.zero_body_other_dispatches,
                        evidence.over_limit_closed,
                        evidence.over_limit_close_ms,
                        evidence.over_limit_owner_reads,
                        evidence.over_limit_dispatches,
                        evidence.split_over_limit_closed,
                        evidence.split_over_limit_close_ms,
                        evidence.split_over_limit_owner_reads,
                        evidence.split_over_limit_dispatches,
                        evidence.truncated_held_open,
                        evidence.truncated_owner_read,
                        evidence.truncated_dispatches,
                        evidence.coalesced_exact,
                        evidence.coalesced_owner_dispatches,
                        evidence.coalesced_other_dispatches,
                        evidence.coalesced_over_budget_closed,
                        evidence.coalesced_over_budget_close_ms,
                        evidence.coalesced_over_budget_owner_reads,
                        evidence.coalesced_over_budget_dispatches,
                        evidence.sibling_refreshed_before_rejections,
                        evidence.sibling_stream_survived,
                        evidence.idle_remote_closed,
                        evidence.idle_remote_close_ms,
                        evidence.peer_idle_timeout_ms,
                        evidence.cleanup_joined,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m7-remote-body-limits exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m3-http-forward-real-path" => {
            match tokio::time::timeout(
                Duration::from_secs(300),
                tunnel_test_harness::production_cluster::verify_http_forward_real_path(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_http_forward_real_path_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M3 http-forward real path passed: relays={} owner={} ingress={} non_owner_ingress={} upload_bytes={} echoed_bytes={} handler_sha256_match={} echo_sha256_match={} saturated_when_probed={} permission_status={} permission_latency_ms={} owner_local_permission_exact={} cancel_owner_release={} cancel_reset_reason={:?} cancel_ingress_error={:?} cancel_device_response_aborted={} handler_cancellation_latency_ms={} ingress_request_handoff_hw={} ingress_response_handoff_hw={} ingress_response_body_hw={} ingress_peer_in_flight_hw={} ingress_peer_receive_hw={} owner_request_handoff_hw={} owner_response_handoff_hw={} owner_peer_in_flight_hw={} owner_peer_receive_hw={} owner_receive_buffer_hw={}/{} owner_parked_hw={} owner_replay_hw={} owner_data_bytes_hw={}/{} device_receive_buffer_hw={}/{} device_parked_hw={} device_request_handoff_hw={} device_response_handoff_hw={} device_request_body_hw={} handler_headers={:?} handler_forbidden_header={} handler_value_leak={} response_header_leak={} internal_header_probe={} unauthenticated={} rejected_probes_dispatched={} sequential_requests={} sequential_ok={} sequential_dispatches={} sequential_not_dispatched_retries={} sequential_highest_stream_id={} sequential_session_stable={} sequential_phase_after={} sequential_ready_after={} open_journal_entries_peak={} open_journal_entries_before={} open_journal_entries_after={} open_journal_ids_before={:?} open_journal_ids_after={:?} open_journal_settle_ms={} earlier_phase_streams={:?} open_streams_retired={}(+{} before) open_retired_ranges_coalesced={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.ingress_node,
                        evidence.non_owner_ingress,
                        evidence.upload_bytes,
                        evidence.echoed_bytes,
                        evidence.handler_digest_matches_upload,
                        evidence.echo_digest_matches_upload,
                        evidence.saturated_when_probed,
                        evidence.permission_status,
                        evidence.permission_latency_ms,
                        evidence.owner_local_permission_exact,
                        evidence.cancel_owner_release,
                        evidence.cancel_owner_reset_reason,
                        evidence.cancel_ingress_error,
                        evidence.cancel_device_response_aborted,
                        evidence.handler_cancellation_latency_ms,
                        evidence.max_ingress_request_handoff,
                        evidence.max_ingress_response_handoff,
                        evidence.max_ingress_response_body,
                        evidence.max_ingress_peer_send_in_flight,
                        evidence.max_ingress_peer_receive_queue,
                        evidence.max_owner_request_handoff,
                        evidence.max_owner_response_handoff,
                        evidence.max_owner_peer_send_in_flight,
                        evidence.max_owner_peer_receive_queue,
                        evidence.max_owner_receive_buffer,
                        evidence.owner_receive_window,
                        evidence.max_owner_parked,
                        evidence.max_owner_replay,
                        evidence.owner_data_bytes_high_water,
                        evidence.owner_data_bytes_limit,
                        evidence.max_device_receive_buffer,
                        evidence.device_receive_window,
                        evidence.max_device_parked,
                        evidence.max_device_request_handoff,
                        evidence.max_device_response_handoff,
                        evidence.max_device_request_body,
                        evidence.handler_header_names,
                        evidence.handler_saw_forbidden_header,
                        evidence.handler_header_value_leak,
                        evidence.consumer_response_header_leak,
                        evidence.internal_header_probe_status,
                        evidence.unauthenticated_status,
                        evidence.rejected_probes_dispatched,
                        evidence.sequential_requests,
                        evidence.sequential_ok,
                        evidence.sequential_dispatches,
                        evidence.sequential_not_dispatched_retries,
                        evidence.sequential_highest_stream_id,
                        evidence.sequential_session_id_stable,
                        evidence.sequential_phase_after,
                        evidence.sequential_ready_after,
                        evidence.open_journal_entries_peak,
                        evidence.open_journal_entries_before_sequential,
                        evidence.open_journal_entries_after_sequential,
                        evidence.open_journal_stream_ids_before,
                        evidence.open_journal_stream_ids_after,
                        evidence.open_journal_settle_ms,
                        evidence.earlier_phase_streams,
                        evidence.open_streams_retired,
                        evidence.open_streams_retired_before_sequential,
                        evidence.open_retired_ranges_coalesced,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m3-http-forward-real-path exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m8-acp-real-path" => {
            match tokio::time::timeout(
                Duration::from_secs(600),
                tunnel_test_harness::production_cluster::verify_acp_real_path(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_acp_real_path_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M8 ACP real path passed: relays={} owner={} ingress={} non_owner={} cases={:?} connection_opened={} session_from_stream={} prompt_202={} stop_reason={} permission_on_wire={} offered={:?} allow_at_agent={} reject_at_agent={} allow_stop={} reject_stop={} unoffered_rule={} unknown_id_rule={} wrong_connection_status={} resign_spacing_ms={} max_membership_age_ms={} resigns={} refusals={} retries={} unexplained={:?} rotations={} device_sessions={} leftover_processes={} not_covered={} terminals(s/c/u)={}/{}/{} unknown_error_ms={} stream_ended_cleanly={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.ingress_node,
                        evidence.non_owner_ingress,
                        evidence.cases_executed,
                        evidence.connection_opened,
                        evidence.session_id_from_connection_stream,
                        evidence.prompt_accepted_202,
                        evidence.conversation_stop_reason,
                        evidence.permission_requested_on_wire,
                        evidence.offered_options,
                        evidence.allow_outcome_at_agent,
                        evidence.reject_outcome_at_agent,
                        evidence.allow_stop_reason,
                        evidence.reject_stop_reason,
                        evidence.unoffered_option_rule,
                        evidence.unknown_request_id_rule,
                        evidence.wrong_connection_status,
                        evidence.resign_spacing_ms,
                        evidence.max_membership_age_at_case_end_ms,
                        evidence.membership_resigns,
                        evidence.not_dispatched_refusals,
                        evidence.not_dispatched_retries,
                        evidence.unexplained_refusal,
                        evidence.rotations_observed,
                        evidence.device_sessions,
                        evidence.leftover_processes,
                        evidence.not_covered.len(),
                        evidence.export_terminal_succeeded_delta,
                        evidence.export_terminal_cancelled_delta,
                        evidence.export_terminal_unknown_delta,
                        evidence.unknown_error_latency_ms,
                        evidence.unknown_stream_ended_cleanly,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m8-acp-real-path exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m8-acp-cluster" => {
            match tokio::time::timeout(
                Duration::from_secs(900),
                tunnel_test_harness::production_cluster::verify_acp_cluster(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_acp_cluster_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M8 ACP cluster passed: relays={} owner={} ingress={} non_owner={} cases={:?} rotations_across_span={} owner_rotations={} span_ms={} met_schedule={} distinct_sockets={} new_per_round={:?} steady={:?} socket_peak={} connection_alive={} device_session_stable={} epoch_stable={} effects={} effects_after_settle={} sessions={:?} resign_spacing_ms={} max_membership_age_ms={} resigns={} boundary_route_probes={} refusals={} retries={} unexplained={:?} leftover_processes={} open_journal_entries={} open_streams_retired={} not_covered={} revocation_after=({}/{}/{}) revocation_after_prompt_status={} key_overlap_staged={} version_bump=(interrupted={} reasons={:?}) key_rotation=(interrupted={} no_stop_reason={} left_verifier={} reasons={:?}) key_rotation_route_probes={} owner_device_at_one_instant=(to_device={} from_device={} samples={})",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.ingress_node,
                        evidence.non_owner_ingress,
                        evidence.cases_executed,
                        evidence.rotations_across_span,
                        evidence.owner_rotations_across_span,
                        evidence.rotation_span_ms,
                        evidence.rotation_span_met_schedule,
                        evidence.distinct_device_sockets,
                        evidence.new_sockets_per_round,
                        evidence.steady_state_sockets,
                        evidence.device_socket_peak,
                        evidence.connection_stream_alive,
                        evidence.device_session_stable,
                        evidence.device_epoch_stable,
                        evidence.side_effects_in_ledger,
                        evidence.side_effects_after_settle,
                        evidence.sessions,
                        evidence.resign_spacing_ms,
                        evidence.max_membership_age_at_case_end_ms,
                        evidence.membership_resigns,
                        evidence.boundary_route_probes,
                        evidence.not_dispatched_refusals,
                        evidence.not_dispatched_retries,
                        evidence.unexplained_refusal,
                        evidence.leftover_processes,
                        evidence.open_journal_entries,
                        evidence.open_streams_retired,
                        evidence.not_covered.len(),
                        // Printed so both revocation refusals are established
                        // figures rather than fields only a validator sees.
                        // The prompt rule was `>= 400` because nobody had
                        // measured it; printing it here established 404, and
                        // it is pinned there now.
                        evidence.revocation_after_status,
                        evidence.revocation_after_code,
                        evidence.revocation_after_execution,
                        evidence.revocation_after_prompt_status,
                        // Printed for the same reason: the key-rotation
                        // attribution is the whole point of that case, and a
                        // reason set only a validator sees is a figure nobody
                        // can quote.  The control arm is printed beside it
                        // because the key arm's reason means nothing alone.
                        evidence.key_overlap_staged,
                        evidence.version_bump_interrupted,
                        evidence.version_bump_reasons,
                        evidence.key_rotation_interrupted,
                        evidence.key_rotation_no_stop_reason,
                        evidence.key_left_ingress_verifier,
                        evidence.key_rotation_reasons,
                        evidence.key_rotation_route_probes,
                        evidence.owner_device_request_bytes_at_instant,
                        evidence.owner_device_response_bytes_at_instant,
                        evidence.owner_device_coherent_samples,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m8-acp-cluster exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-real-path" => {
            match tokio::time::timeout(
                Duration::from_secs(300),
                tunnel_test_harness::production_cluster::verify_fs_real_path(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_real_path_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem real path passed: relays={} owner={} non_owner={} descriptor_status={} content_type={} cache_control={} schema={} subprotocol={} dialect={} root_read_only={} operations={:?} device_matches={} service_matches={} grant_revision_present={} host_path_leak={} identity_field_leak={} empty_grant={}/{} unsupported_host={}/{} unauthenticated={}/{} unknown_device={}/{} method_not_allowed={} stale_revision={}/{} missing_subprotocol={} non_owner_upgrade={}/{} selected_subprotocol={} negotiated_msize={} negotiated_dialect={} attach_qid_is_directory={} forged_uname_close={:?} forged_uname_admitted={} forged_afid_close={:?} forged_afid_admitted={} read_file_bytes={} read_observed_bytes={} read_checksum_matches={} read_messages={} readdir_expected={} readdir_observed={} readdir_pages={} readdir_every_name_once={} list_only_stat_size_matches={} list_only_open_errno={:?} read_only_read_matches={} read_only_getattr_errno={:?} read_only_directory_open_errno={:?} flush_rflush_observed={} flush_victim_reply_observed={} flush_replies_after_rflush={} flush_session_survived={} fid_reuse_first_read_matches={} fid_reuse_stale_read_errno={:?} fid_reuse_second_read_matches={} mutation_write_open_errno={:?} mutation_write_errno={:?} mutation_create_errno={:?} mutation_mkdir_errno={:?} mutation_host_unchanged={} revision_advanced_in_catalog={} revised_descriptor_status={} revised_revision_differs={} superseded_descriptor={}/{} superseded_upgrade={}/{} current_revision_upgrade_admitted={} revoked_session_served_before={} revoked_session_closed={} revoked_session_close_code={:?} revoked_session_replies_after={} grant_deadline_initial_ms={:?} grant_deadline_crossed={} grant_deadline_renewals={} grant_deadline_served_after={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.non_owner_node,
                        evidence.descriptor_status,
                        evidence.descriptor_content_type,
                        evidence.descriptor_cache_control,
                        evidence.descriptor_schema_version,
                        evidence.descriptor_subprotocol,
                        evidence.descriptor_dialect,
                        evidence.descriptor_root_read_only,
                        evidence.descriptor_operations,
                        evidence.descriptor_device_matches,
                        evidence.descriptor_service_matches,
                        evidence.descriptor_grant_revision_present,
                        evidence.descriptor_host_path_leak,
                        evidence.descriptor_identity_field_leak,
                        evidence.empty_grant_status,
                        evidence.empty_grant_code,
                        evidence.unsupported_host_status,
                        evidence.unsupported_host_code,
                        evidence.unauthenticated_status,
                        evidence.unauthenticated_code,
                        evidence.unknown_device_status,
                        evidence.unknown_device_code,
                        evidence.method_not_allowed_status,
                        evidence.stale_revision_status,
                        evidence.stale_revision_code,
                        evidence.missing_subprotocol_status,
                        evidence.non_owner_upgrade_status,
                        evidence.non_owner_upgrade_code,
                        evidence.selected_subprotocol,
                        evidence.negotiated_msize,
                        evidence.negotiated_dialect,
                        evidence.attach_qid_is_directory,
                        evidence.forged_uname_close_code,
                        evidence.forged_uname_admitted,
                        evidence.forged_afid_close_code,
                        evidence.forged_afid_admitted,
                        evidence.read_file_bytes,
                        evidence.read_observed_bytes,
                        evidence.read_checksum_matches,
                        evidence.read_messages,
                        evidence.readdir_entries_expected,
                        evidence.readdir_names_observed,
                        evidence.readdir_pages,
                        evidence.readdir_every_name_exactly_once,
                        evidence.list_only_getattr_size_matches,
                        evidence.list_only_open_errno,
                        evidence.read_only_read_matches,
                        evidence.read_only_getattr_errno,
                        evidence.read_only_directory_open_errno,
                        evidence.flush_rflush_observed,
                        evidence.flush_victim_reply_observed,
                        evidence.flush_replies_after_rflush,
                        evidence.flush_session_survived,
                        evidence.fid_reuse_first_read_matches,
                        evidence.fid_reuse_stale_read_errno,
                        evidence.fid_reuse_second_read_matches,
                        evidence.mutation_write_open_errno,
                        evidence.mutation_write_errno,
                        evidence.mutation_create_errno,
                        evidence.mutation_mkdir_errno,
                        evidence.mutation_host_unchanged,
                        evidence.revision_advanced_in_catalog,
                        evidence.revised_descriptor_status,
                        evidence.revised_revision_differs,
                        evidence.superseded_descriptor_status,
                        evidence.superseded_descriptor_code,
                        evidence.superseded_upgrade_status,
                        evidence.superseded_upgrade_code,
                        evidence.current_revision_upgrade_admitted,
                        evidence.revoked_session_served_before,
                        evidence.revoked_session_closed,
                        evidence.revoked_session_close_code,
                        evidence.revoked_session_replies_after,
                        evidence.grant_deadline_initial_ms,
                        evidence.grant_deadline_crossed,
                        evidence.grant_deadline_renewals,
                        evidence.grant_deadline_served_after,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-real-path exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-write-path" => {
            match tokio::time::timeout(
                Duration::from_secs(300),
                tunnel_test_harness::production_cluster::verify_fs_write_path(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_write_path_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem write path passed: relays={} owner={} root_read_only={} advertises_write={} write_file_bytes={} write_acknowledged_bytes={} write_messages={} write_readback_matches={} write_length_exact={} create={} mkdir={} unlink={} rename={} rmdir={} truncate_emptied={} setattr_size={} read_only_attempted={} read_only_errnos={:?} read_only_host_unchanged={} hard_link_count={} hard_link_write_errno={:?} hard_link_read_write_errno={:?} hard_link_truncate_errno={:?} hard_link_setattr_errno={:?} hard_link_content_intact={} hard_link_read_served={} interrupt_blocks_sent={} interrupt_acknowledged_bytes={} interrupt_host_bytes={} interrupt_prefix_matches={} interrupt_is_source_prefix={} interrupt_within_sent={} interrupt_replayed={} host_failure_errno={:?} host_failure_leaked_a_name={} host_failure_session_survived={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.descriptor_root_read_only,
                        evidence.descriptor_advertises_write,
                        evidence.write_file_bytes,
                        evidence.write_acknowledged_bytes,
                        evidence.write_messages,
                        evidence.write_readback_matches,
                        evidence.write_length_exact,
                        evidence.create_observed_on_host,
                        evidence.mkdir_observed_on_host,
                        evidence.unlink_observed_on_host,
                        evidence.rename_observed_on_host,
                        evidence.rmdir_observed_on_host,
                        evidence.truncate_emptied_the_file,
                        evidence.setattr_size_observed_on_host,
                        evidence.read_only_refusals_attempted,
                        evidence.read_only_refusal_errnos,
                        evidence.read_only_host_unchanged,
                        evidence.hard_link_count_observed,
                        evidence.hard_link_write_open_errno,
                        evidence.hard_link_read_write_open_errno,
                        evidence.hard_link_truncate_open_errno,
                        evidence.hard_link_setattr_size_errno,
                        evidence.hard_link_content_intact,
                        evidence.hard_link_read_still_served,
                        evidence.interrupt_blocks_sent,
                        evidence.interrupt_acknowledged_bytes,
                        evidence.interrupt_host_bytes,
                        evidence.interrupt_acknowledged_prefix_matches,
                        evidence.interrupt_is_source_prefix,
                        evidence.interrupt_within_sent_bytes,
                        evidence.interrupt_replayed,
                        evidence.host_failure_errno,
                        evidence.host_failure_leaked_a_name,
                        evidence.host_failure_session_survived,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-write-path exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-rotation" => {
            match tokio::time::timeout(
                Duration::from_secs(360),
                tunnel_test_harness::production_cluster::verify_fs_rotation(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_rotation_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem rotation passed: relays={} owner={} subprotocol={} msize={} dialect={} prefix_bytes={} freeze_phase={} freeze_attempt_active={} freeze_connector_fence={:?} freeze_relay_recv_contiguous={} freeze_relay_fence={:?} freeze_old_generation={} freeze_candidate_generation={:?} freeze_writer_barriers={:?} exchange_in_flight_at_freeze={} freeze_polls={} held_tag={} held_reply_tag_matched={} held_reply_was_rread={} held_reply_bytes={} transfer_bytes={}/{} transfer_checksum_matches={} transfer_messages={} rotations_completed={}->{} generation={}->{} epoch={}->{} total_replayed_frames={} deadline_forced_retirement={} rotation_recovery_reason={:?} session_id_stable={} epoch_stable={} fid_survived_getattr={} fid_survived_getattr_size={} attach_fid_survived_walk={} post_rotation_tag_correlated={} attach_count={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.selected_subprotocol,
                        evidence.negotiated_msize,
                        evidence.negotiated_dialect,
                        evidence.prefix_bytes,
                        evidence.freeze.phase,
                        evidence.freeze.attempt_active,
                        evidence.freeze.connector_fence,
                        evidence.freeze.relay_recv_contiguous,
                        evidence.freeze.relay_fence,
                        evidence.freeze.old_generation,
                        evidence.freeze.candidate_generation,
                        evidence.freeze.writer_barriers_flushed,
                        evidence.exchange_in_flight_at_freeze,
                        evidence.freeze_polls,
                        evidence.held_tag,
                        evidence.held_reply_tag_matched,
                        evidence.held_reply_was_rread,
                        evidence.held_reply_bytes,
                        evidence.transfer_bytes,
                        evidence.transfer_expected_bytes,
                        evidence.transfer_checksum_matches,
                        evidence.transfer_messages,
                        evidence.rotations_completed_before,
                        evidence.rotations_completed_after,
                        evidence.generation_before,
                        evidence.generation_after,
                        evidence.epoch_before,
                        evidence.epoch_after,
                        evidence.total_replayed_frames,
                        evidence.deadline_forced_retirement,
                        evidence.rotation_recovery_reason,
                        evidence.session_id_stable,
                        evidence.epoch_stable,
                        evidence.fid_survived_getattr,
                        evidence.fid_survived_getattr_size,
                        evidence.attach_fid_survived_walk,
                        evidence.post_rotation_tag_correlated,
                        evidence.attach_count,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-rotation exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-rotation-write" => {
            match tokio::time::timeout(
                Duration::from_secs(480),
                tunnel_test_harness::production_cluster::verify_fs_rotation_write(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_rotation_write_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem rotation write passed: relays={} owner={} subprotocol={} msize={} dialect={} held_region_before_send={} prefix_region_after_write={} prefix_acknowledged_bytes={} held_region_before_freeze={} write_freeze_phase={} write_freeze_attempt_active={} write_freeze_connector_fence={:?} write_freeze_relay_recv_contiguous={} write_freeze_relay_fence={:?} write_freeze_old_generation={} write_freeze_candidate_generation={:?} write_freeze_writer_barriers={:?} write_exchange_in_flight_at_freeze={} write_freeze_polls={} held_write_tag={} held_write_reply_tag_matched={} held_write_reply_was_rwrite={} held_write_acknowledged_bytes={} held_write_answered={} held_write_ambiguous={} held_region_after_rotation={} image_bytes={}/{} image_checksum_matches={} flush_freeze_phase={} flush_freeze_attempt_active={} flush_freeze_connector_fence={:?} flush_freeze_relay_recv_contiguous={} flush_freeze_relay_fence={:?} flush_freeze_old_generation={} flush_freeze_candidate_generation={:?} flush_freeze_writer_barriers={:?} flush_exchange_in_flight_at_freeze={} flush_freeze_polls={} flush_tag={} flushed_victim_tag={} rflush_observed={} flushed_victim_reply_observed={} flushed_replies_after_rflush={} flush_pipeline_replies={} rotations_completed={}->{}->{} generation={}->{} epoch={}->{} total_replayed_frames={} deadline_forced_retirement={} rotation_recovery_reason={:?} session_id_stable={} epoch_stable={} fid_survived_read={} fid_read_back_matches_payload={} post_rotation_tag_correlated={} attach_count={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.selected_subprotocol,
                        evidence.negotiated_msize,
                        evidence.negotiated_dialect,
                        evidence.held_region_before_send.as_str(),
                        evidence.prefix_region_after_write.as_str(),
                        evidence.prefix_acknowledged_bytes,
                        evidence.held_region_before_freeze.as_str(),
                        evidence.write_freeze.phase,
                        evidence.write_freeze.attempt_active,
                        evidence.write_freeze.connector_fence,
                        evidence.write_freeze.relay_recv_contiguous,
                        evidence.write_freeze.relay_fence,
                        evidence.write_freeze.old_generation,
                        evidence.write_freeze.candidate_generation,
                        evidence.write_freeze.writer_barriers_flushed,
                        evidence.write_exchange_in_flight_at_freeze,
                        evidence.write_freeze_polls,
                        evidence.held_write_tag,
                        evidence.held_write_reply_tag_matched,
                        evidence.held_write_reply_was_rwrite,
                        evidence.held_write_acknowledged_bytes,
                        evidence.held_write_answered,
                        evidence.held_write_ambiguous,
                        evidence.held_region_after_rotation.as_str(),
                        evidence.image_bytes,
                        evidence.image_expected_bytes,
                        evidence.image_checksum_matches,
                        evidence.flush_freeze.phase,
                        evidence.flush_freeze.attempt_active,
                        evidence.flush_freeze.connector_fence,
                        evidence.flush_freeze.relay_recv_contiguous,
                        evidence.flush_freeze.relay_fence,
                        evidence.flush_freeze.old_generation,
                        evidence.flush_freeze.candidate_generation,
                        evidence.flush_freeze.writer_barriers_flushed,
                        evidence.flush_exchange_in_flight_at_freeze,
                        evidence.flush_freeze_polls,
                        evidence.flush_tag,
                        evidence.flushed_victim_tag,
                        evidence.rflush_observed,
                        evidence.flushed_victim_reply_observed,
                        evidence.flushed_replies_after_rflush,
                        evidence.flush_pipeline_replies,
                        evidence.rotations_completed_before,
                        evidence.rotations_completed_after_write,
                        evidence.rotations_completed_after_flush,
                        evidence.generation_before,
                        evidence.generation_after,
                        evidence.epoch_before,
                        evidence.epoch_after,
                        evidence.total_replayed_frames,
                        evidence.deadline_forced_retirement,
                        evidence.rotation_recovery_reason,
                        evidence.session_id_stable,
                        evidence.epoch_stable,
                        evidence.fid_survived_read,
                        evidence.fid_read_back_matches_payload,
                        evidence.post_rotation_tag_correlated,
                        evidence.attach_count,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-rotation-write exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-consumer-loss" => {
            match tokio::time::timeout(
                Duration::from_secs(360),
                tunnel_test_harness::production_cluster::verify_fs_consumer_loss(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_consumer_loss_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem consumer loss passed: relays={} owner={} subprotocol={} msize={} dialect={} prefix_bytes={} stream_id={} emitted={}->{} recv_contiguous={}->{} request_outstanding_at_loss={} loss_polls={} abandoned_tag={} lost_stream_deregistered={} device_session_survived={} session_id_stable={} epoch={}->{} pre_attach_probe_close_code={:?} pre_attach_probe_answered={} second_session_msize={} stale_file_fid_refused={} stale_file_fid_errno={:?} stale_attach_fid_refused={} stale_attach_fid_errno={:?} second_session_attached={} second_session_bytes={}/{} second_session_checksum_matches={} second_session_messages={} second_session_getattr_size={} attach_count={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.selected_subprotocol,
                        evidence.negotiated_msize,
                        evidence.negotiated_dialect,
                        evidence.prefix_bytes,
                        evidence.loss.stream_id,
                        evidence.loss.emitted_before,
                        evidence.loss.emitted_at_loss,
                        evidence.loss.recv_contiguous_before,
                        evidence.loss.recv_contiguous_at_loss,
                        evidence.request_outstanding_at_loss,
                        evidence.loss_polls,
                        evidence.abandoned_tag,
                        evidence.lost_stream_deregistered,
                        evidence.device_session_survived,
                        evidence.session_id_stable,
                        evidence.epoch_before,
                        evidence.epoch_after,
                        evidence.pre_attach_probe_close_code,
                        evidence.pre_attach_probe_answered,
                        evidence.second_session_msize,
                        evidence.stale_file_fid_refused,
                        evidence.stale_file_fid_errno,
                        evidence.stale_attach_fid_refused,
                        evidence.stale_attach_fid_errno,
                        evidence.second_session_attached,
                        evidence.second_session_bytes,
                        evidence.second_session_expected_bytes,
                        evidence.second_session_checksum_matches,
                        evidence.second_session_messages,
                        evidence.second_session_getattr_size,
                        evidence.attach_count,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-consumer-loss exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-data-recovery" => {
            match tokio::time::timeout(
                Duration::from_secs(360),
                tunnel_test_harness::production_cluster::verify_fs_data_recovery(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_data_recovery_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem data-socket recovery passed: relays={} owner={} subprotocol={} msize={} dialect={} prefix_bytes={} stream_id={} emitted={}->{} recv_contiguous={}->{} request_outstanding_at_failure={} failure_polls={} held_tag={} connection_id={}->{} generation={}->{} rotations_completed={}->{} failed_connection_closed_at_proxy={} replacement_connection_observed_at_proxy={} catalog_owner_session_stable={} catalog_epoch={}->{} owner_session_id_stable={} owner_epoch={}->{} control_carrier_unchanged={} recovery_attempted={} owner_recovery_reason={:?} recovery_released_failed_carrier={} recovery_successor_is_active_carrier={} replayed_frames={}->{} operation_id_stable={} stream_remained_registered={} sole_consumer_stream_at_owner={} stream_not_terminal={} same_owner_qualifiers_held={} held_reply_tag_matched={} held_reply_was_rread={} held_reply_bytes={} transfer_bytes={}/{} transfer_messages={} transfer_checksum_matches={} fid_survived_getattr={} fid_survived_getattr_size={} attach_fid_survived_walk={} post_recovery_tag_correlated={} attach_count={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.selected_subprotocol,
                        evidence.negotiated_msize,
                        evidence.negotiated_dialect,
                        evidence.prefix_bytes,
                        evidence.failure.stream_id,
                        evidence.failure.emitted_before,
                        evidence.failure.emitted_at_failure,
                        evidence.failure.recv_contiguous_before,
                        evidence.failure.recv_contiguous_at_failure,
                        evidence.request_outstanding_at_failure,
                        evidence.failure_polls,
                        evidence.held_tag,
                        evidence.connection_id_before,
                        evidence.connection_id_after,
                        evidence.generation_before,
                        evidence.generation_after,
                        evidence.rotations_completed_before,
                        evidence.rotations_completed_after,
                        evidence.failed_connection_closed_at_proxy,
                        evidence.replacement_connection_observed_at_proxy,
                        evidence.catalog_owner_session_stable,
                        evidence.catalog_epoch_before,
                        evidence.catalog_epoch_after,
                        evidence.owner_session_id_stable,
                        evidence.owner_epoch_before,
                        evidence.owner_epoch_after,
                        evidence.control_carrier_unchanged,
                        evidence.recovery_attempted,
                        evidence.owner_recovery_reason,
                        evidence.recovery_released_failed_carrier,
                        evidence.recovery_successor_is_active_carrier,
                        evidence.replayed_frames_before,
                        evidence.replayed_frames_after,
                        evidence.operation_id_stable,
                        evidence.stream_remained_registered,
                        evidence.sole_consumer_stream_at_owner,
                        evidence.stream_not_terminal,
                        evidence.same_owner_contract_qualifiers_held(),
                        evidence.held_reply_tag_matched,
                        evidence.held_reply_was_rread,
                        evidence.held_reply_bytes,
                        evidence.transfer_bytes,
                        evidence.transfer_expected_bytes,
                        evidence.transfer_messages,
                        evidence.transfer_checksum_matches,
                        evidence.fid_survived_getattr,
                        evidence.fid_survived_getattr_size,
                        evidence.attach_fid_survived_walk,
                        evidence.post_recovery_tag_correlated,
                        evidence.attach_count,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-data-recovery exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-epoch-change" => {
            match tokio::time::timeout(
                Duration::from_secs(360),
                tunnel_test_harness::production_cluster::verify_fs_epoch_change(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_epoch_change_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem control-epoch change passed: relays={} owner={} subprotocol={} msize={} dialect={} prefix_bytes={} stream_id={} emitted={}->{} recv_contiguous={}->{} request_outstanding_at_change={} change_polls={} held_tag={} epoch={}->{} device_epoch={}->{} session_id_changed={} owner_released_between={} second_connector_active={} pending_call_closed={} pending_call_close_code={:?} pending_call_answered={} held_session_teardown_reason={:?} held_stream_deregistered={} pre_attach_probe_close_code={:?} pre_attach_probe_answered={} second_session_msize={} stale_file_fid_refused={} stale_file_fid_errno={:?} stale_attach_fid_refused={} stale_attach_fid_errno={:?} second_session_attached={} second_session_bytes={}/{} second_session_checksum_matches={} second_session_messages={} second_session_getattr_size={} attach_count={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.selected_subprotocol,
                        evidence.negotiated_msize,
                        evidence.negotiated_dialect,
                        evidence.prefix_bytes,
                        evidence.change.stream_id,
                        evidence.change.emitted_before,
                        evidence.change.emitted_at_change,
                        evidence.change.recv_contiguous_before,
                        evidence.change.recv_contiguous_at_change,
                        evidence.request_outstanding_at_change,
                        evidence.change_polls,
                        evidence.held_tag,
                        evidence.epoch_before,
                        evidence.epoch_after,
                        evidence.device_epoch_before,
                        evidence.device_epoch_after,
                        evidence.session_id_before != evidence.session_id_after,
                        evidence.owner_released_between,
                        evidence.second_connector_active,
                        evidence.pending_call_closed,
                        evidence.pending_call_close_code,
                        evidence.pending_call_answered,
                        evidence.held_session_teardown_reason,
                        evidence.held_stream_deregistered,
                        evidence.pre_attach_probe_close_code,
                        evidence.pre_attach_probe_answered,
                        evidence.second_session_msize,
                        evidence.stale_file_fid_refused,
                        evidence.stale_file_fid_errno,
                        evidence.stale_attach_fid_refused,
                        evidence.stale_attach_fid_errno,
                        evidence.second_session_attached,
                        evidence.second_session_bytes,
                        evidence.second_session_expected_bytes,
                        evidence.second_session_checksum_matches,
                        evidence.second_session_messages,
                        evidence.second_session_getattr_size,
                        evidence.attach_count,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-epoch-change exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-process-restart" => {
            match tokio::time::timeout(
                Duration::from_secs(360),
                tunnel_test_harness::production_cluster::verify_fs_process_restart(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_process_restart_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem connector process restart passed: relays={} owner={} subprotocol={} msize={} dialect={} prefix_bytes={} journal_entries_before_held={} stream_id={} emitted={}->{} recv_contiguous={}->{} request_outstanding_at_kill={} restart_polls={} held_tag={} held_effect_present_before_kill={} journal_entries_before_kill={} journal_polls={} pid={}->{} first_process_exited={} first_process_killed_by_signal={} second_process_active={} epoch={}->{} session_id_changed={} owner_released_between={} pending_call_closed={} pending_call_close_code={:?} pending_call_answered={} pending_call_errored={} held_call_outcome={:?} held_call_settled={:?} held_stream_deregistered={} pre_attach_probe_close_code={:?} pre_attach_probe_answered={} second_session_msize={} stale_file_fid_refused={} stale_file_fid_errno={:?} stale_attach_fid_refused={} stale_attach_fid_errno={:?} stale_journal_fid_refused={} stale_journal_fid_errno={:?} retry_refused_above_dispatch={} retry_refusal_errno={:?} journal_entries_after_retry={} second_session_attached={} journal_entries_over_ninep={} journal_entries_final={} held_effect_exactly_once={} second_session_bytes={}/{} second_session_checksum_matches={} second_session_messages={} second_session_getattr_size={} attach_count={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.selected_subprotocol,
                        evidence.negotiated_msize,
                        evidence.negotiated_dialect,
                        evidence.prefix_bytes,
                        evidence.journal_entries_before_held,
                        evidence.restart.stream_id,
                        evidence.restart.emitted_before,
                        evidence.restart.emitted_at_kill,
                        evidence.restart.recv_contiguous_before,
                        evidence.restart.recv_contiguous_at_kill,
                        evidence.request_outstanding_at_kill,
                        evidence.restart_polls,
                        evidence.held_tag,
                        evidence.held_effect_present_before_kill,
                        evidence.journal_entries_before_kill,
                        evidence.journal_polls,
                        evidence.first_pid,
                        evidence.second_pid,
                        evidence.first_process_exited,
                        evidence.first_process_killed_by_signal,
                        evidence.second_process_active,
                        evidence.epoch_before,
                        evidence.epoch_after,
                        evidence.session_id_before != evidence.session_id_after,
                        evidence.owner_released_between,
                        evidence.pending_call_closed,
                        evidence.pending_call_close_code,
                        evidence.pending_call_answered,
                        evidence.pending_call_errored,
                        evidence.held_call_outcome,
                        evidence
                            .held_call_outcome
                            .map(tunnel_fs_core::Outcome::is_settled),
                        evidence.held_stream_deregistered,
                        evidence.pre_attach_probe_close_code,
                        evidence.pre_attach_probe_answered,
                        evidence.second_session_msize,
                        evidence.stale_file_fid_refused,
                        evidence.stale_file_fid_errno,
                        evidence.stale_attach_fid_refused,
                        evidence.stale_attach_fid_errno,
                        evidence.stale_journal_fid_refused,
                        evidence.stale_journal_fid_errno,
                        evidence.retry_refused_above_dispatch,
                        evidence.retry_refusal_errno,
                        evidence.journal_entries_after_retry,
                        evidence.second_session_attached,
                        evidence.journal_entries_over_ninep,
                        evidence.journal_entries_final,
                        evidence.held_effect_exactly_once,
                        evidence.second_session_bytes,
                        evidence.second_session_expected_bytes,
                        evidence.second_session_checksum_matches,
                        evidence.second_session_messages,
                        evidence.second_session_getattr_size,
                        evidence.attach_count,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-process-restart exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-write-restart" => {
            match tokio::time::timeout(
                Duration::from_secs(360),
                tunnel_test_harness::production_cluster::verify_fs_write_restart(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_write_restart_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem write restart passed: relays={} owner={} subprotocol={} msize={} dialect={} prefix_bytes={} held_region_before_send={} prefix_region_after_write={} prefix_acknowledged_bytes={} prefix_write_advanced_mtime={} stream={} emitted={}->{} recv_contiguous={}->{} request_outstanding_at_kill={} restart_polls={} held_tag={} held_region_before_kill={} torn_observed_before_kill={} journal_polls={} first_pid={} first_process_exited={} first_process_killed_by_signal={} second_pid={} second_process_active={} epoch={}->{} session={}->{} owner_released_between={} pending_call_closed={} pending_call_close_code={:?} pending_call_answered={} pending_call_errored={} held_call_outcome={:?} held_stream_deregistered={} held_region_after_restart={} stale_file_fid_refused={} stale_file_fid_errno={:?} retry_refused_above_dispatch={} retry_refusal_errno={:?} host_mtime_unchanged_across_retry={} held_region_after_retry={} image_bytes={}/{} image_outside_held_region_matches={} second_session_msize={} second_session_attached={} held_region_over_ninep={} ninep_image_matches_host={} second_session_bytes={}/{} second_session_messages={} second_session_getattr_size={} attach_count={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.selected_subprotocol,
                        evidence.negotiated_msize,
                        evidence.negotiated_dialect,
                        evidence.prefix_bytes,
                        evidence.held_region_before_send.as_str(),
                        evidence.prefix_region_after_write.as_str(),
                        evidence.prefix_acknowledged_bytes,
                        evidence.prefix_write_advanced_mtime,
                        evidence.restart.stream_id,
                        evidence.restart.emitted_before,
                        evidence.restart.emitted_at_kill,
                        evidence.restart.recv_contiguous_before,
                        evidence.restart.recv_contiguous_at_kill,
                        evidence.request_outstanding_at_kill,
                        evidence.restart_polls,
                        evidence.held_tag,
                        evidence.held_region_before_kill.as_str(),
                        evidence.torn_observed_before_kill,
                        evidence.journal_polls,
                        evidence.first_pid,
                        evidence.first_process_exited,
                        evidence.first_process_killed_by_signal,
                        evidence.second_pid,
                        evidence.second_process_active,
                        evidence.epoch_before,
                        evidence.epoch_after,
                        evidence.session_id_before,
                        evidence.session_id_after,
                        evidence.owner_released_between,
                        evidence.pending_call_closed,
                        evidence.pending_call_close_code,
                        evidence.pending_call_answered,
                        evidence.pending_call_errored,
                        evidence.held_call_outcome.map(tunnel_fs_core::Outcome::as_str),
                        evidence.held_stream_deregistered,
                        evidence.held_region_after_restart.as_str(),
                        evidence.stale_file_fid_refused,
                        evidence.stale_file_fid_errno,
                        evidence.retry_refused_above_dispatch,
                        evidence.retry_refusal_errno,
                        evidence.host_mtime_unchanged_across_retry,
                        evidence.held_region_after_retry.as_str(),
                        evidence.image_bytes,
                        evidence.image_expected_bytes,
                        evidence.image_outside_held_region_matches,
                        evidence.second_session_msize,
                        evidence.second_session_attached,
                        evidence.held_region_over_ninep.as_str(),
                        evidence.ninep_image_matches_host,
                        evidence.second_session_bytes,
                        evidence.second_session_expected_bytes,
                        evidence.second_session_messages,
                        evidence.second_session_getattr_size,
                        evidence.attach_count,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-write-restart exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-rename-restart" => {
            match tokio::time::timeout(
                Duration::from_secs(360),
                tunnel_test_harness::production_cluster::verify_fs_rename_restart(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_rename_restart_evidence(
                        &evidence,
                    )?;
                    println!(
                        "M4 filesystem rename restart passed: relays={} owner={} subprotocol={} msize={} dialect={} prefix_bytes={} held_namespace_before_send={} control_namespace={}->{} source_inode_before={:?} destination_inode_after={:?} rename_preserved_the_inode={} inode_instrument_discriminates={} entry_count={}->{} stream={} emitted={}->{} recv_contiguous={}->{} request_outstanding_at_kill={} restart_polls={} held_tag={} held_namespace_before_kill={} journal_polls={} forbidden_intermediate_observed={} first_pid={} first_process_exited={} first_process_killed_by_signal={} second_pid={} second_process_active={} epoch={}->{} session={}->{} owner_released_between={} pending_call_closed={} pending_call_close_code={:?} pending_call_answered={} pending_call_errored={} held_call_outcome={:?} held_stream_deregistered={} held_namespace_after_restart={} stale_source_fid_refused={} stale_source_fid_errno={:?} retry_refused_above_dispatch={} retry_refusal_errno={:?} held_namespace_after_retry={} absent_source_control_refused={} absent_source_control_errno={:?} errno_instrument_discriminates={} held_namespace_after_control={} second_session_msize={} second_session_attached={} second_session_bytes={}/{} second_session_messages={} renamed_content_matches={} second_session_getattr_size={} namespace_over_ninep={} source_name_walk_refused={} attach_count={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.selected_subprotocol,
                        evidence.negotiated_msize,
                        evidence.negotiated_dialect,
                        evidence.prefix_bytes,
                        evidence.held_namespace_before_send.as_str(),
                        evidence.control_namespace_before.as_str(),
                        evidence.control_namespace_after.as_str(),
                        evidence.source_inode_before,
                        evidence.destination_inode_after,
                        evidence.rename_preserved_the_inode(),
                        evidence.inode_instrument_discriminates(),
                        evidence.entry_count_before,
                        evidence.entry_count_after,
                        evidence.restart.stream_id,
                        evidence.restart.emitted_before,
                        evidence.restart.emitted_at_kill,
                        evidence.restart.recv_contiguous_before,
                        evidence.restart.recv_contiguous_at_kill,
                        evidence.request_outstanding_at_kill,
                        evidence.restart_polls,
                        evidence.held_tag,
                        evidence.held_namespace_before_kill.as_str(),
                        evidence.journal_polls,
                        evidence.forbidden_intermediate_observed,
                        evidence.first_pid,
                        evidence.first_process_exited,
                        evidence.first_process_killed_by_signal,
                        evidence.second_pid,
                        evidence.second_process_active,
                        evidence.epoch_before,
                        evidence.epoch_after,
                        evidence.session_id_before,
                        evidence.session_id_after,
                        evidence.owner_released_between,
                        evidence.pending_call_closed,
                        evidence.pending_call_close_code,
                        evidence.pending_call_answered,
                        evidence.pending_call_errored,
                        evidence.held_call_outcome.map(tunnel_fs_core::Outcome::as_str),
                        evidence.held_stream_deregistered,
                        evidence.held_namespace_after_restart.as_str(),
                        evidence.stale_source_fid_refused,
                        evidence.stale_source_fid_errno,
                        evidence.retry_refused_above_dispatch,
                        evidence.retry_refusal_errno,
                        evidence.held_namespace_after_retry.as_str(),
                        evidence.absent_source_control_refused,
                        evidence.absent_source_control_errno,
                        evidence.errno_instrument_discriminates(),
                        evidence.held_namespace_after_control.as_str(),
                        evidence.second_session_msize,
                        evidence.second_session_attached,
                        evidence.second_session_bytes,
                        evidence.second_session_expected_bytes,
                        evidence.second_session_messages,
                        evidence.renamed_content_matches,
                        evidence.second_session_getattr_size,
                        evidence.namespace_over_ninep.as_str(),
                        evidence.source_name_walk_refused,
                        evidence.attach_count,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-rename-restart exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m4-fs-client-e2e" => {
            match tokio::time::timeout(
                Duration::from_secs(600),
                tunnel_test_harness::production_cluster::verify_fs_client_e2e(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // Re-validate at the command boundary so a validator
                    // regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_fs_client_e2e(&evidence)?;
                    println!(
                        "M4 filesystem client end-to-end passed: relays={} owner={} client_module_is_the_package={} public_entry_point={} endpoints_all_https={} node_tls_reject_unauthorized={} probe_code={} probe_retryable={} probe_extra_ca={} schema={} subprotocol={} dialect={} operations={:?} read_only_root={} availability={} unauthenticated={} revision_moved={} revision_upgrade={} revision_upgrade_status={} msize={} lifecycle={} read_bytes={} read_checksum={} read_messages={} write_bytes={} write_messages={} write_acks={} write_host_bytes={} write_host_checksum={} listing_names={} listing_unique={} ro_read={} ro_client_codes={:?} ro_device_codes={:?} ro_host_unchanged={} unknown_requests={} unknown_classified={} unknown_client_acknowledged={} unknown_close_codes={:?} ledger_before={:?} ledger_after={:?} ledger_identity={} unknown_host_bytes={} unknown_host_pattern={} unknown_host_matches_ledger={} device_applied_beyond_client_knowledge={} read_only_device_refused={} read_only_client_reported_failed={} adapter={} adapter_read={} adapter_write_bytes={} adapter_host_write={} adapter_listing={} adapter_stat={} adapter_append={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.client_module_is_the_package,
                        evidence.public_entry_point_used,
                        evidence.endpoints_all_https,
                        evidence.node_tls_reject_unauthorized,
                        evidence.probe_code,
                        evidence.probe_retryable,
                        evidence.probe_extra_ca,
                        evidence.descriptor_schema_version,
                        evidence.descriptor_subprotocol,
                        evidence.descriptor_dialect,
                        evidence.descriptor_operations,
                        evidence.descriptor_read_only,
                        evidence.descriptor_availability,
                        evidence.unauthenticated_code,
                        evidence.revision_advanced_in_catalog,
                        evidence.revision_upgrade_code,
                        evidence.revision_upgrade_status,
                        evidence.negotiated_msize,
                        evidence.session_lifecycle,
                        evidence.read_bytes,
                        evidence.read_checksum_matches,
                        evidence.read_messages,
                        evidence.write_bytes,
                        evidence.write_messages,
                        evidence.write_acknowledgements,
                        evidence.write_host_bytes,
                        evidence.write_host_checksum_matches,
                        evidence.listing_names_observed,
                        evidence.listing_every_name_exactly_once,
                        evidence.read_only_read_matches,
                        evidence.read_only_client_codes,
                        [
                            evidence.read_only_device_create_code.as_str(),
                            evidence.read_only_device_mkdir_code.as_str(),
                            evidence.read_only_device_unlink_code.as_str(),
                            evidence.read_only_device_open_write_code.as_str(),
                        ],
                        evidence.read_only_host_unchanged,
                        evidence.unknown_requests,
                        evidence.unknown_classified_unknown,
                        evidence.unknown_client_acknowledged_bytes,
                        evidence.unknown_close_codes,
                        evidence.ledger_before,
                        evidence.ledger_after,
                        evidence.ledger_identity_holds,
                        evidence.unknown_host_bytes,
                        evidence.unknown_host_pattern_matches,
                        evidence.unknown_host_matches_ledger,
                        evidence.device_applied_beyond_client_knowledge,
                        evidence.read_only_device_refused,
                        evidence.read_only_client_reported_failed,
                        evidence.adapter_name,
                        evidence.adapter_read_matches,
                        evidence.adapter_write_bytes,
                        evidence.adapter_host_write_matches,
                        evidence.adapter_listing_names,
                        evidence.adapter_stat_size_matches,
                        evidence.adapter_append_refused,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m4-fs-client-e2e exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m3-http-forward-rotation" => {
            match tokio::time::timeout(
                Duration::from_secs(480),
                tunnel_test_harness::production_cluster::verify_http_forward_rotation(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_http_forward_rotation_evidence(
                        &evidence,
                    )?;
                    let cases = evidence
                        .cases
                        .iter()
                        .map(|case| {
                            format!(
                                "{}(stream={} rotations={:?} positions={:?} invocations={} heads={} ends={} fin={} exact={} forgotten={})",
                                case.name,
                                case.stream_id,
                                case.observations
                                    .iter()
                                    .map(|observation| observation.rotation)
                                    .collect::<Vec<_>>(),
                                case.observations
                                    .iter()
                                    .map(|observation| (
                                        observation.request.position,
                                        observation.response.position,
                                        observation.relay_fence,
                                        observation.connector_fence
                                    ))
                                    .collect::<Vec<_>>(),
                                case.handler_invocations,
                                case.device_request_heads,
                                case.device_request_ends,
                                case.device_request_fin,
                                case.bytes_exact,
                                case.forgotten,
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    let race = &evidence.cancel_race;
                    println!(
                        "M3 http-forward rotation passed: relays={} resign_spacing_ms={} owner={} ingress={} non_owner_ingress={} session_stable={} rotations_completed={} steady_state_sockets={:?} device_socket_peak={} admission_probe={:?} cases=[{}] cancel_race=(stream={} freeze_polls={} held={} handler_cancelled_while_frozen={} still_frozen={} deferred_reset={} unsequenced={} cancel_sent={} device_cancel={} reset_sequence={:?} relay_fence={:?} reset_generation={:?} new_generation={:?} forgotten={}) lost_ack=({:?}) owner_loss=({:?})",
                        evidence.relay_count,
                        evidence.resign_spacing_ms,
                        evidence.owner_node,
                        evidence.ingress_node,
                        evidence.non_owner_ingress,
                        evidence.session_stable,
                        evidence.rotations_completed,
                        evidence.steady_state_sockets,
                        evidence.device_socket_peak,
                        evidence.admission_probe,
                        cases,
                        race.stream_id,
                        race.freeze_observation_polls,
                        race.freeze_held,
                        race.handler_cancelled_while_frozen,
                        race.owner_still_frozen_after_cancel,
                        race.deferred_reset_while_frozen,
                        race.reset_unsequenced_while_frozen,
                        race.cancel_sent,
                        race.device_cancel_received,
                        race.owner_record.as_ref().and_then(|record| record.reset_sequence),
                        race.observation.as_ref().and_then(|observation| observation.relay_fence),
                        race.owner_record.as_ref().and_then(|record| record.reset_generation),
                        race.observation.as_ref().map(|observation| observation.new_generation),
                        race.forgotten,
                        evidence.lost_ack,
                        evidence.owner_loss,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m3-http-forward-rotation exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m3-mcp-cloud-client" => {
            match tokio::time::timeout(
                Duration::from_secs(1_500),
                tunnel_test_harness::production_cluster::verify_mcp_cloud_client(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    tunnel_test_harness::production_cluster::validate_mcp_cloud_client_evidence(
                        &evidence,
                    )?;
                    // Payload-free: kinds, profiles, stream IDs, rotation
                    // numbers and counters.
                    for combo in &evidence.combos {
                        println!(
                            "M3 MCP cloud client {}/{}: discovery(lifecycle={} tools_list={} echo={}) notifications(progress={:?} logs={:?} request_stream_logs={} standalone_logs={} standalone_streams={}) cancellation(stream={} invocations={} observed={} responses={} bridge_cancel={} descendant_killed={:?} release={} reset_reason={:?}) crash(failed={} invocations={} responses={} follow_up_attempts={} session_expired={} lifecycle_after={} children_after={} interrupted={} sessions_ended={} descendant_killed={:?} backend_exited={:?}) rotation_discovery(stream={} rotation={:?} dispatches={}) rotation_invocation(stream={} rotation={:?} dispatches={}) streaming(stream={} rotations={:?} events={} exact={} invocations={} children={})",
                            combo.kind,
                            combo.profile,
                            combo.discovery.lifecycle_dispatches,
                            combo.discovery.tools_list_dispatches,
                            combo.discovery.echo_invocations,
                            combo.notifications.progress_values,
                            combo.notifications.log_seqs,
                            combo.notifications.wire.logs_on_request_streams,
                            combo.notifications.wire.logs_on_standalone_streams,
                            combo.notifications.wire.standalone_opened,
                            combo.cancellation.stream_id,
                            combo.cancellation.invocations,
                            combo.cancellation.server_observed_cancel,
                            combo.cancellation.cancelled_call_responses,
                            combo.cancellation.bridge_cancel_notifications,
                            combo.cancellation.descendant_killed,
                            combo.cancellation.owner_release,
                            combo.cancellation.owner_reset_reason,
                            combo.crash.call_failed,
                            combo.crash.invocations,
                            combo.crash.crash_responses,
                            combo.crash.follow_up_attempts,
                            combo.crash.wire.session_expired,
                            combo.crash.lifecycle_dispatches_after_crash,
                            combo.crash.children_spawned_after_crash,
                            combo.crash.export_interrupted,
                            combo.crash.sessions_ended,
                            combo.crash.descendant_killed,
                            combo.crash.backend_exited,
                            combo.rotation_discovery.stream_id,
                            combo
                                .rotation_discovery
                                .observation
                                .as_ref()
                                .map(|observation| observation.rotation),
                            combo.rotation_discovery.dispatches,
                            combo.rotation_invocation.stream_id,
                            combo
                                .rotation_invocation
                                .observation
                                .as_ref()
                                .map(|observation| observation.rotation),
                            combo.rotation_invocation.dispatches,
                            combo.streaming.stream_id,
                            combo
                                .streaming
                                .observations
                                .iter()
                                .map(|observation| observation.rotation)
                                .collect::<Vec<_>>(),
                            combo.streaming.events_received,
                            combo.streaming.events_exact_in_order,
                            combo.streaming.invocations,
                            combo.streaming.children_spawned,
                        );
                        println!(
                            "M3 MCP cloud client {}/{}: session(stable={} rotations={} highest_stream={} children_after_stop={}) not_dispatched(refusals={:?} freeze_retries={:?} standalone_refusals={:?} standalone_retries={:?} unexplained={:?})",
                            combo.kind,
                            combo.profile,
                            combo.session_stable,
                            combo.session_rotations,
                            combo.highest_call_stream_id,
                            combo.children_running_after_stop,
                            combo
                                .case_wires()
                                .iter()
                                .map(|(case, wire)| (*case, wire.not_dispatched_refusals))
                                .collect::<Vec<_>>(),
                            combo
                                .case_wires()
                                .iter()
                                .map(|(case, wire)| (*case, wire.not_dispatched_retries))
                                .collect::<Vec<_>>(),
                            combo
                                .case_wires()
                                .iter()
                                .map(|(case, wire)| {
                                    (*case, wire.standalone_not_dispatched_refusals)
                                })
                                .collect::<Vec<_>>(),
                            combo
                                .case_wires()
                                .iter()
                                .map(|(case, wire)| (*case, wire.standalone_retries))
                                .collect::<Vec<_>>(),
                            combo
                                .case_wires()
                                .iter()
                                .filter_map(|(case, wire)| {
                                    wire.unexplained_refusal
                                        .as_ref()
                                        .map(|cause| (*case, cause.clone()))
                                })
                                .collect::<Vec<_>>(),
                        );
                    }
                    println!(
                        "M3 MCP cloud client passed: relays={} owner={} ingress={} profiles={:?} session_stable={} rotations={} sidecar_connections={} ingress_exchanges={} owner_exchanges={} leftover_processes={} not_covered={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.ingress_node,
                        evidence.relay_profiles,
                        evidence.device_session_stable,
                        evidence.rotations_completed,
                        evidence.sidecar_connections,
                        evidence.ingress_exchanges_recorded,
                        evidence.owner_exchanges_recorded,
                        evidence.leftover_processes,
                        evidence.not_covered.len(),
                    );
                    let hold = &evidence.owner_freeze_hold;
                    println!(
                        "M3 MCP cloud client owner rotation-freeze hold: held={} admitted_after_hold={} released_on_commit={} released_on_abort={} released_on_recovery={} released_with_deferred_writes={} refused_after_bound={} refused_hold_full={} cancelled={} released_on_session_loss={} currently_held={} max_hold_wait_ms={}",
                        hold.held,
                        hold.admitted_after_hold,
                        hold.released_on_commit,
                        hold.released_on_abort,
                        hold.released_on_recovery,
                        hold.released_with_deferred_writes,
                        hold.refused_after_bound,
                        hold.refused_hold_full,
                        hold.cancelled,
                        hold.released_on_session_loss,
                        hold.currently_held,
                        hold.max_hold_wait_ms,
                    );
                    println!(
                        "M3 MCP cloud client not_dispatched totals: refusals={} freeze_retries={} (only the relay's ROTATION_FREEZE answer is resent for a POST)",
                        evidence
                            .combos
                            .iter()
                            .flat_map(tunnel_test_harness::production_cluster::McpComboEvidence::case_wires)
                            .map(|(_, wire)| wire.not_dispatched_refusals)
                            .sum::<u64>(),
                        evidence
                            .combos
                            .iter()
                            .flat_map(tunnel_test_harness::production_cluster::McpComboEvidence::case_wires)
                            .map(|(_, wire)| wire.not_dispatched_retries)
                            .sum::<u64>(),
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m3-mcp-cloud-client exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m3-mcp-isolation" => {
            match tokio::time::timeout(
                Duration::from_secs(1_500),
                tunnel_test_harness::production_cluster::verify_mcp_isolation(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    // The validator runs again at the command boundary, so a
                    // validator regression cannot silently pass the command.
                    tunnel_test_harness::production_cluster::validate_mcp_isolation_evidence(
                        &evidence,
                    )?;
                    // Payload-free: statuses, counts and typed codes.
                    println!(
                        "M3 MCP isolation binding-forgery: attempts={} refused={} ingress_rejections={} dispatched={}",
                        evidence.forgery.attempts,
                        evidence.forgery.refused,
                        evidence.forgery.ingress_rejections,
                        evidence.forgery.dispatched,
                    );
                    println!(
                        "M3 MCP isolation session-isolation: distinct={} foreign(post={} get={} delete={}) indistinguishable={} own_served={} sibling_served={} notifications({}/{}) no_cross_delivery={} sessions_opened={} children={}",
                        evidence.isolation.sessions_distinct,
                        evidence.isolation.foreign_post_status,
                        evidence.isolation.foreign_get_status,
                        evidence.isolation.foreign_delete_status,
                        evidence.isolation.foreign_matches_unknown,
                        evidence.isolation.owner_still_served,
                        evidence.isolation.sibling_still_served,
                        evidence.isolation.own_notifications,
                        evidence.isolation.sibling_notifications,
                        evidence.isolation.no_cross_delivery,
                        evidence.isolation.sessions_opened,
                        evidence.isolation.children_spawned,
                    );
                    println!(
                        "M3 MCP isolation correlation: calls_per_principal={} sessionless_exact={} session_exact={} progress_exact={} duplicate(id={} token={}) answers={} misrouted={}",
                        evidence.correlation.calls_per_principal,
                        evidence.correlation.sessionless_exact,
                        evidence.correlation.session_exact,
                        evidence.correlation.progress_exact,
                        evidence.correlation.duplicate_id_status,
                        evidence.correlation.duplicate_token_status,
                        evidence.correlation.answers,
                        evidence.correlation.misrouted,
                    );
                    println!(
                        "M3 MCP isolation revocation: baseline={} in_flight({} {} {} withdrawn_in={}ms) after({} {} {}) within={}ms dispatched_after={} sibling_served={} device_session_survived={} revoked_session_unreachable={}",
                        evidence.revocation.baseline_status,
                        evidence.revocation.in_flight_status,
                        evidence.revocation.in_flight_code,
                        evidence.revocation.in_flight_execution,
                        evidence.revocation.withdrawn_within_ms,
                        evidence.revocation.after_status,
                        evidence.revocation.after_code,
                        evidence.revocation.after_execution,
                        evidence.revocation.failed_within_ms,
                        evidence.revocation.dispatched_after,
                        evidence.revocation.sibling_principal_served,
                        evidence.revocation.device_session_survived,
                        evidence.revocation.revoked_session_unreachable,
                    );
                    println!(
                        "M3 MCP isolation rotation-span: rotations={} dispatched_between_rotations={} anchor_to_dispatch_ms={} status={} exact={} invocations={} session_stable={}",
                        evidence.rotation_span.rotations_spanned,
                        evidence.rotation_span.dispatched_between_rotations,
                        evidence.rotation_span.anchor_to_dispatch_ms,
                        evidence.rotation_span.status,
                        evidence.rotation_span.result_exact,
                        evidence.rotation_span.invocations,
                        evidence.rotation_span.session_stable,
                    );
                    for outcome in [&evidence.lost_ack, &evidence.owner_loss] {
                        println!(
                            "M3 MCP isolation unknown-outcome {}: status={} code={} execution={} outcome={} side_effects({} -> {}) settled_on={} device_exchanges={}",
                            outcome.fault,
                            outcome.status,
                            outcome.body_code,
                            outcome.body_execution,
                            outcome.result_outcome,
                            outcome.side_effects_before_fault,
                            outcome.side_effects_after_outcome,
                            outcome.settled_on,
                            outcome.device_exchanges,
                        );
                    }
                    println!(
                        "M3 MCP isolation passed: relays={} owner={} ingress={} profiles={:?} principals={} device_sessions={} journal_peak={} sessions({} opened, {} ended) children_after_stop={} not_covered={}",
                        evidence.relay_count,
                        evidence.owner_node,
                        evidence.ingress_node,
                        evidence.relay_profiles,
                        evidence.principals,
                        evidence.device_sessions,
                        evidence.journal_entries_peak,
                        evidence.sessions_opened,
                        evidence.sessions_deleted,
                        evidence.children_after_stop,
                        evidence.not_covered.len(),
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "verify-m3-mcp-isolation exceeded its bounded deadline".into(),
                )),
            }
        }
        [command] if command == "verify-m7-queue-saturation" => {
            match tokio::time::timeout(
                Duration::from_secs(240),
                tunnel_test_harness::production_cluster::verify_queue_saturation(),
            )
            .await
            {
                Ok(result) => result.and_then(|evidence| {
                    require_m7_queue_saturation_evidence(&evidence)?;
                    println!(
                        "M7 queue saturation passed: relays={} ready={} non_owner_ingress={} queue_bytes_limit={} data_slots={} control_slots={} max_streams={} record_bytes={} charge_per_record={} frames_per_record={} credit_records_per_stream={} reachable_entries={} route_maximum_entries={} streams_admitted={} stream_cap_refused_one_more={} data_depth_observed={} data_depth_high_water={} data_enqueues_during_blackhole={} physically_resident_frames={} absorbed_frames={} absorbed_wire_bytes={} reachable_bound_saturated={} reserved_free_data_slots={} reserved_data_slot_accepted={} queue_bytes_high_water={} headroom_at_peak={} control_reserved_bytes={} data_bytes_limit={} data_bytes_high_water={} control_bytes_available_at_data_peak={} control_depth_at_peak={} control_depth_high_water={} control_refusals={} control_enqueues_during_blackhole={} cancellation_accepted={} fresh_stream_admitted={} sibling_survived={} first_terminal_immutable={} terminal_observations={} terminal_tombstone_observations={} paused_target_to_client={} paused_generation={} drain_observations={}/{} drained={} rotation_replaced_paused_carrier={} rotation_generation={} rotations_after_drain={} final_generation={} attempts_with_deadline={} deadline_never_extended={} deadline_within_overlap={} device_sockets={} device_send_buffer_bytes={} dispatch_delta_after_drain={} elapsed_ms={}",
                        evidence.relay_count,
                        evidence.membership_ready_relays,
                        evidence.non_owner_ingress,
                        evidence.configured_queue_bytes_limit,
                        evidence.configured_data_queue_capacity,
                        evidence.configured_control_queue_capacity,
                        evidence.configured_max_streams_per_device,
                        evidence.workload_record_bytes,
                        evidence.workload_charge_per_record_bytes,
                        evidence.workload_frames_per_record,
                        evidence.workload_records_per_stream_by_credit,
                        evidence.workload_reachable_entries,
                        evidence.route_maximum_reachable_entries,
                        evidence.streams_admitted,
                        evidence.stream_cap_refused_one_more,
                        evidence.data_queue_depth_observed,
                        evidence.data_queue_depth_high_water,
                        evidence.data_enqueues_during_blackhole,
                        evidence.physically_resident_frames,
                        evidence.writer_absorbed_frames,
                        evidence.writer_absorbed_wire_bytes,
                        evidence.reachable_bound_saturated,
                        evidence.reserved_free_data_slots_at_peak,
                        evidence.reserved_data_slot_accepted_at_peak,
                        evidence.queue_bytes_high_water,
                        evidence.queue_bytes_headroom_at_peak,
                        evidence.configured_control_reserved_bytes,
                        evidence.configured_data_bytes_limit,
                        evidence.data_bytes_high_water,
                        evidence.control_bytes_available_at_data_peak,
                        evidence.control_queue_depth_at_peak,
                        evidence.control_queue_depth_high_water,
                        evidence.control_queue_refusals,
                        evidence.control_enqueues_during_blackhole,
                        evidence.cancellation_accepted_after_resume,
                        evidence.fresh_stream_admitted_after_cancellation,
                        evidence.sibling_stream_survived,
                        evidence.first_terminal_observation_immutable,
                        evidence.terminal_observations,
                        evidence.terminal_tombstone_observations,
                        evidence.paused_target_to_client,
                        evidence.paused_generation,
                        evidence.physical_drain_observations,
                        evidence.physical_drain_observation_bound,
                        evidence.physical_drain_completed,
                        evidence.rotation_replaced_paused_carrier,
                        evidence.rotation_committed_generation,
                        evidence.rotations_completed_after_drain,
                        evidence.final_generation,
                        evidence.rotation_attempts_with_observed_deadline,
                        evidence.rotation_deadline_never_extended,
                        evidence.rotation_deadline_within_configured_overlap,
                        evidence.device_socket_peak_open,
                        evidence.device_send_buffer_bytes,
                        evidence.dispatch_delta_after_drain,
                        evidence.elapsed_ms,
                    );
                    Ok(())
                }),
                Err(_) => Err(HarnessError::Timeout(
                    "M7 queue saturation acceptance exceeded 240 seconds".to_owned(),
                )),
            }
        }
        [command] if command == "verify-m7-c11-diagnostics" => {
            tunnel_test_harness::production_cluster::verify_c11_diagnostics()
                .await
                .map(|evidence| {
                    println!(
                        "M7 C11 diagnostics passed: source={} build={} runs={} safe_field_count={} captured_streams={} captured_bytes={} peer_fault_tuples={} window_start_ms={} window_end_ms={}",
                        evidence.source_id,
                        evidence.build_id,
                        evidence.runs,
                        evidence.safe_field_count,
                        evidence.captured_streams,
                        evidence.captured_bytes,
                        evidence.peer_fault_tuples,
                        evidence.matrix_started_utc_ms,
                        evidence.matrix_ended_utc_ms,
                    );
                })
        }
        [command] if command == "verify-m7-og02-correlation" => {
            tunnel_test_harness::production_cluster::verify_og02_correlation()
                .await
                .map(|evidence| {
                    for row in &evidence.rows {
                        println!(
                            "M7 OG-02 row={} command={} correlation={} peer_fault_required={} missing={} peer_fault_tuples={} tuples={} captured_streams={} captured_bytes={} started_ms={} ended_ms={}",
                            row.name,
                            row.command,
                            if row.complete { "complete" } else { "incomplete" },
                            row.peer_fault_required,
                            if row.missing_fields.is_empty() {
                                "none".to_owned()
                            } else {
                                row.missing_fields.join(",")
                            },
                            row.peer_fault_tuples.len(),
                            if row.peer_fault_tuples.is_empty() {
                                "none".to_owned()
                            } else {
                                row.peer_fault_tuples.join(",")
                            },
                            row.captured_streams,
                            row.captured_bytes,
                            row.started_utc_ms,
                            row.ended_utc_ms,
                        );
                    }
                    println!(
                        "M7 OG-02 correlation passed: source={} build={} rows={} complete_rows={} incomplete_rows={} window_start_ms={} window_end_ms={}",
                        evidence.source_id,
                        evidence.build_id,
                        evidence.rows.len(),
                        evidence.complete_rows(),
                        evidence.incomplete_rows(),
                        evidence.window_started_utc_ms,
                        evidence.window_ended_utc_ms,
                    );
                })
        }
        [command] if command == "verify-m7-cluster" => {
            cluster_acceptance::verify().await.map(|_| ())
        }
        [
            command,
            url_flag,
            url,
            namespace_flag,
            namespace,
            receipt_flag,
            receipt,
        ] if matches!(
            command.as_str(),
            "redis-restart-seed" | "redis-restart-check"
        ) && url_flag == "--redis-url"
            && namespace_flag == "--namespace"
            && receipt_flag == "--receipt-file" =>
        {
            let operation = async {
                if command == "redis-restart-seed" {
                    redis_restart::seed(url, namespace, receipt).await
                } else {
                    redis_restart::check(url, namespace, receipt).await
                }
            };
            match tokio::time::timeout(Duration::from_secs(30), operation).await {
                Ok(result) => result.map_err(|error| HarnessError::Redis(error.to_string())),
                Err(_) => Err(HarnessError::Timeout(
                    "Redis restart probe exceeded 30 seconds".to_owned(),
                )),
            }
        }
        [
            command,
            url_flag,
            url,
            namespace_flag,
            namespace,
            handshake_flag,
            handshake,
        ] if command == "redis-lane-restart"
            && url_flag == "--redis-url"
            && namespace_flag == "--namespace"
            && handshake_flag == "--handshake-file" =>
        {
            // The owning script restarts the Redis process between this
            // command's two handshake signals, so the command's own bound is
            // the module's bounded wait plus its bounded post-restart probes.
            redis_lane_restart::run(url, namespace, handshake)
                .await
                .map(|evidence| {
                    println!("{}", evidence.evidence_line());
                })
                .map_err(|error| HarnessError::Redis(error.to_string()))
        }
        [] => {
            print_help();
            Ok(())
        }
        [command] if matches!(command.as_str(), "help" | "--help" | "-h") => {
            print_help();
            Ok(())
        }
        _ => Err(HarnessError::InvalidInput(
            "unknown command; use --help".to_owned(),
        )),
    };
    let exit_code = command_exit_code(&result);
    if let Err(error) = result {
        eprintln!("tunnel-test-harness: {error}");
    }
    exit_code
}

/// Keep the process-status decision shared by the binary entrypoint and the
/// false-evidence regression tests. The acceptance command still prints the
/// original bounded error before returning this status.
/// Render one fail-closed sentinel outcome as a compact, payload-free field.
/// Only the status, the allowlisted bounded code and execution, the declared
/// and delivered body byte counts, and the elapsed milliseconds appear.
fn fail_closed_outcome(
    outcome: &tunnel_test_harness::production_cluster::SentinelOutcome,
) -> String {
    format!(
        "{}/{}:{}:{}:declared={}:delivered={}:failed_stream={}:transport_failed={}:{}ms",
        outcome.label,
        outcome.status,
        outcome.code.unwrap_or("none"),
        outcome.execution.unwrap_or("none"),
        outcome.declared_body_bytes,
        outcome.delivered_body_bytes,
        outcome.body_stream_failed,
        outcome.transport_failed,
        outcome.elapsed_ms,
    )
}

fn command_exit_code(result: &Result<(), HarnessError>) -> ExitCode {
    acceptance_command_exit_code(result)
}

fn require_m7_acceptance_flags(label: &str, checks: &[(&str, bool)]) -> Result<(), HarnessError> {
    let failed = checks
        .iter()
        .filter_map(|(name, passed)| (!*passed).then_some(*name))
        .collect::<Vec<_>>();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(format!(
            "{label} returned incomplete acceptance evidence: {}",
            failed.join(", ")
        )))
    }
}

fn require_m7_transport_evidence(
    evidence: &cluster_transport::ClusterTransportEvidence,
) -> Result<(), HarnessError> {
    require_m7_acceptance_flags(
        "M7 transport",
        &[
            (
                "response_before_request_end",
                evidence.response_before_request_end,
            ),
            ("body_before_request_end", evidence.body_before_request_end),
            ("wrong_pin_rejected", evidence.wrong_pin_rejected),
            ("wrong_role_rejected", evidence.wrong_role_rejected),
            (
                "oversized_chunk_rejected",
                evidence.oversized_chunk_rejected,
            ),
            ("client_shutdown_joined", evidence.client_shutdown_joined),
            ("server_shutdown_joined", evidence.server_shutdown_joined),
            (
                "response_head_truncation_rejected",
                evidence.response_head_truncation_rejected,
            ),
            (
                "response_body_truncation_rejected",
                evidence.response_body_truncation_rejected,
            ),
            ("idle_blackhole_closed", evidence.idle_blackhole_closed),
            (
                "saturated_lane_cancellation_bounded",
                evidence.saturated_lane_cancellation_bounded,
            ),
            (
                "active_stream_pin_revocation_closed",
                evidence.active_stream_pin_revocation_closed,
            ),
            ("shared_stream_isolated", evidence.shared_stream_isolated),
            (
                "body_budget_reclamation_verified",
                evidence.body_budget_reclamation_verified,
            ),
            ("udp_blackhole_restored", evidence.udp_blackhole_restored),
            ("no_tcp_fallback", evidence.no_tcp_fallback),
            ("zero_rtt_not_admitted", evidence.zero_rtt_not_admitted),
        ],
    )
}

fn require_m7_redis_tls_evidence(
    evidence: &redis_tls::RedisTlsEvidence,
) -> Result<(), HarnessError> {
    require_m7_acceptance_flags(
        "M7 Redis TLS",
        &[
            (
                "authenticated_catalog_connection",
                evidence.authenticated_catalog_connection,
            ),
            ("wrong_ca_rejected", evidence.wrong_ca_rejected),
            (
                "wrong_server_name_rejected",
                evidence.wrong_server_name_rejected,
            ),
            (
                "wrong_client_identity_rejected",
                evidence.wrong_client_identity_rejected,
            ),
        ],
    )
}

/// Require the full owner-lease expiry contract at the CLI boundary.
///
/// The module validator already checks every bound; re-stating the flags and
/// epochs here means a validator regression cannot silently pass the command.
fn require_m7_owner_lease_expiry_evidence(
    evidence: &tunnel_test_harness::production_cluster::OwnerLeaseExpiryEvidence,
) -> Result<(), HarnessError> {
    tunnel_test_harness::production_cluster::validate_owner_lease_expiry_evidence(evidence)
        .map_err(|error| HarnessError::Process(error.to_string()))?;
    require_m7_acceptance_flags(
        "M7 owner lease expiry",
        &[
            ("relay_count_is_three", evidence.relay_count == 3),
            (
                "catalog_generation_preserved",
                evidence.catalog_generation_preserved,
            ),
            ("baseline_echo", evidence.baseline_echo),
            (
                "owner_present_after_barrier",
                evidence.owner_present_after_barrier,
            ),
            (
                "owner_expired_while_partitioned",
                evidence.owner_expired_while_partitioned,
            ),
            (
                "owner_absent_after_lease_deadline",
                evidence.owner_absent_after_lease_deadline,
            ),
            (
                "expired_owner_dispatch_unchanged",
                evidence.expired_owner_dispatch_unchanged,
            ),
            (
                "stale_release_refused_after_expiry",
                evidence.stale_release_refused_after_expiry,
            ),
            ("successor_scope_matched", evidence.successor_scope_matched),
            ("successor_fresh_session", evidence.successor_fresh_session),
            (
                "stale_release_refused_after_successor",
                evidence.stale_release_refused_after_successor,
            ),
            (
                "successor_token_unchanged",
                evidence.successor_token_unchanged,
            ),
            ("successor_echo", evidence.successor_echo),
            (
                "paused_redis_connections_nonzero",
                evidence.paused_redis_connections > 0,
            ),
            (
                "retained_epoch_advanced",
                evidence.successor_epoch > evidence.original_epoch
                    && evidence.original_epoch > evidence.seeded_epoch,
            ),
            (
                "fanout_peak_open_within_bound",
                evidence.fanout_peak_open <= 3,
            ),
        ],
    )
}

fn require_m7_process_pause_evidence(
    evidence: &tunnel_test_harness::production_cluster::ProcessPauseEvidence,
) -> Result<(), HarnessError> {
    require_m7_acceptance_flags(
        "M7 process pause",
        &[
            ("relay_count_is_three", evidence.relay_count == 3),
            (
                "cli_control_data_sockets",
                evidence.cli_control_data_sockets,
            ),
            ("paused_pid_validated", evidence.paused_pid_validated),
            ("pause_fail_closed", evidence.pause_fail_closed),
            (
                "relay_dispatch_counter_unchanged",
                evidence.relay_dispatch_counter_unchanged,
            ),
            ("resumed_and_joined", evidence.resumed_and_joined),
            ("recovery_owner_verified", evidence.recovery_owner_verified),
            ("recovery_echo", evidence.recovery_echo),
            (
                "stale_payload_not_replayed",
                evidence.stale_payload_not_replayed,
            ),
            (
                "fanout_peak_open_within_bound",
                evidence.fanout_peak_open <= 3,
            ),
        ],
    )
}

fn require_m7_redis_partition_evidence(
    evidence: &tunnel_test_harness::production_cluster::RedisPartitionEvidence,
) -> Result<(), HarnessError> {
    require_m7_acceptance_flags(
        "M7 Redis partition",
        &[
            ("relay_count_is_three", evidence.relay_count == 3),
            ("baseline_echo", evidence.baseline_echo),
            (
                "partition_admission_rejected",
                evidence.partition_admission_rejected,
            ),
            (
                "partition_dispatch_interrupted",
                evidence.partition_dispatch_interrupted,
            ),
            (
                "public_livez_ok_during_partition",
                evidence.public_livez_ok_during_partition,
            ),
            (
                "public_readyz_unready_during_partition",
                evidence.public_readyz_unready_during_partition,
            ),
            (
                "public_readyz_ok_after_recovery",
                evidence.public_readyz_ok_after_recovery,
            ),
            (
                "paused_redis_connections_nonzero",
                evidence.paused_redis_connections > 0,
            ),
            ("recovery_owner_verified", evidence.recovery_owner_verified),
            ("recovery_echo", evidence.recovery_echo),
        ],
    )
}

fn require_m7_pressure_evidence(
    evidence: &tunnel_test_harness::production_cluster::PressureEvidence,
) -> Result<(), HarnessError> {
    require_m7_acceptance_flags(
        "M7 pressure",
        &[
            ("baseline_echo", evidence.baseline_echo),
            ("bulk_attempted", evidence.bulk_attempted),
            ("bounded_backpressure", evidence.bounded_backpressure),
            ("queue_budget_observed", evidence.queue_budget_observed),
            ("sibling_canary", evidence.sibling_canary),
            ("cancellation_responsive", evidence.cancellation_responsive),
            (
                "cancellation_not_replayed",
                evidence.cancellation_not_replayed,
            ),
            ("recovery_owner_verified", evidence.recovery_owner_verified),
            ("recovery_echo", evidence.recovery_echo),
            ("relay_count_is_three", evidence.relay_count == 3),
            (
                "bulk_records_attempted_nonzero",
                evidence.bulk_records_attempted > 0,
            ),
            (
                "fanout_peak_open_within_bound",
                evidence.fanout_peak_open <= 3,
            ),
        ],
    )
}

/// Require the full configured message-queue saturation contract.
///
/// The module validator already checks every bound; this independent CLI gate
/// re-states the flags and counts that must hold for the command to exit zero,
/// so a validator regression cannot silently pass the command.
fn require_m7_queue_saturation_evidence(
    evidence: &tunnel_test_harness::production_cluster::QueueSaturationEvidence,
) -> Result<(), HarnessError> {
    tunnel_test_harness::production_cluster::validate_queue_saturation_evidence(evidence)?;
    require_m7_acceptance_flags(
        "M7 queue saturation",
        &[
            ("non_owner_ingress", evidence.non_owner_ingress),
            (
                "stream_cap_refused_one_more",
                evidence.stream_cap_refused_one_more,
            ),
            (
                "reachable_bound_saturated",
                evidence.reachable_bound_saturated,
            ),
            (
                "reserved_data_slot_accepted_at_peak",
                evidence.reserved_data_slot_accepted_at_peak,
            ),
            (
                "cancellation_accepted_after_resume",
                evidence.cancellation_accepted_after_resume,
            ),
            (
                "fresh_stream_admitted_after_cancellation",
                evidence.fresh_stream_admitted_after_cancellation,
            ),
            (
                "reserved_control_capacity_stayed_live",
                evidence.control_enqueues_during_blackhole > 0,
            ),
            ("sibling_stream_survived", evidence.sibling_stream_survived),
            (
                "first_terminal_observation_immutable",
                evidence.first_terminal_observation_immutable,
            ),
            (
                "paused_connection_correlated",
                evidence.paused_connection_correlated,
            ),
            (
                "physical_drain_completed",
                evidence.physical_drain_completed,
            ),
            (
                "rotation_replaced_paused_carrier",
                evidence.rotation_replaced_paused_carrier,
            ),
            (
                "rotation_deadline_never_extended",
                evidence.rotation_deadline_never_extended,
            ),
            (
                "rotation_deadline_within_configured_overlap",
                evidence.rotation_deadline_within_configured_overlap,
            ),
            (
                "three_same_owner_rotations_completed",
                evidence.rotations_completed_after_drain >= 3
                    && evidence.final_generation
                        == evidence.paused_generation + evidence.rotations_completed_after_drain,
            ),
            (
                "rotation_deadline_was_actually_observed",
                evidence.rotation_attempts_with_observed_deadline > 0,
            ),
            ("relay_count_is_three", evidence.relay_count == 3),
            (
                "physical_residency_accounting_closes",
                evidence.physically_resident_frames == evidence.data_queue_depth_high_water + 1
                    && evidence.physically_resident_frames + evidence.writer_absorbed_frames
                        == evidence.workload_reachable_entries
                    && evidence.data_enqueues_during_blackhole
                        == evidence.workload_reachable_entries as u64,
            ),
            (
                "full_message_queue_bound_remains_unreachable",
                evidence.route_maximum_reachable_entries < evidence.configured_data_queue_capacity,
            ),
            (
                "workload_saturates_the_reachable_bound",
                evidence.workload_reachable_entries == evidence.route_maximum_reachable_entries
                    && evidence.streams_admitted == evidence.configured_max_streams_per_device,
            ),
            (
                "reserved_control_capacity_retained",
                evidence.control_queue_refusals == 0
                    && evidence.control_queue_depth_high_water
                        < evidence.configured_control_queue_capacity,
            ),
            (
                "reserved_data_capacity_retained",
                evidence.reserved_free_data_slots_at_peak
                    >= evidence.configured_max_streams_per_device - 1,
            ),
            (
                // One quarter of the configured budget, which is 32 times the
                // 32 KiB `max_control_bytes` bound.
                "byte_budget_headroom_retained",
                evidence.queue_bytes_headroom_at_peak >= evidence.configured_queue_bytes_limit / 4,
            ),
            (
                "drain_within_bounded_observations",
                evidence.physical_drain_observations > 0
                    && evidence.physical_drain_observations
                        <= evidence.physical_drain_observation_bound,
            ),
            (
                "no_replay_after_drain",
                evidence.dispatch_delta_after_drain == 0,
            ),
            (
                "device_socket_peak_within_bound",
                evidence.device_socket_peak_open <= 3,
            ),
        ],
    )
}

/// The usage text.  Every `verify-*` dispatch arm must appear in its usage
/// list and nothing else may (M4-39); `help_text_lists_every_verify_dispatch_arm`
/// holds the two together.
const HELP_TEXT: &str = "Usage: tunnel-test-harness verify\n       tunnel-test-harness verify-m2\n       tunnel-test-harness verify-m2-default\n       tunnel-test-harness verify-m2-faults\n       tunnel-test-harness verify-m7-transport\n       tunnel-test-harness verify-m7-redis-tls\n       tunnel-test-harness verify-m7-cluster\n       tunnel-test-harness verify-m7-production\n       tunnel-test-harness verify-m7-i08-synthetic-rotation\n       tunnel-test-harness verify-m7-i08-partial-response-rotation\n       tunnel-test-harness verify-m7-i08-goaway-rotation\n       tunnel-test-harness verify-m7-i08-rotation-faults\n       tunnel-test-harness verify-m7-i08-recovery-attempts\n       tunnel-test-harness verify-m7-admission-framing\n       tunnel-test-harness verify-m7-ec041-device-attachment\n       tunnel-test-harness verify-m7-ec023-owner-death\n       tunnel-test-harness verify-m7-ec025-handover\n       tunnel-test-harness verify-m7-admission\n       tunnel-test-harness verify-m7-i04-fail-closed\n       tunnel-test-harness verify-m7-queue-saturation\n       tunnel-test-harness verify-m7-remote-body-limits\n       tunnel-test-harness verify-m7-device-revocation\n       tunnel-test-harness verify-m7-credential-expiry-rotation\n       tunnel-test-harness verify-m7-redis-partition\n       tunnel-test-harness verify-m7-process-pause\n       tunnel-test-harness verify-m7-chaos\n       tunnel-test-harness verify-m7-pressure\n       tunnel-test-harness verify-m7-c11-diagnostics\n       tunnel-test-harness verify-m7-og02-correlation\n       tunnel-test-harness verify-m7-lifecycle\n       tunnel-test-harness verify-m7-side-effect\n       tunnel-test-harness verify-m7-side-effect-late\n       tunnel-test-harness verify-m7-public-abandoned-upgrade\n       tunnel-test-harness verify-m7-owner-loss-effect\n       tunnel-test-harness verify-m7-owner-lease-expiry\n       tunnel-test-harness verify-m7-timing-boundaries\n       tunnel-test-harness verify-m7-peer-fragmentation\n       tunnel-test-harness verify-m7-ec044-peer-frames\n       tunnel-test-harness verify-m7-saturated-peer-frames\n       tunnel-test-harness verify-m7-pending-owner\n       tunnel-test-harness verify-m7-successor-pending-owner\n       tunnel-test-harness verify-m7-concurrent-load\n       tunnel-test-harness verify-m7-key-rotation\n       tunnel-test-harness verify-m7-peer-readiness\n       tunnel-test-harness verify-m7-peer-capacity\n       tunnel-test-harness verify-m7-owner-local-capacity\n       tunnel-test-harness verify-m7-owner-contention\n       tunnel-test-harness verify-m7-trust-expiry\n       tunnel-test-harness verify-m7-resign-stream\n       tunnel-test-harness verify-m7-membership-hint-drop\n       tunnel-test-harness verify-m3-http-forward-real-path\n       tunnel-test-harness verify-m3-http-forward-rotation\n       tunnel-test-harness verify-m3-mcp-cloud-client\n       tunnel-test-harness verify-m3-mcp-isolation\n       tunnel-test-harness verify-m4-fs-real-path\n       tunnel-test-harness verify-m4-fs-write-path\n       tunnel-test-harness verify-m4-fs-rotation\n       tunnel-test-harness verify-m4-fs-rotation-write\n       tunnel-test-harness verify-m4-fs-consumer-loss\n       tunnel-test-harness verify-m4-fs-data-recovery\n       tunnel-test-harness verify-m4-fs-epoch-change\n       tunnel-test-harness verify-m4-fs-process-restart\n       tunnel-test-harness verify-m4-fs-write-restart\n       tunnel-test-harness verify-m4-fs-rename-restart\n       tunnel-test-harness verify-m4-fs-client-e2e\n       tunnel-test-harness verify-m8-acp-real-path\n       tunnel-test-harness verify-m8-acp-cluster\n       tunnel-test-harness redis-restart-{seed|check} --redis-url URL --namespace NAME --receipt-file PATH\n       tunnel-test-harness redis-lane-restart --redis-url URL --namespace NAME --handshake-file PATH\n\nverify, verify-m2, and verify-m7-redis-tls commands require TEST_REDIS_URL and built workspace binaries.\nRuns real Redis, HTTPS, device mTLS WebSocket, CLI and HTTP/3 acceptance checks.\nverify-m2 drives a long-lived public echo WebSocket through accelerated real rotations;\nverify-m2-default repeats the same flow at the 300-second policy.\nverify-m2-faults closes exact control/data/candidate sockets and checks explicit recovery outcomes.\nverify-m7-transport proves bounded peer mTLS/HTTP3 duplex exchange and negative identity cases.\nverify-m7-redis-tls proves the authenticated Redis TLS catalog connection and rejection cases.\nverify-m7-cluster connects three real relay peer listeners through signed membership,\nRedis owner fencing, control/data replacement generations and consumer ingress.\nverify-m7-production exercises the production relay actor, signed Redis directory,\nclient WebSockets and public consumer routing across three relays.\nverify-m7-i08-synthetic-rotation verifies a real CLI and checksummed synthetic Echo records across three same-owner rotations.\nverify-m7-i08-partial-response-rotation drives maximum-size multi-frame synthetic adapter responses\ncontinuously across three same-owner rotations and records what the product actually guarantees for a\npartly delivered response: the received prefix equals the source prefix at every observed consumer byte\ncursor, the reassembled response matches a checksum derived from the source rather than the delivery\npath, no bytes are duplicated, each rotation drains to an exact frame-sequence fence, and the adapter is\nshut down inside a rotation overlap window with a typed post-shutdown outcome.  The resume unit is\nrecorded as frame_sequence because the connector emits a response's frames without yielding and the\nrelay fences on last_emitted, so byte-offset resumption inside a record is not a state the product has.\nverify-m7-i08-recovery-attempts fails every retained-recovery attachment of a real CLI at the opaque\ndevice fanout after the owner attached it: three attempts under one absolute episode deadline end in\nthe typed exhaustion diagnostic, then a second attempt recovers the same session and stream.\nverify-m7-admission exercises public negative admission, route allowlisting,\nforged identity-header rejection and selected-owner failure across three relays.\nverify-m7-i04-fail-closed proves the fail-closed admission, readiness, routing and\nfallback matrix with a request-body sentinel: absent/unknown/inactive/ambiguous and\ncaller-destination targets rejected before any body read or owner selection, a\ncaller-named peer address never reached, an empty body distinguished from a failed\nbody, consumed/unpolled/failed bodies under a real owner process loss with no\nreselection, GET/HEAD/OPTIONS shapes at the lost owner's route typed and never\nreselected, the duplicate service label ambiguous through the stream upgrade too,\none bounded consumer-driven safe retry bridging successor readiness, and the\nexcluded browser route boundary recorded.\nverify-m7-ec041-device-attachment races two real device data attachments through two distinct\nnon-owner ingress relays after a successor owner replaces the complete owner token: a stale\npredecessor ticket and an already-consumed ticket are refused with a transport close and no\nDATA_READY, exactly one concurrent attachment wins, and the losing attachment resets no counter.\nverify-m7-device-revocation proves live Redis device-credential revocation,\nexisting-stream withdrawal, exact no-owner admission, and tenant sibling survival.\nverify-m7-credential-expiry-rotation proves a sixteen-second consumer credential\nexpires inside one exact candidate/old scheduled rotation and refresh challenge\nafter admitted baseline echo, with issuer/audience/subject identity and typed\nterminal checks.\nverify-m7-pressure exercises bounded production resource pressure, cancellation, and recovery.\nverify-m7-lifecycle holds one consumer response path and checks cancellation, sibling survival, and fresh-stream recovery.\nverify-m7-side-effect-late proves owner-side receipt and terminal rejection of one late DATA/FIN pair after a selected peer fault.\nverify-m7-public-abandoned-upgrade proves real owner-local and remote public WebSocket upgrades after admission, no 101 response, exact registration reclamation, capacity rejection, and sibling recovery.\nverify-m7-key-rotation exercises bounded recovery after peer-pin withdrawal during scheduled rotation.\nverify-m7-ec044-peer-frames injects reordered, duplicate and late device frames through a real\nmTLS/HTTP3 ingress-to-owner CompleteDeviceData forward into a live relay actor behind the\nproduction peer ingress handler: the owner's delivered contiguous cursor advances only for\nlegitimately ordered frames, a duplicate adds nothing, and a DATA frame after the terminal FIN\nleaves exactly one stream terminal, a typed INVALID_SEQUENCE close, an owner peer-fault tuple at\nthe forwarded-body stage, and no adapter bytes past the FIN cursor.\nverify-m7-saturated-peer-frames proves the M7-I07/M7-C22 conjunction on one genuinely saturated\nnon-owner-ingress route: the full 64-stream per-device cap is admitted with one 20,000-byte\nin-flight record each and the owner's bounded outbound data channel is held above a quarter of its\nconfigured slots, while a real AUTHORIZATION_INVALIDATED revocation close is delivered on the\ncontrol plane and acted on with the typed GRANT_UNAVAILABLE code and no dispatch, reordered,\nduplicate and post-FIN frames are injected on that same saturated carrier with the delivered\ncontiguous cursor advancing only for legitimate ordering and nothing delivered twice, a planned\npeer HTTP/3 GOAWAY refuses fresh peer streams while a sibling stream admitted before it completes\nits outstanding round trip, and the first stream terminal identity is re-sampled and immutable.\nverify-m7-og02-correlation drives the credential-expiry, trust-expiry, GOAWAY, recovery-attempt,\nlease-expiry, queue-saturation, remote-body-limit, Redis-partition, owner-loss and I04 fail-closed\ngates through the C11 capture scanner and reports per row whether the joined window carries\ncomplete OG-02 correlation and the relay's bounded peer stage/cause tuples. Completeness is\nper row: every row must carry all seven correlation families, and only a row declaring\npeer_fault_required must also carry a typed peer stage/cause tuple.\nlease-expiry, queue-saturation and remote-body-limit gates through the C11 capture scanner and\nreports per row whether the joined window carries complete OG-02 correlation and the relay's\nbounded peer stage/cause tuples; declared-complete rows are enforced.\nverify-m7-peer-readiness exercises authenticated peer path loss and fresh-path readiness recovery.\nverify-m7-owner-contention exercises concurrent CLI claims, terminal rejection and fenced successor cleanup.\nverify-m7-chaos cycles owner kill, peer UDP loss, Redis pause and CLI process pause against three relays for a fixed number of rounds, classifies every close/interruption into the closed diagnostics vocabulary, preserves unknown outcomes, and fails on any unclassified interruption or reconnect rate above the documented threshold.\nverify-m7-trust-expiry exercises signed peer-key expiry without a Redis invalidation hint,\npooled-stream closure, unrelated peer survival, and fresh signed-trust recovery.\nverify-m7-resign-stream keeps one consumer stream through a non-owner ingress across single and back-to-back\nsame-key membership re-signs: the admission is re-bound rather than invalidated, no pin set is ever empty and peer\nreadiness recovers within the bound (M7-C80, M7-C83).\nverify-m7-membership-hint-drop drops the process-local invalidation hint entirely and requires\nconvergence from the bounded membership refresh alone: a stream established during the staged\nkey overlap keeps delivering and is torn down only once the old key leaves the verifier, a\nnon-rotated identity's stream is untouched, and the withdrawn key is refused with a typed\nno-dispatch outcome inside the membership refresh bound.\nverify-m3-http-forward-real-path runs http-forward/1 implementation gate 3: a consumer HTTP request through\nnon-owner ingress, the peer HTTP/3 hop, the owner actor and the device WebSocket to an in-process handler, with\none checksummed 16 MiB echo saturated in both directions while a second exchange is cancelled (RESET, handler\ncancelled) and a third answers promptly, per-hop queue high-water bounds, and header credential/address leakage checks.\nverify-m3-http-forward-rotation runs http-forward/1 implementation gate 4: exchanges carried across real scheduled rotations at\nHEAD, inside a record header, inside a BODY payload, between END and FIN, after an early response, during a credit stall and\nthrough a long-lived SSE response; a control CANCEL raced with a RESET queued behind a held freeze; and outcome_unknown without\nretry after lost acknowledgements and owner loss following a synthetic side effect.\nverify-m3-mcp-cloud-client runs M3-03: the official rmcp client through non-owner ingress, the peer hop and the rotating tunnel\nto tunnel-client MCP exports (stdio and Streamable HTTP, mcp-2026-07-28 and mcp-2025-11-25) backed by the synthetic fixture:\ndiscovery and exact invocation, progress and log notifications, cancellation, backend crash, rotation during discovery and\ninvocation, and a byte-exact stream across three rotations with one dispatch.\nverify-m3-mcp-isolation runs M3-04: two distinct authenticated principals of one tenant drive raw MCP HTTP through\nnon-owner ingress and the rotating tunnel to the device's stdio exports and to a Streamable HTTP export backed by one\nshared synthetic server, and a fourth principal authorized only in another tenant drives the same device.  One principal's 2025-11-25 session ID is refused for\nthe other on POST, GET and DELETE with exactly an unknown session's answer, and no notification crosses between them;\nmany concurrent calls with deliberately colliding JSON-RPC IDs and progress tokens, reused across sessions and\nprincipals, are each answered to their own caller with exact results while a genuine duplicate on one session is\nrefused; the Streamable HTTP export, where one backend process and one session table serve every principal, refuses a\nforeign principal's session ID on all three routes, which separates the principal binding from the stdio export's\nper-session child; a consumer authorized in another tenant is refused before dispatch on every route, indistinguishably\nfrom one naming a session that never existed; a third principal's grant is revoked mid-call and mid-session and fails\nclosed with the recorded blast radius; one call spans three completed scheduled rotations exactly once; and a lost acknowledgement and owner process\nloss after a synthetic side effect each give the consumer an explicit unknown outcome with the side effect run once\nand nothing replayed.\nverify-m8-acp-real-path runs ACP over the three-relay production cluster with the device owned by relay-a and the\nconsumer entering at relay-c: an HTTP/2 initialize, the connection GET, a session whose identifier arrives on that\nstream, a session GET carrying no Acp-Session-Id (M8-C05), a prompt answered 202 whose stopReason is read off the\nwire, and permission allow and reject whose outcomes are read from the marker the agent itself wrote, with a\nresponse naming an unoffered option, one answering nothing outstanding and one on the wrong connection each\nrefused.  Membership is re-signed only at case boundaries and at most every 15 s: that is a harness accommodation\nfor M7-C80, not a claim that an ACP connection survives a membership re-sign.  Every not_dispatched refusal is\ncorrelated to an observed rotation freeze and an uncorrelated one fails the run by name (M3-15).\nverify-m8-acp-cluster runs M8 chunk 5: ACP across three relays with the device owned by relay-a and the consumer\nentering at relay-c.  Two sessions on one connection are carried across three completed scheduled device\ndata-socket rotations with a prompt, a permission callback and a pending response spanning each drain: the callback\narrives exactly once, an update arrives before and after, each held turn's side effect is counted once in the\nagent's own append-only ledger, the device holds two sockets at every settled steady state and never more than\nthree, and the device session and owner epoch are unchanged, so these are rotations and not a reconnect.  A\nscheduled rotation and a membership re-sign are different mechanisms and only the second is M7-C80, which is why\nthis is provable at all; membership is not re-signed while the streams are live, and because a peer admission's\ndeadline is never extended the case is bounded to finish inside one membership record rather than escaping that\nlimit.  Two users in two tenants then reuse identical JSON-RPC ids in both types and identical session ids on two\ndevices with two owners, each reply routed to its own caller; another principal of the same tenant, and a\nprincipal of the other tenant, are each refused a live connection id byte-identically to an id that never\nexisted, and a live connection id is inert in the other tenant's context.  A forged tunnel-principal-binding, a\nforged x-agent-tunnel-* header and a forged internal identity header are each refused before a byte reaches the\ndevice.  Both forwarding segments are driven over half their peer credit window at the same time with a live SSE\nstream still served.  A revoked grant withdraws the admitted exchange with execution unknown and dispatches\nnothing afterwards, and peer-key rotation and owner loss each produce an explicit interruption and never a\nfabricated stopReason.  It does not claim per-OS process-tree cleanup, any OS sandbox guarantee, or real-agent\ninteroperability: macOS is the only host and the agent is this repository's own synthetic fixture.\nverify-m4-fs-real-path runs the filesystem endpoint's implementation gate 4 against the production cluster:\nan authenticated HTTPS descriptor read on a read+list grant that carries no host path and no host identity field;\nthe refusal matrix before any 9P byte (403 for an empty grant and for an unsupported host, 401, 404, 405, a 409 on a\nstale grant revision and a 426 on an upgrade offering no agent-tunnel.9p.v1 subprotocol); a real WSS upgrade at the\nowning relay with the subprotocol selected, 9P2000.L and an msize negotiated and a directory qid attached; a forged\nTattach — a non-empty uname, and separately a non-NOFID afid — refused with a 1002 close and no Rattach; a checksummed\nread of a 393,216-byte synthetic file spanning more than four Rread messages; a forty-entry directory paged by opaque\ncookie over more than four pages with every name exactly once; the capability matrix on their own exports, list without\nread (stat succeeds with the real size, opening a file for reading is EPERM) and read without list (reading by name\nsucceeds, stat and enumerating a directory are EPERM); a pipelined Tread and Tflush whose Rflush arrives with no reply\nafter it and a surviving session; a fid-generation collision where a re-bound fid refuses a read against the previous\nbinding and then serves the new one; a relay that does not own the device answering 503 BACKEND_UNAVAILABLE; and every\nmutation refused with the host file unchanged.
verify-m4-fs-write-path runs the filesystem endpoint's implementation gate 5 against the production
cluster: a writable grant whose descriptor derives root.readOnly false; a checksummed 393,216-byte
synthetic file created and written across more than four maximum-size Twrite messages and read back
byte for byte on a fresh fid at exactly the length sent; Tlcreate, Tmkdir, Trenameat, Tunlinkat with
and without AT_REMOVEDIR, a truncating open and a size-changing Tsetattr, each observed on the host;
a read+list grant refusing all eleven mutating primitives and mutating flags before dispatch with the
export byte-for-byte unchanged; the hard-link write rule on a genuinely multiply-linked file, where a
write, a read-write and a truncating open and a size-changing Tsetattr are each EPERM with the content
verified intact and an ordinary read still served; a write interrupted mid-stream by abandoning the
consumer transport with writes outstanding, after which every acknowledged byte is present and
correct, the file is a prefix of the source so nothing was applied twice, the host holds no more than
was sent, and nothing is re-sent; and a host permission failure surfacing EACCES with no name and a
surviving session.
verify-m4-fs-client-e2e runs the filesystem endpoint's implementation gate 6 against the production
cluster, driving the real @agent-tunnel/client from packages/client under node as a child process:
TLS verified against the fixture CA through NODE_EXTRA_CA_CERTS with the client's own loopback
opt-in never passed; the descriptor fetched and validated by the client's own schema rules; a grant
revision moved in the authoritative catalog between the client's descriptor read and its upgrade, so
the upgrade carrying the revision it read is refused 409 CAPABILITIES_CHANGED and the grantRevision
header is observed to be sent; an unsigned token refused UNAUTHENTICATED; twenty-four writes
dispatched and unanswered, every one classified unknown and none retryable, with the device's own
ConnectionStatus::fs ledger read beside them as a delta from zero and the host file checked to hold
exactly what that ledger says was written; a checksummed 393,216-byte read spanning more than four
Rread messages and a checksummed 393,216-byte write spanning more than four Twrite messages verified
on the host; a forty-entry directory listed with every name exactly once; a read-only grant refusing
mutations at both layers — locally as unadvertised operations, and on the device through the raw
session a custom 9P client would use — with the export unchanged; and the Mastra adapter driven end
to end over the same sockets.\nUses isolated Redis namespaces, ephemeral certificates and synthetic echo data.\nRun restart probes through scripts/m1-redis-restart-verify.sh.\nRun the live-catalog Redis process restart through scripts/m7-redis-lane-restart-verify.sh;\nredis-lane-restart keeps one catalog alive across a restart the script performs and requires\nthe typed run-identifier conflict on every command afterwards.\nSet M2_HARNESS_TIMEOUT_SECONDS to override a bounded M2 command timeout.";

fn print_help() {
    println!("{HELP_TEXT}");
}

fn m2_outer_timeout(default: Duration, minimum: Duration) -> Result<Duration, HarnessError> {
    let Some(value) = std::env::var("M2_HARNESS_TIMEOUT_SECONDS")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(default);
    };
    let seconds = value.parse::<u64>().map_err(|_| {
        HarnessError::InvalidInput(
            "M2_HARNESS_TIMEOUT_SECONDS must be an integer between the mode minimum and 3600"
                .to_owned(),
        )
    })?;
    if !(minimum.as_secs()..=3_600).contains(&seconds) {
        return Err(HarnessError::InvalidInput(format!(
            "M2_HARNESS_TIMEOUT_SECONDS must be between {} and 3600 seconds for this mode",
            minimum.as_secs()
        )));
    }
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M4-39: the usage list and the dispatch arms are one set.  Before this,
    /// the help named three of the eleven `verify-m4-fs-*` gates and not
    /// `verify-m7-owner-lease-expiry`, and nothing noticed because nothing
    /// compared them.  The arms are read from this file's own source, so a
    /// new arm without a usage line, or a usage line for a removed arm, fails.
    #[test]
    fn help_text_lists_every_verify_dispatch_arm() {
        let source = include_str!("main.rs");
        let arms: std::collections::BTreeSet<&str> = source
            .split("command == \"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .filter(|command| command.starts_with("verify"))
            .collect();
        let listed: std::collections::BTreeSet<&str> = HELP_TEXT
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                line.strip_prefix("Usage: ")
                    .unwrap_or(line)
                    .strip_prefix("tunnel-test-harness ")
            })
            .filter_map(|rest| rest.split_whitespace().next())
            .filter(|command| command.starts_with("verify"))
            .collect();
        // Anti-vacuity floor: 66 `verify*` arms existed when this landed, so a
        // scan that stopped matching the dispatch cannot pass as an empty set.
        assert!(
            arms.len() >= 60,
            "found only {} verify arms; the dispatch shape changed and this test is not comparing anything",
            arms.len()
        );
        let unlisted: Vec<&&str> = arms.difference(&listed).collect();
        let undispatched: Vec<&&str> = listed.difference(&arms).collect();
        assert!(
            unlisted.is_empty() && undispatched.is_empty(),
            "help usage and dispatch disagree: dispatched but not listed {unlisted:?}; listed but not dispatched {undispatched:?}"
        );
    }

    /// M4-39's second defect: a `\n` that lost its backslash welded an `n` to
    /// the front of `verify-m4-fs-real-path`'s paragraph.  Every descriptive
    /// paragraph naming a gate must start with the gate's own name.
    #[test]
    fn help_text_has_no_welded_line() {
        for line in HELP_TEXT.lines() {
            assert!(
                !line.starts_with("nverify"),
                "a help line starts with a welded `n`: {line:?}"
            );
        }
        assert!(
            HELP_TEXT
                .lines()
                .any(|line| line.starts_with("verify-m4-fs-real-path runs")),
            "verify-m4-fs-real-path's paragraph must start on its own line"
        );
    }

    const CREDENTIAL_SENTINEL: &str = "fixture-secret-token";
    const MAX_ACCEPTANCE_DIAGNOSTIC_BYTES: usize = 4 * 1024;
    const REQUIRED_FALSE_FLAGS: &[(&str, bool)] = &[
        ("response_before_request_end", false),
        ("wrong_pin_rejected", false),
        ("authenticated_catalog_connection", false),
        ("pause_fail_closed", false),
        ("partition_admission_rejected", false),
        ("sibling_canary", false),
    ];

    fn transport_evidence() -> cluster_transport::ClusterTransportEvidence {
        cluster_transport::ClusterTransportEvidence {
            response_status: 200,
            response_body: CREDENTIAL_SENTINEL.as_bytes().to_vec(),
            response_before_request_end: true,
            body_before_request_end: true,
            wrong_pin_rejected: true,
            wrong_role_rejected: true,
            oversized_chunk_rejected: true,
            client_shutdown_joined: true,
            server_shutdown_joined: true,
            response_head_truncation_rejected: true,
            response_body_truncation_rejected: true,
            idle_blackhole_closed: true,
            saturated_lane_cancellation_bounded: true,
            active_stream_pin_revocation_closed: true,
            shared_stream_isolated: true,
            body_budget_reclamation_verified: true,
            udp_blackhole_restored: true,
            no_tcp_fallback: true,
            zero_rtt_not_admitted: true,
        }
    }

    fn redis_tls_evidence() -> redis_tls::RedisTlsEvidence {
        redis_tls::RedisTlsEvidence {
            authenticated_catalog_connection: true,
            wrong_ca_rejected: true,
            wrong_server_name_rejected: true,
            wrong_client_identity_rejected: true,
        }
    }

    fn process_pause_evidence() -> tunnel_test_harness::production_cluster::ProcessPauseEvidence {
        tunnel_test_harness::production_cluster::ProcessPauseEvidence {
            relay_count: 3,
            cli_control_data_sockets: true,
            paused_pid_validated: true,
            pause_fail_closed: true,
            relay_dispatch_counter_unchanged: true,
            resumed_and_joined: true,
            recovery_owner_verified: true,
            recovery_echo: true,
            stale_payload_not_replayed: true,
            fanout_peak_open: 3,
            pause_elapsed_ms: 1,
        }
    }

    fn owner_lease_expiry_evidence()
    -> tunnel_test_harness::production_cluster::OwnerLeaseExpiryEvidence {
        const SEEDED: u64 = 1_u64 << 53;
        tunnel_test_harness::production_cluster::OwnerLeaseExpiryEvidence {
            relay_count: 3,
            seeded_epoch: SEEDED,
            original_epoch: SEEDED + 1,
            catalog_generation_preserved: true,
            baseline_echo: true,
            paused_redis_connections: 4,
            owner_present_after_barrier: true,
            owner_expired_while_partitioned: true,
            owner_absent_after_lease_deadline: true,
            lease_expiry_elapsed_ms: 29_800,
            lease_deadline_margin_ms: 120,
            expired_owner_dispatch_unchanged: true,
            stale_release_refused_after_expiry: true,
            successor_scope_matched: true,
            successor_epoch: SEEDED + 2,
            successor_fresh_session: true,
            stale_release_refused_after_successor: true,
            successor_token_unchanged: true,
            successor_echo: true,
            fanout_peak_open: 2,
            elapsed_ms: 90_000,
        }
    }

    fn redis_partition_evidence() -> tunnel_test_harness::production_cluster::RedisPartitionEvidence
    {
        tunnel_test_harness::production_cluster::RedisPartitionEvidence {
            relay_count: 3,
            baseline_echo: true,
            partition_admission_rejected: true,
            partition_dispatch_interrupted: true,
            paused_redis_connections: 1,
            recovery_owner_verified: true,
            recovery_echo: true,
            public_livez_ok_during_partition: true,
            public_readyz_unready_during_partition: true,
            public_readyz_ok_after_recovery: true,
            partition_elapsed_ms: 1,
        }
    }

    fn pressure_evidence() -> tunnel_test_harness::production_cluster::PressureEvidence {
        tunnel_test_harness::production_cluster::PressureEvidence {
            relay_count: 3,
            baseline_echo: true,
            bulk_attempted: true,
            bulk_records_attempted: 1,
            bounded_backpressure: true,
            queue_budget_observed: true,
            sibling_canary: true,
            cancellation_responsive: true,
            cancellation_not_replayed: true,
            recovery_owner_verified: true,
            recovery_echo: true,
            fanout_peak_open: 3,
            elapsed_ms: 1,
        }
    }

    fn continuous_traffic_evidence() -> m2_acceptance::ContinuousTrafficEvidence {
        m2_acceptance::ContinuousTrafficEvidence {
            rotations_required: 3,
            rotations_observed: 3,
            records_round_tripped: 900,
            records_during_freeze: 12,
            records_during_held_freeze: 1,
            handover_phases_observed: [
                "quiescing".to_owned(),
                "draining".to_owned(),
                "committing".to_owned(),
                "retiring".to_owned(),
            ]
            .into_iter()
            .collect(),
            relay_emitted_delta: 900,
            relay_received_delta: 900,
            relay_last_emitted: 920,
            relay_peer_acked: 920,
            relay_recv_contiguous: 920,
            relay_delivered_contiguous: 920,
            client_emitted_sequences: 920,
            client_received_sequences: 920,
            total_replayed_frames: 0,
            connector_terminal_phase_observed: false,
            stray_response_observed: false,
        }
    }

    fn queue_saturation_evidence()
    -> tunnel_test_harness::production_cluster::QueueSaturationEvidence {
        tunnel_test_harness::production_cluster::QueueSaturationEvidence {
            relay_count: 3,
            membership_ready_relays: 3,
            non_owner_ingress: true,
            configured_queue_bytes_limit: 4 * 1024 * 1024,
            configured_control_reserved_bytes: 4 * 32 * 1024,
            configured_data_bytes_limit: 4 * 1024 * 1024 - 4 * 32 * 1024,
            configured_data_queue_capacity: 128,
            configured_control_queue_capacity: 128,
            configured_max_streams_per_device: 64,
            workload_record_bytes: 20_000,
            workload_charge_per_record_bytes: 40_072,
            workload_frames_per_record: 1,
            workload_streams: 64,
            workload_records_per_stream_by_credit: 6,
            workload_reachable_entries: 64,
            route_maximum_reachable_entries: 64,
            streams_admitted: 64,
            stream_cap_refused_one_more: true,
            data_queue_depth_observed: 43,
            data_queue_depth_high_water: 43,
            data_enqueues_during_blackhole: 64,
            physically_resident_frames: 44,
            writer_absorbed_frames: 20,
            writer_absorbed_wire_bytes: 20 * 20_068,
            reachable_bound_saturated: true,
            reserved_free_data_slots_at_peak: 85,
            reserved_data_slot_accepted_at_peak: true,
            queue_bytes_high_water: 43 * 40_072,
            data_bytes_high_water: 43 * 40_072,
            control_bytes_available_at_data_peak: 4 * 1024 * 1024 - 43 * 40_072,
            queue_bytes_headroom_at_peak: 4 * 1024 * 1024 - 2_564_608,
            control_queue_depth_at_peak: 1,
            control_queue_depth_high_water: 4,
            control_queue_refusals: 0,
            control_enqueues_during_blackhole: 3,
            cancellation_accepted_after_resume: true,
            fresh_stream_admitted_after_cancellation: true,
            sibling_stream_survived: true,
            first_terminal_observation_immutable: true,
            terminal_observations: 8,
            terminal_tombstone_observations: 1,
            paused_target_to_client: 1,
            paused_connection_correlated: true,
            paused_generation: 1,
            physical_drain_observations: 9,
            physical_drain_observation_bound: 200,
            physical_drain_completed: true,
            rotation_replaced_paused_carrier: true,
            rotation_committed_generation: 2,
            rotations_completed_after_drain: 3,
            final_generation: 4,
            rotation_attempts_with_observed_deadline: 3,
            rotation_deadline_never_extended: true,
            rotation_deadline_within_configured_overlap: true,
            device_socket_peak_open: 3,
            device_send_buffer_bytes: 98_304,
            dispatch_delta_after_drain: 0,
            elapsed_ms: 12_345,
        }
    }

    fn assert_rejected(result: Result<(), HarnessError>, expected_name: &str) {
        let message = result
            .as_ref()
            .expect_err("incomplete evidence unexpectedly passed")
            .to_string();
        assert_eq!(
            command_exit_code(&result),
            ExitCode::FAILURE,
            "a failed mandatory gate must reach the nonzero CLI exit path"
        );
        assert!(
            message.len() <= MAX_ACCEPTANCE_DIAGNOSTIC_BYTES,
            "mandatory-gate diagnostic exceeded bounded size: {} bytes",
            message.len()
        );
        assert!(
            message.contains(expected_name),
            "{expected_name} missing from diagnostic: {message}"
        );
        assert!(!message.contains(CREDENTIAL_SENTINEL));
        assert!(!message.contains("private-key-pem"));
        assert!(!message.contains("bearer-token"));
    }

    #[test]
    fn required_false_flags_reach_main_nonzero_exit_path() {
        let result = require_m7_acceptance_flags("M7 false-flag regression", REQUIRED_FALSE_FLAGS);
        let message = result
            .as_ref()
            .expect_err("false required flags unexpectedly passed")
            .to_string();
        assert_eq!(command_exit_code(&result), ExitCode::FAILURE);
        assert!(message.len() <= MAX_ACCEPTANCE_DIAGNOSTIC_BYTES);
        for &(name, _) in REQUIRED_FALSE_FLAGS {
            assert!(
                message.contains(name),
                "missing failed flag {name}: {message}"
            );
        }
        assert!(!message.contains(CREDENTIAL_SENTINEL));
        assert!(!message.contains("private-key-pem"));
        assert!(!message.contains("bearer-token"));
    }

    /// Task row M6-C96: the fault stage's pass line is printed only for
    /// evidence that every stage ran; each missing or skipped part refuses.
    #[test]
    fn m2_fault_gate_requires_every_stage() {
        let complete = m2_acceptance::M2FaultEvidence {
            stages: m2_acceptance::M2_FAULT_STAGES.to_vec(),
            faults_injected: 5,
            sessions_recovered: 2,
            sessions_ended: 3,
            revocation_outcome_ms: 1_200,
            consumer_rejections: 4,
        };
        assert!(m2_acceptance::require_m2_fault_evidence(&complete).is_ok());
        assert!(
            m2_acceptance::require_m2_fault_evidence(&m2_acceptance::M2FaultEvidence::default())
                .is_err()
        );
        for skipped in 0..m2_acceptance::M2_FAULT_STAGES.len() {
            let mut evidence = complete.clone();
            evidence.stages.remove(skipped);
            assert!(
                m2_acceptance::require_m2_fault_evidence(&evidence).is_err(),
                "stage {skipped} skipped"
            );
        }
        let mut reordered = complete.clone();
        reordered.stages.swap(0, 1);
        assert!(m2_acceptance::require_m2_fault_evidence(&reordered).is_err());
        for mutate in [
            |evidence: &mut m2_acceptance::M2FaultEvidence| evidence.faults_injected = 4,
            |evidence: &mut m2_acceptance::M2FaultEvidence| evidence.sessions_recovered = 1,
            |evidence: &mut m2_acceptance::M2FaultEvidence| evidence.sessions_ended = 2,
            |evidence: &mut m2_acceptance::M2FaultEvidence| evidence.consumer_rejections = 3,
        ] {
            let mut evidence = complete.clone();
            mutate(&mut evidence);
            assert!(m2_acceptance::require_m2_fault_evidence(&evidence).is_err());
        }
    }

    #[test]
    fn m2_continuous_traffic_gate_requires_each_flag_and_bound() {
        assert!(
            m2_acceptance::require_m2_continuous_traffic_evidence(&continuous_traffic_evidence())
                .is_ok()
        );
        macro_rules! assert_traffic_mutation {
            ($field:ident = $value:expr, $flag:expr) => {{
                let mut evidence = continuous_traffic_evidence();
                evidence.$field = $value;
                assert_rejected(
                    m2_acceptance::require_m2_continuous_traffic_evidence(&evidence),
                    $flag,
                );
            }};
        }

        assert_traffic_mutation!(
            rotations_observed = 2,
            "rotations_observed_at_least_required"
        );
        assert_traffic_mutation!(
            rotations_required = 0,
            "rotations_observed_at_least_required"
        );
        assert_traffic_mutation!(records_round_tripped = 0, "records_round_tripped_nonzero");
        assert_traffic_mutation!(records_during_freeze = 0, "records_during_freeze_nonzero");
        assert_traffic_mutation!(relay_emitted_delta = 899, "relay_emitted_contiguous");
        assert_traffic_mutation!(relay_emitted_delta = 901, "relay_emitted_contiguous");
        assert_traffic_mutation!(relay_received_delta = 899, "relay_received_contiguous");
        assert_traffic_mutation!(relay_received_delta = 901, "relay_received_contiguous");
        assert_traffic_mutation!(
            relay_peer_acked = 919,
            "relay_peer_acked_reaches_last_emitted"
        );
        assert_traffic_mutation!(
            relay_delivered_contiguous = 919,
            "relay_delivered_reaches_received"
        );
        assert_traffic_mutation!(
            client_received_sequences = 919,
            "client_relay_cursors_agree"
        );
        assert_traffic_mutation!(client_emitted_sequences = 921, "client_relay_cursors_agree");
        assert_traffic_mutation!(total_replayed_frames = 1, "no_replayed_frames");
        assert_traffic_mutation!(
            connector_terminal_phase_observed = true,
            "connector_never_terminal"
        );
        assert_traffic_mutation!(stray_response_observed = true, "no_stray_response");
    }

    #[test]
    fn complete_acceptance_evidence_passes_all_gates() {
        assert!(require_m7_transport_evidence(&transport_evidence()).is_ok());
        assert!(require_m7_redis_tls_evidence(&redis_tls_evidence()).is_ok());
        assert!(require_m7_process_pause_evidence(&process_pause_evidence()).is_ok());
        assert!(require_m7_redis_partition_evidence(&redis_partition_evidence()).is_ok());
        assert!(require_m7_pressure_evidence(&pressure_evidence()).is_ok());
        assert!(require_m7_queue_saturation_evidence(&queue_saturation_evidence()).is_ok());
    }

    #[test]
    fn every_transport_flag_is_required_without_payload_diagnostics() {
        macro_rules! assert_transport_flag {
            ($field:ident) => {{
                let mut evidence = transport_evidence();
                evidence.$field = false;
                assert_rejected(require_m7_transport_evidence(&evidence), stringify!($field));
            }};
        }

        assert_transport_flag!(response_before_request_end);
        assert_transport_flag!(body_before_request_end);
        assert_transport_flag!(wrong_pin_rejected);
        assert_transport_flag!(wrong_role_rejected);
        assert_transport_flag!(oversized_chunk_rejected);
        assert_transport_flag!(client_shutdown_joined);
        assert_transport_flag!(server_shutdown_joined);
        assert_transport_flag!(response_head_truncation_rejected);
        assert_transport_flag!(response_body_truncation_rejected);
        assert_transport_flag!(idle_blackhole_closed);
        assert_transport_flag!(saturated_lane_cancellation_bounded);
        assert_transport_flag!(active_stream_pin_revocation_closed);
        assert_transport_flag!(shared_stream_isolated);
        assert_transport_flag!(body_budget_reclamation_verified);
        assert_transport_flag!(udp_blackhole_restored);
        assert_transport_flag!(no_tcp_fallback);
        assert_transport_flag!(zero_rtt_not_admitted);
    }

    #[test]
    fn every_redis_tls_flag_is_required_without_payload_diagnostics() {
        macro_rules! assert_redis_tls_flag {
            ($field:ident) => {{
                let mut evidence = redis_tls_evidence();
                evidence.$field = false;
                assert_rejected(require_m7_redis_tls_evidence(&evidence), stringify!($field));
            }};
        }

        assert_redis_tls_flag!(authenticated_catalog_connection);
        assert_redis_tls_flag!(wrong_ca_rejected);
        assert_redis_tls_flag!(wrong_server_name_rejected);
        assert_redis_tls_flag!(wrong_client_identity_rejected);
    }

    #[test]
    fn process_pause_gate_requires_each_flag_and_bound() {
        macro_rules! assert_process_pause_flag {
            ($field:ident) => {{
                let mut evidence = process_pause_evidence();
                evidence.$field = false;
                assert_rejected(
                    require_m7_process_pause_evidence(&evidence),
                    stringify!($field),
                );
            }};
        }

        assert_process_pause_flag!(cli_control_data_sockets);
        assert_process_pause_flag!(paused_pid_validated);
        assert_process_pause_flag!(pause_fail_closed);
        assert_process_pause_flag!(relay_dispatch_counter_unchanged);
        assert_process_pause_flag!(resumed_and_joined);
        assert_process_pause_flag!(recovery_owner_verified);
        assert_process_pause_flag!(recovery_echo);
        assert_process_pause_flag!(stale_payload_not_replayed);

        let mut wrong_relay_count = process_pause_evidence();
        wrong_relay_count.relay_count = 2;
        assert_rejected(
            require_m7_process_pause_evidence(&wrong_relay_count),
            "relay_count_is_three",
        );
        let mut excessive_fanout = process_pause_evidence();
        excessive_fanout.fanout_peak_open = 4;
        assert_rejected(
            require_m7_process_pause_evidence(&excessive_fanout),
            "fanout_peak_open_within_bound",
        );
    }

    #[test]
    fn owner_lease_expiry_gate_requires_each_flag_and_bound() {
        macro_rules! assert_lease_flag {
            ($field:ident) => {{
                let mut evidence = owner_lease_expiry_evidence();
                evidence.$field = false;
                assert_rejected(
                    require_m7_owner_lease_expiry_evidence(&evidence),
                    stringify!($field),
                );
            }};
        }

        assert_lease_flag!(catalog_generation_preserved);
        assert_lease_flag!(baseline_echo);
        assert_lease_flag!(owner_present_after_barrier);
        assert_lease_flag!(owner_expired_while_partitioned);
        assert_lease_flag!(owner_absent_after_lease_deadline);
        assert_lease_flag!(expired_owner_dispatch_unchanged);
        assert_lease_flag!(stale_release_refused_after_expiry);
        assert_lease_flag!(successor_scope_matched);
        assert_lease_flag!(successor_fresh_session);
        assert_lease_flag!(stale_release_refused_after_successor);
        assert_lease_flag!(successor_token_unchanged);
        assert_lease_flag!(successor_echo);

        let mut wrong_relay_count = owner_lease_expiry_evidence();
        wrong_relay_count.relay_count = 2;
        assert_rejected(
            require_m7_owner_lease_expiry_evidence(&wrong_relay_count),
            "three relays",
        );
        let mut no_paused_sockets = owner_lease_expiry_evidence();
        no_paused_sockets.paused_redis_connections = 0;
        assert_rejected(
            require_m7_owner_lease_expiry_evidence(&no_paused_sockets),
            "paused no Redis connections",
        );
        let mut reset_epoch = owner_lease_expiry_evidence();
        reset_epoch.successor_epoch = reset_epoch.original_epoch;
        assert_rejected(
            require_m7_owner_lease_expiry_evidence(&reset_epoch),
            "predecessor epoch",
        );
        let mut unretained_epoch = owner_lease_expiry_evidence();
        unretained_epoch.original_epoch = unretained_epoch.seeded_epoch;
        assert_rejected(
            require_m7_owner_lease_expiry_evidence(&unretained_epoch),
            "retained seed",
        );
        let mut early_expiry = owner_lease_expiry_evidence();
        early_expiry.lease_expiry_elapsed_ms = 9_999;
        assert_rejected(
            require_m7_owner_lease_expiry_evidence(&early_expiry),
            "before one renewal tick",
        );
        let mut excessive_fanout = owner_lease_expiry_evidence();
        excessive_fanout.fanout_peak_open = 4;
        assert_rejected(
            require_m7_owner_lease_expiry_evidence(&excessive_fanout),
            "three-socket peak",
        );
    }

    #[test]
    fn redis_partition_gate_requires_each_flag_and_bound() {
        macro_rules! assert_partition_flag {
            ($field:ident) => {{
                let mut evidence = redis_partition_evidence();
                evidence.$field = false;
                assert_rejected(
                    require_m7_redis_partition_evidence(&evidence),
                    stringify!($field),
                );
            }};
        }

        assert_partition_flag!(baseline_echo);
        assert_partition_flag!(partition_admission_rejected);
        assert_partition_flag!(partition_dispatch_interrupted);
        assert_partition_flag!(public_livez_ok_during_partition);
        assert_partition_flag!(public_readyz_unready_during_partition);
        assert_partition_flag!(public_readyz_ok_after_recovery);
        assert_partition_flag!(recovery_owner_verified);
        assert_partition_flag!(recovery_echo);

        let mut wrong_relay_count = redis_partition_evidence();
        wrong_relay_count.relay_count = 2;
        assert_rejected(
            require_m7_redis_partition_evidence(&wrong_relay_count),
            "relay_count_is_three",
        );
        let mut no_paused_connections = redis_partition_evidence();
        no_paused_connections.paused_redis_connections = 0;
        assert_rejected(
            require_m7_redis_partition_evidence(&no_paused_connections),
            "paused_redis_connections_nonzero",
        );
    }

    #[test]
    fn queue_saturation_gate_requires_each_flag_and_bound() {
        assert!(require_m7_queue_saturation_evidence(&queue_saturation_evidence()).is_ok());

        macro_rules! assert_saturation_flag {
            ($field:ident) => {{
                let mut evidence = queue_saturation_evidence();
                evidence.$field = false;
                assert_rejected(
                    require_m7_queue_saturation_evidence(&evidence),
                    stringify!($field),
                );
            }};
        }

        assert_saturation_flag!(non_owner_ingress);
        assert_saturation_flag!(stream_cap_refused_one_more);
        assert_saturation_flag!(reachable_bound_saturated);
        assert_saturation_flag!(reserved_data_slot_accepted_at_peak);
        assert_saturation_flag!(cancellation_accepted_after_resume);
        assert_saturation_flag!(fresh_stream_admitted_after_cancellation);
        assert_saturation_flag!(sibling_stream_survived);
        assert_saturation_flag!(first_terminal_observation_immutable);
        assert_saturation_flag!(paused_connection_correlated);
        assert_saturation_flag!(physical_drain_completed);
        assert_saturation_flag!(rotation_replaced_paused_carrier);
        assert_saturation_flag!(rotation_deadline_never_extended);
        assert_saturation_flag!(rotation_deadline_within_configured_overlap);

        type Mutate = fn(&mut tunnel_test_harness::production_cluster::QueueSaturationEvidence);
        let bounds: [Mutate; 25] = [
            // Reserved control bytes at the data-byte peak (M7-C49): no
            // reservation, a data-lane peak that consumed the reservation, and
            // a derived control capacity that does not follow from the bounds.
            |e| e.configured_control_reserved_bytes = 0,
            |e| {
                e.data_bytes_high_water = 4 * 1024 * 1024 - 4 * 32 * 1024 + 1;
                e.queue_bytes_high_water = e.data_bytes_high_water;
                e.control_bytes_available_at_data_peak = 4 * 32 * 1024 - 1;
            },
            |e| e.control_bytes_available_at_data_peak += 1,
            // A logical admission count must never satisfy the physical floor.
            |e| {
                e.data_queue_depth_observed = 1;
                e.data_queue_depth_high_water = 1;
                e.physically_resident_frames = 2;
                e.writer_absorbed_frames = 62;
                e.writer_absorbed_wire_bytes = 62 * 20_068;
            },
            // Residency that does not account for the writer-held frame.
            |e| e.physically_resident_frames = 43,
            // Fewer in-flight records admitted than the configured bound.
            |e| e.data_enqueues_during_blackhole = 32,
            // Absorption accounting that does not close.
            |e| e.writer_absorbed_frames = 1,
            // Control starvation, by refusal and by a filled control channel.
            |e| e.control_queue_refusals = 1,
            |e| e.control_enqueues_during_blackhole = 0,
            |e| e.control_queue_depth_high_water = 128,
            // No reserved free data slot.
            |e| e.reserved_free_data_slots_at_peak = 1,
            |e| e.queue_bytes_headroom_at_peak = 1,
            // A route on which the full channel bound would be reachable must
            // reopen the gate rather than keep asserting the smaller bound.
            |e| e.route_maximum_reachable_entries = 128,
            // A workload that does not saturate the reachable bound.
            |e| {
                e.workload_reachable_entries = 32;
                e.route_maximum_reachable_entries = 32;
            },
            |e| e.streams_admitted = 16,
            |e| e.relay_count = 2,
            |e| e.physical_drain_observations = 201,
            |e| e.dispatch_delta_after_drain = 1,
            |e| e.device_socket_peak_open = 4,
            |e| e.device_send_buffer_bytes = 0,
            |e| e.device_send_buffer_bytes = 16_384,
            |e| e.device_send_buffer_bytes = 131_072,
            |e| e.rotations_completed_after_drain = 2,
            |e| e.final_generation = 2,
            |e| e.rotation_attempts_with_observed_deadline = 0,
        ];
        for mutate in bounds {
            let mut evidence = queue_saturation_evidence();
            mutate(&mut evidence);
            assert_rejected(
                require_m7_queue_saturation_evidence(&evidence),
                "queue saturation",
            );
        }
    }

    #[test]
    fn pressure_gate_requires_each_flag_and_bound() {
        macro_rules! assert_pressure_flag {
            ($field:ident) => {{
                let mut evidence = pressure_evidence();
                evidence.$field = false;
                assert_rejected(require_m7_pressure_evidence(&evidence), stringify!($field));
            }};
        }

        assert_pressure_flag!(baseline_echo);
        assert_pressure_flag!(bulk_attempted);
        assert_pressure_flag!(bounded_backpressure);
        assert_pressure_flag!(queue_budget_observed);
        assert_pressure_flag!(sibling_canary);
        assert_pressure_flag!(cancellation_responsive);
        assert_pressure_flag!(cancellation_not_replayed);
        assert_pressure_flag!(recovery_owner_verified);
        assert_pressure_flag!(recovery_echo);

        let mut wrong_relay_count = pressure_evidence();
        wrong_relay_count.relay_count = 2;
        assert_rejected(
            require_m7_pressure_evidence(&wrong_relay_count),
            "relay_count_is_three",
        );
        let mut no_bulk_records = pressure_evidence();
        no_bulk_records.bulk_records_attempted = 0;
        assert_rejected(
            require_m7_pressure_evidence(&no_bulk_records),
            "bulk_records_attempted_nonzero",
        );
        let mut excessive_fanout = pressure_evidence();
        excessive_fanout.fanout_peak_open = 4;
        assert_rejected(
            require_m7_pressure_evidence(&excessive_fanout),
            "fanout_peak_open_within_bound",
        );
    }
}
