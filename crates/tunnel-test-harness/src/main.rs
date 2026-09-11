use std::{process::ExitCode, time::Duration};
use tunnel_test_harness::{
    ClusterFixture, FixturePki, HarnessError, acceptance, acceptance_command_exit_code,
    cluster_acceptance, cluster_transport, m2_acceptance, redis_restart, redis_tls,
};

#[tokio::main]
async fn main() -> ExitCode {
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
                Duration::from_secs(180),
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
                }),
                Err(_) => Err(HarnessError::Process(
                    "M7 production acceptance exceeded 180 seconds".to_owned(),
                )),
            }
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
        [command] if command == "verify-m7-admission-framing" => {
            tunnel_test_harness::production_cluster::verify_c10_actual_path().await.and_then(|evidence| {
                tunnel_test_harness::production_cluster::validate_c10_actual_path_evidence(&evidence)?;
                println!("M7 admission framing passed: relays={} fresh_control={} fresh_epoch={} empty_single_prefix={} empty_owner_read={} empty_dispatch={:?} unary_exact={} unary_owner_read={} unary_dispatch={:?} truncated_read={} truncated_not_dispatched={} raw_bearer_owner_revalidated={} owner_token_changed_before_101={} owner_change_pre_101_rejected={} owner_change_pre_101_not_dispatched={} owner_change_pre_101_body_not_polled={} cleanup_joined={}", evidence.relay_count, evidence.fresh_control_after_no_live_owner, evidence.fresh_epoch_advanced, evidence.empty_body_single_prefix, evidence.empty_body_owner_read, evidence.empty_body_dispatch_delta, evidence.empty_unary_body_response_exact, evidence.empty_unary_body_owner_read, evidence.empty_unary_body_dispatch_delta, evidence.truncated_body_owner_read, evidence.truncated_body_not_dispatched, evidence.raw_bearer_owner_revalidated, evidence.owner_token_changed_before_101, evidence.owner_change_pre_101_rejected, evidence.owner_change_pre_101_not_dispatched, evidence.owner_change_pre_101_body_not_polled, evidence.cleanup_joined);
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
        [command] if command == "verify-m7-c11-diagnostics" => {
            tunnel_test_harness::production_cluster::verify_c11_diagnostics()
                .await
                .map(|evidence| {
                    println!(
                        "M7 C11 diagnostics passed: source={} build={} runs={} safe_field_count={} captured_streams={} captured_bytes={} window_start_ms={} window_end_ms={}",
                        evidence.source_id,
                        evidence.build_id,
                        evidence.runs,
                        evidence.safe_field_count,
                        evidence.captured_streams,
                        evidence.captured_bytes,
                        evidence.matrix_started_utc_ms,
                        evidence.matrix_ended_utc_ms,
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

fn print_help() {
    println!(
        "Usage: tunnel-test-harness verify\n       tunnel-test-harness verify-m2\n       tunnel-test-harness verify-m2-default\n       tunnel-test-harness verify-m2-faults\n       tunnel-test-harness verify-m7-transport\n       tunnel-test-harness verify-m7-redis-tls\n       tunnel-test-harness verify-m7-cluster\n       tunnel-test-harness verify-m7-production\n       tunnel-test-harness verify-m7-i08-synthetic-rotation\n       tunnel-test-harness verify-m7-i08-goaway-rotation\n       tunnel-test-harness verify-m7-i08-rotation-faults\n       tunnel-test-harness verify-m7-admission-framing\n       tunnel-test-harness verify-m7-admission\n       tunnel-test-harness verify-m7-device-revocation\n       tunnel-test-harness verify-m7-credential-expiry-rotation\n       tunnel-test-harness verify-m7-redis-partition\n       tunnel-test-harness verify-m7-process-pause\n       tunnel-test-harness verify-m7-pressure\n       tunnel-test-harness verify-m7-c11-diagnostics\n       tunnel-test-harness verify-m7-lifecycle\n       tunnel-test-harness verify-m7-side-effect\n       tunnel-test-harness verify-m7-side-effect-late\n       tunnel-test-harness verify-m7-public-abandoned-upgrade\n       tunnel-test-harness verify-m7-owner-loss-effect\n       tunnel-test-harness verify-m7-timing-boundaries\n       tunnel-test-harness verify-m7-peer-fragmentation\n       tunnel-test-harness verify-m7-pending-owner\n       tunnel-test-harness verify-m7-successor-pending-owner\n       tunnel-test-harness verify-m7-concurrent-load\n       tunnel-test-harness verify-m7-key-rotation\n       tunnel-test-harness verify-m7-peer-readiness\n       tunnel-test-harness verify-m7-peer-capacity\n       tunnel-test-harness verify-m7-owner-local-capacity\n       tunnel-test-harness verify-m7-owner-contention\n       tunnel-test-harness verify-m7-trust-expiry\n       tunnel-test-harness redis-restart-{{seed|check}} --redis-url URL --namespace NAME --receipt-file PATH\n\nverify, verify-m2, and verify-m7-redis-tls commands require TEST_REDIS_URL and built workspace binaries.\nRuns real Redis, HTTPS, device mTLS WebSocket, CLI and HTTP/3 acceptance checks.\nverify-m2 drives a long-lived public echo WebSocket through accelerated real rotations;\nverify-m2-default repeats the same flow at the 300-second policy.\nverify-m2-faults closes exact control/data/candidate sockets and checks explicit recovery outcomes.\nverify-m7-transport proves bounded peer mTLS/HTTP3 duplex exchange and negative identity cases.\nverify-m7-redis-tls proves the authenticated Redis TLS catalog connection and rejection cases.\nverify-m7-cluster connects three real relay peer listeners through signed membership,\nRedis owner fencing, control/data replacement generations and consumer ingress.\nverify-m7-production exercises the production relay actor, signed Redis directory,\nclient WebSockets and public consumer routing across three relays.\nverify-m7-i08-synthetic-rotation verifies a real CLI and checksummed synthetic Echo records across three same-owner rotations.\nverify-m7-admission exercises public negative admission, route allowlisting,\nforged identity-header rejection and selected-owner failure across three relays.\nverify-m7-device-revocation proves live Redis device-credential revocation,\nexisting-stream withdrawal, exact no-owner admission, and tenant sibling survival.\nverify-m7-credential-expiry-rotation proves a sixteen-second consumer credential\nexpires inside one exact candidate/old scheduled rotation and refresh challenge\nafter admitted baseline echo, with issuer/audience/subject identity and typed\nterminal checks.\nverify-m7-pressure exercises bounded production resource pressure, cancellation, and recovery.\nverify-m7-lifecycle holds one consumer response path and checks cancellation, sibling survival, and fresh-stream recovery.\nverify-m7-side-effect-late proves owner-side receipt and terminal rejection of one late DATA/FIN pair after a selected peer fault.\nverify-m7-public-abandoned-upgrade proves real owner-local and remote public WebSocket upgrades after admission, no 101 response, exact registration reclamation, capacity rejection, and sibling recovery.\nverify-m7-key-rotation exercises bounded recovery after peer-pin withdrawal during scheduled rotation.\nverify-m7-peer-readiness exercises authenticated peer path loss and fresh-path readiness recovery.\nverify-m7-owner-contention exercises concurrent CLI claims, terminal rejection and fenced successor cleanup.\nverify-m7-trust-expiry exercises signed peer-key expiry without a Redis invalidation hint,\npooled-stream closure, unrelated peer survival, and fresh signed-trust recovery.\nUses isolated Redis namespaces, ephemeral certificates and synthetic echo data.\nRun restart probes through scripts/m1-redis-restart-verify.sh.\nSet M2_HARNESS_TIMEOUT_SECONDS to override a bounded M2 command timeout."
    );
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

    #[test]
    fn complete_acceptance_evidence_passes_all_gates() {
        assert!(require_m7_transport_evidence(&transport_evidence()).is_ok());
        assert!(require_m7_redis_tls_evidence(&redis_tls_evidence()).is_ok());
        assert!(require_m7_process_pause_evidence(&process_pause_evidence()).is_ok());
        assert!(require_m7_redis_partition_evidence(&redis_partition_evidence()).is_ok());
        assert!(require_m7_pressure_evidence(&pressure_evidence()).is_ok());
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
