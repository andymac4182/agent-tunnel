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
                }),
                Err(_) => Err(HarnessError::Process(
                    "M7 production acceptance exceeded 300 seconds".to_owned(),
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
                        "M7 queue saturation passed: relays={} ready={} non_owner_ingress={} queue_bytes_limit={} data_slots={} control_slots={} max_streams={} record_bytes={} charge_per_record={} frames_per_record={} credit_records_per_stream={} reachable_entries={} route_maximum_entries={} streams_admitted={} stream_cap_refused_one_more={} data_depth_observed={} data_depth_high_water={} data_enqueues_during_blackhole={} physically_resident_frames={} absorbed_frames={} absorbed_wire_bytes={} reachable_bound_saturated={} reserved_free_data_slots={} reserved_data_slot_accepted={} queue_bytes_high_water={} headroom_at_peak={} control_reserved_bytes={} data_bytes_limit={} data_bytes_high_water={} control_bytes_available_at_data_peak={} control_depth_at_peak={} control_depth_high_water={} control_refusals={} control_enqueues_during_blackhole={} cancellation_accepted={} fresh_stream_admitted={} sibling_survived={} first_terminal_immutable={} terminal_observations={} paused_target_to_client={} paused_generation={} drain_observations={}/{} drained={} rotation_replaced_paused_carrier={} rotation_generation={} rotations_after_drain={} final_generation={} attempts_with_deadline={} deadline_never_extended={} deadline_within_overlap={} device_sockets={} dispatch_delta_after_drain={} elapsed_ms={}",
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
                            "M7 OG-02 row={} command={} correlation={} missing={} peer_fault_tuples={} tuples={} captured_streams={} captured_bytes={} started_ms={} ended_ms={}",
                            row.name,
                            row.command,
                            if row.complete { "complete" } else { "incomplete" },
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

fn print_help() {
    println!(
        "Usage: tunnel-test-harness verify\n       tunnel-test-harness verify-m2\n       tunnel-test-harness verify-m2-default\n       tunnel-test-harness verify-m2-faults\n       tunnel-test-harness verify-m7-transport\n       tunnel-test-harness verify-m7-redis-tls\n       tunnel-test-harness verify-m7-cluster\n       tunnel-test-harness verify-m7-production\n       tunnel-test-harness verify-m7-i08-synthetic-rotation\n       tunnel-test-harness verify-m7-i08-goaway-rotation\n       tunnel-test-harness verify-m7-i08-rotation-faults\n       tunnel-test-harness verify-m7-i08-recovery-attempts\n       tunnel-test-harness verify-m7-admission-framing\n       tunnel-test-harness verify-m7-admission\n       tunnel-test-harness verify-m7-i04-fail-closed\n       tunnel-test-harness verify-m7-queue-saturation\n       tunnel-test-harness verify-m7-remote-body-limits\n       tunnel-test-harness verify-m7-device-revocation\n       tunnel-test-harness verify-m7-credential-expiry-rotation\n       tunnel-test-harness verify-m7-redis-partition\n       tunnel-test-harness verify-m7-process-pause\n       tunnel-test-harness verify-m7-pressure\n       tunnel-test-harness verify-m7-c11-diagnostics\n       tunnel-test-harness verify-m7-og02-correlation\n       tunnel-test-harness verify-m7-lifecycle\n       tunnel-test-harness verify-m7-side-effect\n       tunnel-test-harness verify-m7-side-effect-late\n       tunnel-test-harness verify-m7-public-abandoned-upgrade\n       tunnel-test-harness verify-m7-owner-loss-effect\n       tunnel-test-harness verify-m7-timing-boundaries\n       tunnel-test-harness verify-m7-peer-fragmentation\n       tunnel-test-harness verify-m7-pending-owner\n       tunnel-test-harness verify-m7-successor-pending-owner\n       tunnel-test-harness verify-m7-concurrent-load\n       tunnel-test-harness verify-m7-key-rotation\n       tunnel-test-harness verify-m7-peer-readiness\n       tunnel-test-harness verify-m7-peer-capacity\n       tunnel-test-harness verify-m7-owner-local-capacity\n       tunnel-test-harness verify-m7-owner-contention\n       tunnel-test-harness verify-m7-trust-expiry\n       tunnel-test-harness redis-restart-{{seed|check}} --redis-url URL --namespace NAME --receipt-file PATH\n\nverify, verify-m2, and verify-m7-redis-tls commands require TEST_REDIS_URL and built workspace binaries.\nRuns real Redis, HTTPS, device mTLS WebSocket, CLI and HTTP/3 acceptance checks.\nverify-m2 drives a long-lived public echo WebSocket through accelerated real rotations;\nverify-m2-default repeats the same flow at the 300-second policy.\nverify-m2-faults closes exact control/data/candidate sockets and checks explicit recovery outcomes.\nverify-m7-transport proves bounded peer mTLS/HTTP3 duplex exchange and negative identity cases.\nverify-m7-redis-tls proves the authenticated Redis TLS catalog connection and rejection cases.\nverify-m7-cluster connects three real relay peer listeners through signed membership,\nRedis owner fencing, control/data replacement generations and consumer ingress.\nverify-m7-production exercises the production relay actor, signed Redis directory,\nclient WebSockets and public consumer routing across three relays.\nverify-m7-i08-synthetic-rotation verifies a real CLI and checksummed synthetic Echo records across three same-owner rotations.\nverify-m7-i08-recovery-attempts fails every retained-recovery attachment of a real CLI at the opaque\ndevice fanout after the owner attached it: three attempts under one absolute episode deadline end in\nthe typed exhaustion diagnostic, then a second attempt recovers the same session and stream.\nverify-m7-admission exercises public negative admission, route allowlisting,\nforged identity-header rejection and selected-owner failure across three relays.\nverify-m7-i04-fail-closed proves the fail-closed admission, readiness, routing and\nfallback matrix with a request-body sentinel: absent/unknown/inactive/ambiguous and\ncaller-destination targets rejected before any body read or owner selection, a\ncaller-named peer address never reached, an empty body distinguished from a failed\nbody, consumed/unpolled/failed bodies under a real owner process loss with no\nreselection, GET/HEAD/OPTIONS shapes at the lost owner's route typed and never\nreselected, the duplicate service label ambiguous through the stream upgrade too,\none bounded consumer-driven safe retry bridging successor readiness, and the\nexcluded browser route boundary recorded.\nverify-m7-device-revocation proves live Redis device-credential revocation,\nexisting-stream withdrawal, exact no-owner admission, and tenant sibling survival.\nverify-m7-credential-expiry-rotation proves a sixteen-second consumer credential\nexpires inside one exact candidate/old scheduled rotation and refresh challenge\nafter admitted baseline echo, with issuer/audience/subject identity and typed\nterminal checks.\nverify-m7-pressure exercises bounded production resource pressure, cancellation, and recovery.\nverify-m7-lifecycle holds one consumer response path and checks cancellation, sibling survival, and fresh-stream recovery.\nverify-m7-side-effect-late proves owner-side receipt and terminal rejection of one late DATA/FIN pair after a selected peer fault.\nverify-m7-public-abandoned-upgrade proves real owner-local and remote public WebSocket upgrades after admission, no 101 response, exact registration reclamation, capacity rejection, and sibling recovery.\nverify-m7-key-rotation exercises bounded recovery after peer-pin withdrawal during scheduled rotation.\nverify-m7-og02-correlation drives the credential-expiry, trust-expiry, GOAWAY, recovery-attempt,\nlease-expiry, queue-saturation and remote-body-limit gates through the C11 capture scanner and\nreports per row whether the joined window carries complete OG-02 correlation and the relay's\nbounded peer stage/cause tuples; declared-complete rows are enforced.\nverify-m7-peer-readiness exercises authenticated peer path loss and fresh-path readiness recovery.\nverify-m7-owner-contention exercises concurrent CLI claims, terminal rejection and fenced successor cleanup.\nverify-m7-trust-expiry exercises signed peer-key expiry without a Redis invalidation hint,\npooled-stream closure, unrelated peer survival, and fresh signed-trust recovery.\nUses isolated Redis namespaces, ephemeral certificates and synthetic echo data.\nRun restart probes through scripts/m1-redis-restart-verify.sh.\nSet M2_HARNESS_TIMEOUT_SECONDS to override a bounded M2 command timeout."
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
        let bounds: [Mutate; 22] = [
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
