//! The process's `rustls` crypto provider is chosen, not inferred (M8-C09).
//!
//! This test binary exists so the assertion runs in a process that has done no
//! TLS work yet: `install_default` succeeds exactly once per process, and the
//! whole point of the claim is that **this workspace's call is the one that
//! succeeds**.

#[test]
fn the_process_provider_is_installed_by_this_workspace_and_is_ring() {
    assert!(
        !tunnel_transport::process_provider_is_ring(),
        "nothing may have installed a provider before this line; if something \
         did, the workspace no longer decides this process's cryptography"
    );
    tunnel_transport::install_process_crypto_provider()
        .expect("this call installs the process provider");
    assert!(
        tunnel_transport::process_provider_is_ring(),
        "the installed provider is ring's"
    );
    // Idempotent in effect, and honest about it: a second call reports that it
    // was not the one that installed, rather than pretending it was.
    assert_eq!(
        tunnel_transport::install_process_crypto_provider(),
        Err(tunnel_transport::ProviderAlreadyInstalled),
        "a second call must report that it did not install the provider"
    );
}
