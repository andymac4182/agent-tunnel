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
    // Control: show the discriminator reads something real.
    //
    // The first version of `process_provider_is_ring` compared cipher-suite
    // lists, which are identical between rustls 0.23's `ring` and `aws_lc_rs`
    // default providers -- so it returned `true` for exactly the provider
    // M8-C09 exists to exclude, and could not have failed for its stated
    // reason.  It now reads the secure-random implementation's type name, and
    // this asserts that name is what the discriminator expects rather than
    // trusting a substring match to mean something.
    //
    // The negative control -- that an `aws_lc_rs` provider makes it false --
    // is deliberately NOT here: that provider is out of the default graph by
    // M8-C09's own build-level fix, and pulling it back in to test this would
    // undo the fix.  So this is a positive control only, and that limit is
    // stated rather than papered over.
    let ring = rustls::crypto::ring::default_provider();
    assert_eq!(
        format!("{:?}", ring.secure_random),
        "Ring",
        "the discriminator's expected type name changed under it"
    );
    // Idempotent in effect, and honest about it: a second call reports that it
    // was not the one that installed, rather than pretending it was.
    assert_eq!(
        tunnel_transport::install_process_crypto_provider(),
        Err(tunnel_transport::ProviderAlreadyInstalled),
        "a second call must report that it did not install the provider"
    );
}
