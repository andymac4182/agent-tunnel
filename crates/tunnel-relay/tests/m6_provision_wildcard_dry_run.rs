//! Task row M6-C36: `provision-catalog --dry-run` refuses a wildcard
//! operation name, through the shipped binary and the shipped examples.
//!
//! A grant is checked by exact operation name, and the catalog stores names
//! opaquely, so `operations = ["*"]` used to dry-run clean (exit 0, printing
//! `grant_operations=*`) and then provision a grant that authorizes nothing.
//! The dry run contacts no Redis, so this runs in the ordinary workspace test
//! pass. The certificate is generated per run; no key material is committed.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Workdir(PathBuf);

impl Drop for Workdir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Write the shipped records example with `service` and `grant` operation
/// lists replaced, beside a freshly issued device certificate, and dry-run it
/// against the shipped relay example.
fn dry_run(work: &Path, name: &str, service: &str, grant: &str) -> Output {
    let example = fs::read_to_string(repository().join("examples/m6-catalog.toml"))
        .expect("read examples/m6-catalog.toml");
    let value: toml::Value = toml::from_str(&example).expect("parse the records example");
    let device = value["device"]["id"].as_str().expect("[device].id");
    let certificate_name = value["device"]["certificate"]
        .as_str()
        .expect("[device].certificate");

    let key = rcgen::KeyPair::generate().expect("device key");
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names.push(rcgen::SanType::URI(
        format!("urn:agent-tunnel:device:{device}")
            .try_into()
            .expect("device role SAN"),
    ));
    let certificate = params.self_signed(&key).expect("device certificate");
    let dir = work.join(name);
    fs::create_dir_all(&dir).expect("case dir");
    fs::write(dir.join(certificate_name), certificate.pem()).expect("write certificate");

    // Replace exactly the two `operations = ...` lines, in document order:
    // the service's and then the grant's.
    let mut replacements = [service, grant].into_iter();
    let records: String = example
        .lines()
        .map(|line| {
            if line.starts_with("operations = ") {
                format!(
                    "operations = {}\n",
                    replacements.next().expect("exactly two operations lines")
                )
            } else {
                format!("{line}\n")
            }
        })
        .collect();
    assert!(
        replacements.next().is_none(),
        "the example must have a service and a grant operations line"
    );
    let path = dir.join("catalog.toml");
    fs::write(&path, records).expect("write records");
    Command::new(env!("CARGO_BIN_EXE_tunnel-relay"))
        .args(["provision-catalog", "--config"])
        .arg(repository().join("examples/m1-relay.toml"))
        .arg("--records")
        .arg(&path)
        .arg("--dry-run")
        .output()
        .expect("run provision-catalog --dry-run")
}

#[test]
fn a_wildcard_operation_is_refused_by_the_dry_run() {
    let work = Workdir(env::temp_dir().join(format!(
        "m6c36-dry-run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    )));
    fs::create_dir_all(&work.0).expect("workdir");

    // Control: the same document with exact names dry-runs clean, so a
    // refusal below is the wildcard's and not the fixture's.
    let exact = dry_run(&work.0, "exact", "[\"echo:invoke\"]", "[\"echo:invoke\"]");
    assert!(
        exact.status.success()
            && String::from_utf8_lossy(&exact.stdout).contains("grant_operations=echo:invoke"),
        "the exact-name control must dry-run clean: {:?} {} {}",
        exact.status.code(),
        String::from_utf8_lossy(&exact.stdout),
        String::from_utf8_lossy(&exact.stderr)
    );

    // Each case dry-runs clean without the M6-C36 check.  The first is the
    // review's measurement; a grant-only wildcard is not a case because the
    // grant-subset-of-service rule already refuses it.
    for (case, service, grant) in [
        ("whole wildcard", "[\"*\"]", "[\"*\"]"),
        (
            "partial wildcard",
            "[\"echo:invoke\", \"echo:*\"]",
            "[\"echo:invoke\"]",
        ),
    ] {
        let refused = dry_run(&work.0, case, service, grant);
        let stdout = String::from_utf8_lossy(&refused.stdout);
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            !refused.status.success(),
            "{case}: a wildcard dry-ran clean (exit {:?}): {stdout}",
            refused.status.code()
        );
        assert!(
            stderr.contains("wildcards are not supported"),
            "{case}: the refusal must name the wildcard: {stderr}"
        );
        assert!(
            !stdout.contains("grant_operations="),
            "{case}: nothing may be reported as valid: {stdout}"
        );
    }
}
