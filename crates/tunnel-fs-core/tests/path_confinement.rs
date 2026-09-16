//! Escape classes, boundaries, and the generative invariants of the lexical
//! confinement layer.

mod common;

use common::{PATH_FRAGMENTS, Rng, default_bounds};
use tunnel_fs_core::{MAX_COMPONENT_BYTES, PathBounds, PathRule, VirtualPath};

/// Every escape class the contract names, with the rule that must refuse it.
///
/// This table is the executable form of the "no escape via" list in
/// `docs/filesystem-api.md`.  A rule that stops firing fails here by name.
const ESCAPES: &[(&str, PathRule)] = &[
    // Parent traversal, in every position.
    ("/..", PathRule::DotDotComponent),
    ("/../etc/passwd", PathRule::DotDotComponent),
    ("/a/../../b", PathRule::DotDotComponent),
    ("/a/b/..", PathRule::DotDotComponent),
    ("/a/../b", PathRule::DotDotComponent),
    // Current-directory components, which a normaliser would fold away.
    ("/.", PathRule::DotComponent),
    ("/./a", PathRule::DotComponent),
    ("/a/./b", PathRule::DotComponent),
    // Empty components from repeated or trailing separators.
    ("//", PathRule::EmptyComponent),
    ("/a//b", PathRule::EmptyComponent),
    ("/a/", PathRule::EmptyComponent),
    ("///", PathRule::EmptyComponent),
    // Not absolute.
    ("a", PathRule::MissingLeadingSlash),
    ("./a", PathRule::MissingLeadingSlash),
    ("../a", PathRule::MissingLeadingSlash),
    ("a/b", PathRule::MissingLeadingSlash),
    // Windows separators and drive/UNC syntax.
    ("/a\\b", PathRule::Backslash),
    ("\\a", PathRule::MissingLeadingSlash),
    ("\\\\server\\share", PathRule::MissingLeadingSlash),
    ("/\\\\server\\share", PathRule::Backslash),
    ("/C:\\Windows", PathRule::Colon),
    ("/C:", PathRule::Colon),
    ("/file.txt:stream", PathRule::Colon),
    // NUL and control characters.
    ("/a\u{0}b", PathRule::Nul),
    ("/\u{0}", PathRule::Nul),
    ("/a\nb", PathRule::ControlCharacter),
    ("/a\tb", PathRule::ControlCharacter),
    ("/a\u{7}b", PathRule::ControlCharacter),
    ("/a\u{7f}b", PathRule::ControlCharacter),
    ("/a\u{1b}[0m", PathRule::ControlCharacter),
    // Reserved Windows device names, any case, with or without an extension.
    ("/CON", PathRule::WindowsDeviceName),
    ("/con", PathRule::WindowsDeviceName),
    ("/CoN", PathRule::WindowsDeviceName),
    ("/NUL", PathRule::WindowsDeviceName),
    ("/NUL.txt", PathRule::WindowsDeviceName),
    ("/COM1", PathRule::WindowsDeviceName),
    ("/com9.log", PathRule::WindowsDeviceName),
    ("/LPT0", PathRule::WindowsDeviceName),
    ("/AUX", PathRule::WindowsDeviceName),
    ("/PRN", PathRule::WindowsDeviceName),
    ("/CONIN$", PathRule::WindowsDeviceName),
    ("/CONOUT$.dat", PathRule::WindowsDeviceName),
    ("/dir/con/file", PathRule::WindowsDeviceName),
    // `ntdll` trims trailing spaces from the stem before comparing, so these
    // open the console device on Windows despite the space.
    ("/CON .txt", PathRule::WindowsDeviceName),
    ("/con   .log", PathRule::WindowsDeviceName),
    ("/dir/aux  .dat", PathRule::WindowsDeviceName),
    // Microsoft reserves the superscript spellings alongside the ASCII digits.
    ("/COM\u{b9}", PathRule::WindowsDeviceName),
    ("/COM\u{b2}.txt", PathRule::WindowsDeviceName),
    ("/LPT\u{b9}", PathRule::WindowsDeviceName),
    ("/lpt\u{b3}.log", PathRule::WindowsDeviceName),
    // Endings a Windows host silently trims, which would alias two paths.
    ("/trailing.", PathRule::TrailingSpaceOrDot),
    ("/trailing ", PathRule::TrailingSpaceOrDot),
    ("/a/b. /c", PathRule::TrailingSpaceOrDot),
    ("/ ", PathRule::TrailingSpaceOrDot),
    ("/...", PathRule::TrailingSpaceOrDot),
    ("/a..", PathRule::TrailingSpaceOrDot),
    // Empty.
    ("", PathRule::Empty),
];

#[test]
fn every_named_escape_class_is_refused_by_its_own_rule() {
    let bounds = default_bounds();
    assert_eq!(
        ESCAPES.len(),
        57,
        "the escape corpus changed; update the evidence count in docs/tasks.md"
    );
    for (candidate, expected) in ESCAPES {
        match VirtualPath::parse(candidate, bounds) {
            Ok(accepted) => panic!(
                "escape accepted: rule {} expected, got a path with {} components",
                expected.as_str(),
                accepted.component_count()
            ),
            Err(rule) => assert_eq!(
                rule,
                *expected,
                "wrong rule for escape class {}",
                expected.as_str()
            ),
        }
    }

    // Every rule must be exercised somewhere, so a rule added without a case
    // cannot ship untested.  Four are covered by their own tests rather than by
    // this corpus, because each needs a constructed input rather than a
    // literal: the three length rules are driven at their exact boundaries by
    // the limit tests below, and `Separator` is reachable only through `join`.
    let covered_elsewhere = [
        PathRule::TooLongBytes,      // path_byte_limit_is_exact_...
        PathRule::TooManyComponents, // component_count_limit_is_exact_...
        PathRule::ComponentTooLong,  // component_byte_limit_is_exact_...
        PathRule::Separator,         // parent_and_join_stay_within_the_root
    ];
    for rule in PathRule::ALL {
        if covered_elsewhere.contains(&rule) {
            continue;
        }
        assert!(
            ESCAPES.iter().any(|(_, expected)| *expected == rule),
            "{rule} has no case in the escape corpus"
        );
    }
}

#[test]
fn ordinary_paths_are_accepted_unchanged() {
    let bounds = default_bounds();
    for candidate in [
        "/",
        "/a",
        "/a/b",
        "/notes.txt",
        "/dir/sub/file.tar.gz",
        "/with space/and more",
        "/unicode-\u{e9}\u{fc}\u{4e2d}\u{6587}",
        "/percent%20literal",
        "/hash#literal",
        "/question?literal",
        "/star*literal",
        "/MixedCase/PreServed",
        "/..a",
        "/.hidden",
        "/console",
        "/COMX",
        "/COM10",
    ] {
        let path = VirtualPath::parse(candidate, bounds)
            .unwrap_or_else(|rule| panic!("{} refused {candidate:?}", rule.as_str()));
        assert_eq!(
            path.as_str(),
            candidate,
            "validation must not rewrite the path"
        );
    }
}

/// Build a path of exactly `total` bytes whose components stay well inside
/// [`MAX_COMPONENT_BYTES`], leaving room to append one more byte to the last.
fn path_of_exactly(total: usize) -> String {
    assert!(total >= 2, "a non-root path needs at least two bytes");
    let mut out = String::with_capacity(total);
    let mut remaining = total;
    while remaining > 0 {
        let len = (MAX_COMPONENT_BYTES - 1).min(remaining - 1);
        assert!(len > 0, "a component must not be empty");
        out.push('/');
        for _ in 0..len {
            out.push('a');
        }
        remaining -= len + 1;
    }
    out
}

#[test]
fn path_byte_limit_is_exact_at_the_boundary_and_one_beyond() {
    for max_bytes in [2usize, 16, 64, 4_096] {
        let bounds = PathBounds::new(max_bytes, 256).expect("non-zero bounds");
        let at = path_of_exactly(max_bytes);
        assert_eq!(at.len(), max_bytes);
        assert!(
            VirtualPath::parse(&at, bounds).is_ok(),
            "a path of exactly {max_bytes} bytes must be accepted"
        );

        // One byte beyond, by lengthening the final component rather than
        // adding one, so the only rule that can fire is the byte limit.
        let beyond = format!("{at}a");
        assert_eq!(beyond.len(), max_bytes + 1);
        assert_eq!(
            VirtualPath::parse(&beyond, bounds),
            Err(PathRule::TooLongBytes),
            "a path of {} bytes must be refused",
            max_bytes + 1
        );
    }
}

#[test]
fn component_count_limit_is_exact_at_the_boundary_and_one_beyond() {
    for max_components in [1usize, 2, 8, 256] {
        let bounds = PathBounds::new(4_096, max_components).expect("non-zero bounds");
        let at: String = (0..max_components).map(|_| "/a").collect();
        let path = VirtualPath::parse(&at, bounds)
            .unwrap_or_else(|rule| panic!("{} refused {max_components} components", rule.as_str()));
        assert_eq!(path.component_count(), max_components);

        let beyond: String = (0..=max_components).map(|_| "/a").collect();
        assert_eq!(
            VirtualPath::parse(&beyond, bounds),
            Err(PathRule::TooManyComponents),
            "{} components must be refused",
            max_components + 1
        );
    }
}

#[test]
fn component_byte_limit_is_exact_at_the_boundary_and_one_beyond() {
    let bounds = default_bounds();
    let at = format!("/{}", "a".repeat(MAX_COMPONENT_BYTES));
    assert!(VirtualPath::parse(&at, bounds).is_ok());

    let beyond = format!("/{}", "a".repeat(MAX_COMPONENT_BYTES + 1));
    assert_eq!(
        VirtualPath::parse(&beyond, bounds),
        Err(PathRule::ComponentTooLong)
    );
}

#[test]
fn zero_bounds_are_refused_so_zero_cannot_mean_unlimited() {
    assert!(PathBounds::new(0, 256).is_none());
    assert!(PathBounds::new(4_096, 0).is_none());
    assert!(PathBounds::new(0, 0).is_none());
    assert!(PathBounds::new(1, 1).is_some());
}

#[test]
fn every_single_byte_is_accounted_for_in_a_component() {
    let bounds = default_bounds();
    for byte in 0u8..=255 {
        let candidate = format!("/x{}y", byte as char);
        let outcome = VirtualPath::parse(&candidate, bounds);
        match byte {
            0 => assert_eq!(outcome, Err(PathRule::Nul), "byte {byte:#04x}"),
            b'\\' => assert_eq!(outcome, Err(PathRule::Backslash), "byte {byte:#04x}"),
            b':' => assert_eq!(outcome, Err(PathRule::Colon), "byte {byte:#04x}"),
            0x01..=0x1F | 0x7F => {
                assert_eq!(outcome, Err(PathRule::ControlCharacter), "byte {byte:#04x}");
            }
            b'/' => assert!(outcome.is_ok(), "byte {byte:#04x} splits into components"),
            _ => assert!(
                outcome.is_ok(),
                "byte {byte:#04x} should be an ordinary character, got {outcome:?}"
            ),
        }
    }
}

#[test]
fn parent_and_join_stay_within_the_root() {
    let bounds = default_bounds();
    let root = VirtualPath::root();
    assert!(root.is_root());
    assert_eq!(root.parent(), None, "the root has no parent to escape into");

    let nested = VirtualPath::parse("/a/b/c", bounds).expect("valid");
    let mut current = nested.clone();
    let mut steps = 0;
    while let Some(parent) = current.parent() {
        assert!(parent.is_within(&VirtualPath::root()));
        assert!(
            nested.is_within(&parent),
            "an ancestor must contain its leaf"
        );
        current = parent;
        steps += 1;
        assert!(
            steps <= 4,
            "walking to the parent must terminate at the root"
        );
    }
    assert!(current.is_root());

    // A component that would escape is refused by join, not resolved.
    assert_eq!(nested.join("..", bounds), Err(PathRule::DotDotComponent));
    assert_eq!(nested.join(".", bounds), Err(PathRule::DotComponent));
    assert_eq!(nested.join("", bounds), Err(PathRule::EmptyComponent));
    // A separator in a joined component is its own rule: the component is not
    // empty, it is several components, and calling it empty would misreport it.
    assert_eq!(nested.join("a/b", bounds), Err(PathRule::Separator));
    assert_eq!(nested.join("/", bounds), Err(PathRule::Separator));
    assert_eq!(nested.join("a\\b", bounds), Err(PathRule::Backslash));

    let joined = nested.join("d", bounds).expect("ordinary component");
    assert_eq!(joined.as_str(), "/a/b/c/d");
    assert!(joined.is_within(&nested));
}

#[test]
fn containment_is_component_wise_not_a_string_prefix() {
    let bounds = default_bounds();
    let short = VirtualPath::parse("/a", bounds).expect("valid");
    let sibling = VirtualPath::parse("/ab", bounds).expect("valid");
    let child = VirtualPath::parse("/a/b", bounds).expect("valid");

    assert!(child.is_within(&short));
    assert!(
        !sibling.is_within(&short),
        "/ab must not count as being inside /a"
    );
    assert!(short.is_within(&VirtualPath::root()));
    assert!(sibling.is_within(&VirtualPath::root()));
}

#[test]
fn distinct_paths_that_a_host_may_alias_are_all_accepted_here() {
    // This module offers no collision key, deliberately.  These pairs are each
    // two distinct virtual paths that some host resolves to one file, and every
    // one of them is accepted, because deciding them needs file identity from
    // the host rather than a string comparison.  The test exists so the residue
    // is visible and counted rather than assumed away; gate 2 owns it.
    let bounds = default_bounds();
    let aliasing_pairs = [
        // ASCII case, on a case-insensitive volume.
        ("/Dir/File.TXT", "/dir/file.txt"),
        // Unicode case pairs, which an ASCII fold would have missed.
        ("/\u{3c3}", "/\u{3a3}"),
        ("/stra\u{df}e", "/STRASSE"),
        // NFC and NFD spellings of the same name on APFS or HFS+.
        ("/caf\u{e9}", "/cafe\u{301}"),
        // An NTFS 8.3 short name and its long form.
        ("/LONGFI~1.TXT", "/longfilename.txt"),
    ];
    for (left, right) in aliasing_pairs {
        let first = VirtualPath::parse(left, bounds)
            .unwrap_or_else(|rule| panic!("{} refused {left:?}", rule.as_str()));
        let second = VirtualPath::parse(right, bounds)
            .unwrap_or_else(|rule| panic!("{} refused {right:?}", rule.as_str()));
        assert_ne!(
            first, second,
            "{left:?} and {right:?} are distinct virtual paths here"
        );
    }
}

#[test]
fn debug_of_a_path_never_contains_its_text() {
    let bounds = default_bounds();
    let path = VirtualPath::parse("/secret-directory/confidential.key", bounds).expect("valid");
    let rendered = format!("{path:?}");

    for leaked in ["secret-directory", "confidential", ".key", "/"] {
        assert!(
            !rendered.contains(leaked),
            "Debug leaked {leaked:?} in {rendered:?}"
        );
    }
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("bytes=34"), "{rendered}");
    assert!(rendered.contains("components=2"));
}

// --- Generative invariants -------------------------------------------------

/// Build a candidate by gluing fragments together.
fn generate(rng: &mut Rng) -> String {
    let mut candidate = String::new();
    if rng.below(8) != 0 {
        candidate.push('/');
    }
    let parts = 1 + rng.below(5);
    for index in 0..parts {
        if index > 0 && rng.below(4) != 0 {
            candidate.push('/');
        }
        candidate.push_str(PATH_FRAGMENTS[rng.below(PATH_FRAGMENTS.len())]);
    }
    candidate
}

#[test]
fn accepted_paths_never_contain_an_escape_and_reparse_identically() {
    let bounds = default_bounds();
    let mut accepted = 0u32;
    let mut rejected = 0u32;

    for seed in 0..20_000u64 {
        let mut rng = Rng::new(seed.wrapping_add(1));
        let candidate = generate(&mut rng);
        let Ok(path) = VirtualPath::parse(&candidate, bounds) else {
            rejected += 1;
            continue;
        };
        accepted += 1;

        let context = || format!("seed {seed} produced {candidate:?}");

        // The accepted text is exactly the input: validation never rewrites.
        assert_eq!(path.as_str(), candidate, "{}", context());
        // Absolute, and never ends in a separator unless it is the root.
        assert!(path.as_str().starts_with('/'), "{}", context());
        assert!(
            path.is_root() || !path.as_str().ends_with('/'),
            "{}",
            context()
        );
        // No component can express traversal or a host separator.
        let mut counted = 0;
        for component in path.components() {
            counted += 1;
            assert!(!component.is_empty(), "{}", context());
            assert_ne!(component, ".", "{}", context());
            assert_ne!(component, "..", "{}", context());
            assert!(!component.contains('\\'), "{}", context());
            assert!(!component.contains(':'), "{}", context());
            assert!(!component.contains('\u{0}'), "{}", context());
            assert!(component.len() <= MAX_COMPONENT_BYTES, "{}", context());
            assert!(
                !component.ends_with('.') && !component.ends_with(' '),
                "{}",
                context()
            );
        }
        assert_eq!(counted, path.component_count(), "{}", context());
        // Within bounds.
        assert!(path.as_str().len() <= bounds.max_bytes(), "{}", context());
        assert!(counted <= bounds.max_components(), "{}", context());
        // Every accepted path lies inside the root, and re-parsing is stable.
        assert!(path.is_within(&VirtualPath::root()), "{}", context());
        let reparsed = VirtualPath::parse(path.as_str(), bounds).expect("idempotent");
        assert_eq!(reparsed, path, "{}", context());
        // Debug never carries the text.
        assert!(!format!("{path:?}").contains(&candidate), "{}", context());
    }

    // The corpus must genuinely exercise both arms; a generator that only ever
    // produced rejections would make every invariant above vacuous.
    assert!(
        accepted >= 500,
        "generator produced only {accepted} accepted paths"
    );
    assert!(
        rejected >= 500,
        "generator produced only {rejected} rejected paths"
    );
}

#[test]
fn every_parent_chain_of_a_generated_path_terminates_at_the_root() {
    let bounds = default_bounds();
    for seed in 0..5_000u64 {
        let mut rng = Rng::new(seed.wrapping_mul(2_654_435_761).wrapping_add(7));
        let candidate = generate(&mut rng);
        let Ok(path) = VirtualPath::parse(&candidate, bounds) else {
            continue;
        };
        let expected = path.component_count();
        let mut current = path.clone();
        let mut steps = 0usize;
        while let Some(parent) = current.parent() {
            assert!(
                path.is_within(&parent),
                "seed {seed}: {candidate:?} escaped its own ancestor"
            );
            current = parent;
            steps += 1;
            assert!(
                steps <= expected,
                "seed {seed}: {candidate:?} walked past the root"
            );
        }
        assert!(current.is_root(), "seed {seed}: {candidate:?}");
        assert_eq!(steps, expected, "seed {seed}: {candidate:?}");
    }
}

#[test]
fn arbitrary_bytes_never_panic_and_are_classified() {
    let bounds = default_bounds();
    let mut accepted = 0u32;
    let mut rejected = 0u32;

    for seed in 0..20_000u64 {
        let mut rng = Rng::new(seed ^ 0xDEAD_BEEF_CAFE_F00D);
        let length = rng.below(48);
        let mut candidate = String::with_capacity(length + 1);
        // Half the seeds get a leading separator.  Without it a random first
        // scalar is `/` with probability 1 in 0x110000, so every candidate is
        // refused as non-absolute and the acceptance arm below never runs.
        if seed % 2 == 0 {
            candidate.push('/');
        }
        for _ in 0..length {
            // Draw from the whole scalar range, including astral planes.
            let raw = rng.below(0x11_0000) as u32;
            if let Some(character) = char::from_u32(raw) {
                candidate.push(character);
            }
        }
        match VirtualPath::parse(&candidate, bounds) {
            Ok(path) => {
                accepted += 1;
                assert_eq!(path.as_str(), candidate, "seed {seed}");
                assert!(path.is_within(&VirtualPath::root()), "seed {seed}");
                for component in path.components() {
                    assert_ne!(component, "..", "seed {seed}");
                    assert_ne!(component, ".", "seed {seed}");
                    assert!(!component.is_empty(), "seed {seed}");
                }
            }
            Err(rule) => {
                rejected += 1;
                // The rule must be one this crate defines; `parse` on the token
                // round-trips, which catches a rule added without a token.
                assert_eq!(PathRule::parse(rule.as_str()), Some(rule), "seed {seed}");
            }
        }
    }

    // Both arms must genuinely run, or the invariants above are vacuous.
    assert!(
        accepted >= 1_000,
        "only {accepted} candidates were accepted"
    );
    assert!(
        rejected >= 1_000,
        "only {rejected} candidates were rejected"
    );
}
