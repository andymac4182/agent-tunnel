# Agent Uplink website

Vercel project `agentuplink` is connected to GitHub `andymac4182/agentuplink`.
Production follows `main`, with `site` as the root directory and files outside
that root excluded. Pushes to the production branch trigger Vercel builds.
Both pages offer System, Light and Dark themes with browser-local persistence.

## Documentation publishing

The downloads/setup pages query public GitHub releases for the newest complete
main development release. Drafts, incomplete matrices and other tag formats
are excluded; failed API lookups do not invent a version. `test-releases.cjs`
tests these states with synthetic responses. No browser credentials are used.
Main release workflow activation requires landing `.github/workflows/release.yml`
on the default branch, and all existing main CI gates must pass before packaging.
Published builds are prereleases, not production or complete platform acceptance.

Eight static documentation pages live in `docs/`. Their reviewed content is
maintained in `build-docs.cjs`; regenerate with `node site/build-docs.cjs` from
the repository root. `provenance.json` records the reviewed origin/main revision,
not a claim that the runtime's entire acceptance suite passed at that revision.
The hourly thread automation fetches and reviews upstream changes, updates
public documentation when relevant, deploys website assets and verifies them.
It must not overwrite local work, publish runtime source, or bypass Git approval.

Standalone static marketing site. Deploy only this directory, never the repository root.
No runtime credentials, backend, analytics, forms, or third-party scripts are used.
The hardware photograph is AI-generated illustrative imagery, not a product screenshot.

The copy intentionally describes development scope rather than general availability.
Feature status is grounded in `../docs/tasks.md`; protocol boundaries are described in
`../docs/architecture.md`. Existing package and wire identifiers are not renamed.

Link the intended Vercel personal project from this directory before deploying.
Hobby deployment requires a personal, non-commercial project. Domain registration,
contact selection, DNS, and production deployment require their respective confirmations.

## Branding exploration

Open `brand-lab.html` locally for twenty numbered logo and palette options.
The comparison follows the Mount brand-lab five-role palette format. Shortlists
are stored only in this browser's local storage. Generated marks are concepts,
not cleared trademarks or production vector artwork. The board and its assets
are included in Vercel deployment at `/brand-lab` for sharing. Shortlist selections
remain browser-local and are not shared with other viewers.

Verified on 2026-09-22 in Chrome at 1440, 390 and 320 pixel widths: twenty
options, one hundred swatches, loaded source image, no horizontal overflow,
and shortlist filtering. The marketing site separately passed local and live
verification at 1440, 1920, 390 and 320 pixels via `verify.cjs`.
