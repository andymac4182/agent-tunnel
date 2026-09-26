# Demo: the disposable macOS CUA guest

This recipe drives the macOS half of the M5-03 VM setup with [`scripts/m5-cua-vm-macos.sh`](../../scripts/m5-cua-vm-macos.sh). It does **not** go through a relay yet. The probe reaches the guest's `cua-computer-server` over an SSH forward to the guest's loopback, not through a tunnel device. The Linux end-to-end relay demo is on branch `feat-cua-demo`. Background, safety boundary and measurements: [testing.md, "Disposable macOS CUA VM"](../testing.md#disposable-macos-cua-vm-apple-silicon-host).

Prerequisites: an Apple Silicon Mac, Tart 2.38.0 on `PATH` (or `TART=~/.local/bin/tart`), and at least 20 GiB of free space left after each step. The first build pulls about 25 GB.

```sh
export PATH="$HOME/.local/bin:$PATH"
scripts/m5-cua-vm-macos.sh golden     # builds cua-macos-golden and cua-macos-golden-denied
```

Expected ending:

```
m5-cua-vm-macos: golden images cua-macos-golden and cua-macos-golden-denied ready; NN GiB free
m5-cua-vm-macos: NEXT (a person, at the VM's window): grant Screen Recording and Accessibility in cua-macos-golden only;
```

## Permission-denied run (works now)

```sh
scripts/m5-cua-vm-macos.sh cycle cua-mac-d1 --from denied --expect denied                        # 2x display: 1280x800pt comes up as 1024x768 points at scale 2.0 (unexplained)
scripts/m5-cua-vm-macos.sh cycle cua-mac-d2 --from denied --expect denied --display 1280x800px   # 1x display
```

Expected output: `preflight: screen_recording=False accessibility=False`. Each of `native`, `native-width640` and `cua-driver` logs `probe.py: screenshot corners are not the fixture markers; refusing to keep the image or its pixels`, which is the expected denial. The run ends with `cycle complete: cua-mac-dN created, probed and deleted`. Evidence goes under `~/.local/state/agentuplink-m5-cua-vm-macos/runs/`.

## Granted run (after the owner's one-time grant)

Follow [the owner steps](../testing.md#owner-granting-the-permissions-once-by-hand-in-cua-macos-golden-only), then:

```sh
scripts/m5-cua-vm-macos.sh cycle cua-mac-g1 --from golden --expect granted   # 2x: 1024x768 points, see above
```

Expected output: `preflight: screen_recording=True accessibility=True`, no "refusing" lines, `screenshot-*.png` files in the evidence directory, and `cycle complete`.

## Failure recovery

- `aborting: free space would drop below 20 GiB`: free space, or run `scripts/m5-cua-vm-macos.sh destroy-golden` (this also discards the owner's grant).
- `cua did not log in automatically` or `Setup Assistant is running`: rebuild with `golden --rebuild`.
- `fixture did not come to the front full-screen`: the window stack is printed. Re-run `run NAME` on a fresh clone.
- `expected both grants; preflight says ...False`: the grant went to the wrong binary. Repeat the owner steps with the exact `Python.app` path.
- A leftover clone: `scripts/m5-cua-vm-macos.sh destroy NAME`. The script refuses to destroy either golden image this way.
