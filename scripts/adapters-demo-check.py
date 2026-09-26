#!/usr/bin/env python3
"""Check the four-adapter demo's consumer report against the exported host
directory (docs/demo/adapters.md, scripts/adapters-demo.sh).

    adapters-demo-check.py RESULT_JSON EXPORT_ROOT SEED_FILES

Every judgement is taken here, from the host's own bytes, never from the
consumer's opinion of itself: a digest the consumer computed is compared with a
digest of the host file, a write the consumer reports is looked for on the host
disk, and a listing is compared with the seed set the script created before the
consumer ran. Each check prints `ok <name>` or `FAILED <name>`; the exit status
is 1 if any failed. Output carries no file content beyond the synthetic lines
the demo itself wrote.
"""

import hashlib
import json
import os
import sys


def main() -> int:
    result = json.load(open(sys.argv[1]))
    root = sys.argv[2]
    seed = [line for line in open(sys.argv[3]).read().splitlines() if line]
    failed = []

    def check(name, condition, detail=""):
        suffix = f": {detail}" if detail else ""
        if condition:
            print(f"ok {name}{suffix}")
        else:
            print(f"FAILED {name}{suffix}")
            failed.append(name)

    def host(path):
        full = os.path.join(root, path.lstrip("/"))
        return open(full, "rb").read() if os.path.isfile(full) else None

    def sha256(data):
        return hashlib.sha256(data).hexdigest()

    ops = set(result["descriptor"]["operations"])
    check(
        "descriptor advertises a writable grant",
        result["descriptor"]["readOnly"] is False and {"readFile", "writeFile", "readDirectory", "remove"} <= ops,
        ",".join(sorted(ops)),
    )

    # -- Files SDK -----------------------------------------------------------
    f = result["filesSdk"]
    seed_keys = sorted(p.lstrip("/") for p in seed)
    listed = [k for k in f["keys"] if not k.startswith("outbox/") and not k.startswith("uploads/")]
    check("Files SDK list() returns every seeded key", sorted(listed) == seed_keys, f"{len(listed)} of {len(seed_keys)}")
    check("Files SDK head() size equals the host's", f["headSize"] == len(host("/docs/notes.txt") or b""))
    blob = host("/data/blob.bin") or b""
    check(
        "Files SDK download() of /data/blob.bin: size and SHA-256 equal the host's",
        f["blobBytes"] == len(blob) and f["blobSha256"] == sha256(blob),
        f"{f['blobBytes']} bytes",
    )
    check(
        "Files SDK upload() landed on the device's disk byte for byte",
        host("/outbox/files-sdk.txt") == f["uploadedText"].encode() and f["uploadedExists"] is True,
    )
    check(
        "Files SDK delete() removed the file from the device's disk",
        f["scratchExists"] is False and host("/outbox/scratch.txt") is None,
    )

    # -- just-bash -----------------------------------------------------------
    b = {c["command"]: c for c in result["justBash"]["commands"]}
    ls = b["ls /docs"]
    check("just-bash ls /docs", ls["exitCode"] == 0 and ls["stdout"].split() == ["guide", "notes.txt"], " ".join(ls["stdout"].split()))
    md5 = b["find /docs /data -type f | sort | xargs md5sum"]
    sums = {}
    for line in md5["stdout"].splitlines():
        digest, _, path = line.partition("  ")
        sums[path.strip()] = digest
    wanted = [p for p in seed if p.startswith("/docs/") or p.startswith("/data/")]
    bad = [p for p in wanted if sums.get(p) != hashlib.md5(host(p) or b"").hexdigest()]
    check(
        "just-bash find | xargs md5sum equals the host's MD5 of every file",
        md5["exitCode"] == 0 and not bad and len(sums) == len(wanted),
        f"{len(wanted) - len(bad)} of {len(wanted)} match",
    )
    wc = b["cat /docs/notes.txt | wc -l"]
    host_lines = (host("/docs/notes.txt") or b"").count(b"\n")
    check("just-bash cat | wc -l equals the host's line count", wc["stdout"].strip() == str(host_lines), wc["stdout"].strip())
    grep = b['grep -c "," /data/numbers.csv']
    host_commas = sum(1 for line in (host("/data/numbers.csv") or b"").splitlines() if b"," in line)
    check("just-bash grep -c equals the host's count", grep["stdout"].strip() == str(host_commas), grep["stdout"].strip())
    redirect = b['echo "written by just-bash" > /outbox/just-bash.txt && cat /outbox/just-bash.txt']
    check(
        "just-bash redirect wrote the file on the device's disk",
        redirect["exitCode"] == 0 and host("/outbox/just-bash.txt") == b"written by just-bash\n",
    )
    check("just-bash recorded no ambiguous remote mutation", result["justBash"]["operationFailures"] == 0)

    # -- Mastra --------------------------------------------------------------
    m = result["mastra"]
    names = [c["toolName"] for c in m["calls"]]
    check(
        "Mastra Agent called list_files, read_file and write_file through the Workspace",
        names == ["mastra_workspace_list_files", "mastra_workspace_read_file", "mastra_workspace_write_file"],
        ", ".join(names),
    )
    listing = m["calls"][0]["result"] if m["calls"] else ""
    check("Mastra list_files output names the host's /docs entries", "notes.txt" in listing and "chapter-1.md" in listing)
    read = m["calls"][1]["result"] if len(m["calls"]) > 1 else ""
    notes_lines = (host("/docs/notes.txt") or b"").decode().splitlines()
    check("Mastra read_file output carries the host file's lines", all(line in read for line in notes_lines) and bool(notes_lines))
    check("Mastra write_file landed on the device's disk", host("/outbox/mastra.txt") == m["writtenText"].encode())
    check("Mastra Agent finished with the scripted model's final text", m["text"] == "Saw 3 tool results.")

    # -- AI SDK --------------------------------------------------------------
    a = result["aiSdk"]
    check(
        "AI SDK tools offered match the grant",
        sorted(a["offered"]) == ["list_directory", "read_file", "stat", "write_file"],
        ", ".join(sorted(a["offered"])),
    )
    calls = a["calls"]
    check(
        "AI SDK generateText ran the scripted tool calls in order",
        [c["toolName"] for c in calls] == ["list_directory", "read_file", "stat", "write_file", "write_file"],
    )
    lst = calls[0]["output"]
    check(
        "AI SDK list_directory /data equals the host's",
        lst["ok"] and sorted(e["name"] for e in lst["entries"]) == sorted(os.listdir(os.path.join(root, "data"))),
    )
    rd = calls[1]["output"]
    csv = host("/data/numbers.csv") or b""
    check(
        "AI SDK read_file returned exactly the first 64 host bytes and said truncated",
        rd["ok"] and rd["bytesReturned"] == 64 and rd["truncated"] is True and rd["content"].encode() == csv[:64],
    )
    st = calls[2]["output"]
    check("AI SDK stat size equals the host's", st["ok"] and st["size"] == str(len(blob)), st.get("size", ""))
    wr = calls[3]["output"]
    check(
        "AI SDK write_file landed on the device's disk",
        wr["ok"] and wr["outcome"] == "applied" and host("/outbox/ai-sdk.txt") == a["writtenText"].encode(),
    )
    again = calls[4]["output"]
    check(
        "AI SDK write_file refuses to replace without overwrite, as a model-visible EEXIST that is not retry-safe",
        # A failed mutation is a floor ("at least this much", filesystem-api.md),
        # so only not_started may be marked retry-safe for a write.
        again["ok"] is False and again["code"] == "EEXIST" and again["outcome"] == "failed"
        and again["retrySafe"] is False
        and host("/outbox/ai-sdk.txt") == a["writtenText"].encode(),
        f"{again.get('code')} outcome={again.get('outcome')}",
    )
    fv = a["filesV4"]
    uploads = [n for n in os.listdir(os.path.join(root, "uploads"))]
    check("FilesV4 reference is opaque (no path in it)", fv["referenceIsOpaque"] is True)
    check(
        "FilesV4 upload is one file on the device's disk whose SHA-256 equals the download's",
        len(uploads) == 1
        and sha256(host("/uploads/" + uploads[0]) or b"") == fv["uploadSha256"] == fv["downloadSha256"],
        f"{len(uploads)} file(s) in /uploads",
    )

    # -- Nothing else changed ---------------------------------------------------
    now = sorted(
        "/" + os.path.relpath(os.path.join(d, n), root)
        for d, _, files in os.walk(root)
        for n in files
    )
    expected = sorted(
        seed
        + ["/outbox/files-sdk.txt", "/outbox/just-bash.txt", "/outbox/mastra.txt", "/outbox/ai-sdk.txt"]
        + ["/uploads/" + n for n in uploads]
    )
    check("the export holds exactly the seed files plus the demo's writes", now == expected, f"{len(now)} files")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
