# Media Intake & Security Toolkit

Small, read-only Linux tools for reviewing completed downloads before a
separately approved Jellyfin import. Generalized from the inspection, piece
verification and antivirus-coverage helpers used in a personal media homelab.

| Command | Checks |
| --- | --- |
| `inspect` | File magic against supported extensions; optional FFprobe stream/duration checks; rejects symlinks, special files and unexpected sidecars. |
| `verify` | Streams BitTorrent v1 SHA-1 pieces across exact files using a supplied JSON manifest; detects missing files, length differences and mismatched pieces. |
| `coverage` | Calculates union coverage from reported scan windows; excludes failed/unknown windows and avoids counting overlaps twice. |

Reports use numeric item IDs and fixed findings. They omit filenames, source
paths, media hashes, raw probe metadata, account data and tool stderr.
The commands never move, delete, execute or extract payloads, contact Jellyfin,
fetch torrents, change network controls or authorize a library release.

## Try the synthetic examples

Python 3.10+ on Linux is sufficient for integrity, coverage and tests:

```sh
python3 intake.py verify --completed-root examples/payload --completion-confirmed --manifest examples/manifest.json
python3 intake.py coverage examples/scan-windows.json
python3 -m unittest discover -s tests -q
```

The payload is two short, fictional text files. The overlapping scan-window
record is invented; no antivirus scan of those files is implied.

To inspect a selected item, first independently confirm download completion:

```sh
python3 intake.py inspect --completed-root /path/to/selected-completed-item --completion-confirmed
```

Inspection uses `file`; media probing also needs `ffprobe`. Missing tools,
implausible streams, embedded attachments/data or type mismatches require review.
Supported types are MKV, MP4, WAV, MP3, FLAC, SRT and plain-text NFO. Other types
are held for review, including archives, scripts and installers. Run inspection
tools maintained and contained; parsing hostile input still carries risk.

## Interpreting results

- **Integrity is not source trust.** The JSON manifest carries exact relative
  paths, lengths, a piece length and ordered 40-character SHA-1 hashes extracted
  separately from trusted v1 metadata. V2/hybrid torrents and incomplete
  boundary caches are not supported. Missing files never become a partial pass.
- **Coverage is not a clean scan.** `coverage` evaluates supplied records; it
  does not launch antivirus or prove that the scanner analyzed every byte.
  Even full raw-window coverage cannot establish whole-container analysis or
  whole-file signature matching. Inspect scanner limits, errors and database
  freshness separately. No result guarantees malware-free content.
- **Completion is an external check.** The required flag records the operator's
  assertion; the toolkit does not query a download client. Exit zero means the
  selected check succeeded, never permission to import.

Release remains a separate reviewed step: inspect the complete selected item,
resolve conflicts, complete antivirus review, preserve `noexec,nosuid,nodev`
and read-only Jellyfin media mounts, copy/move only approved files and expected
sidecars, then refresh and verify indexing. The companion
[Media Server Homelab](https://github.com/5A-4D/media-server-homelab) has the full
operations runbooks.

## Portfolio scope

This is a one-time private snapshot, not an automatic publication of the working
scripts. The original helpers also handled network evidence, scanner processes,
private boundary caches and item-specific imports; those deployment-bound paths
and runtime records are excluded. This smaller port retains the core checks
with exact paths, anchored read-only file opens, conservative failures and
sanitized reports. It includes no real media, torrents, receipts or credentials.

Original helper files and the live library remain unchanged. No automatic
synchronization or deployment is configured. No open-source license has been
selected for this private snapshot.
