# shell-bucket

Generic tty wrapper with in-band PTY multiplexing -- wraps any tty tool (ssh,
aws ecs execute-command, docker exec, bash, screen, ...) and brings the user's
tooling up over it. Two halves that talk to each other over the byte stream: the
Python wrapper (`src/shell_bucket/`) and the native V `sb` binary
(`native/sb/src/main.v`). Both are production code.

## Source conventions

- **ASCII only.** No non-ASCII anywhere in `.v`, `.py`, or `.sh` -- not even in
  comments. Use `->` `<-` `<->` `=>` for arrows, `--` for em dashes, `>=` `<=`
  `!=` for comparisons, `...` for ellipsis, `*` or `|` for bullets/separators.
  Non-ASCII comment bytes (multi-byte UTF-8) are the main thing that breaks the
  Edit tool's exact-match, and string-literal unicode ships in the wire-shipped
  binary. The repo is ASCII-clean; keep it that way.
- **`main.v` is tab-indented and must stay `v fmt`-clean.** V is a tabs language
  by toolchain decree (like Go): `v fmt` has no space option and ignores
  `.editorconfig` -- it rewrites spaces back to tabs. Run `v fmt -w
  native/sb/src/main.v` after editing and before committing.
- Python is space-indented (PEP8). Shell uses tabs.
- No trailing whitespace in any source file.

## Editing main.v (and any tab-indented file)

The Edit tool matches `old_string` byte-for-byte and is language-agnostic (there
is no per-language "mode"). It edits tab-indented V exactly like tab-indented Go
-- smoothly, IF the tabs in `old_string` are reproduced faithfully. To make that
reliable:

1. **Copy indentation verbatim from the Read output** -- tabs and all. Do not
   retype leading whitespace from memory; that is what injects spaces where the
   file has tabs and makes the match fail.
2. **Anchor on the smallest unique span** -- often a single unique line -- rather
   than pasting a large indented block. Smaller match surface, fewer ways to
   mismatch.
3. **`v fmt -w` after the edit** normalizes any alignment drift, so "looks right"
   and "is canonical" converge.

Do NOT reach for Python/sed splices to work around a failed Edit. They bypass the
tool's safety checks, add ad-hoc throwaway code, and are more error-prone than a
correct byte-exact Edit. Reserve scripted edits for genuine bulk transforms across
many files (e.g. a tree-wide scrub), never for a single-site code edit.

## Build & test

- Production binary: `native/sb/build.sh` -> `dist/` (stripped, no `__xxx` test
  hooks; `-d sb_test` is omitted so `-skip-unused` + `--gc-sections` drop them).
  Every byte ships over the wire -- keep non-production code out of it.
- Instrumented binary + V self-tests: `native/sb/check.sh` -> `dist-test/` (with
  `-d sb_test -g`). The integration tests drive `__xxx` hooks, so they require
  `dist-test/`, not `dist/`.
- V self-tests live in `native/sb/test/*.sh` (run inside Docker by `check.sh`).
- Python: `.venv/bin/pytest -q` (unit); `-m integration` for the Docker-backed
  end-to-end suite.
