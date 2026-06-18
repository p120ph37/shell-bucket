"""CLI entrypoint for shell-bucket."""

from __future__ import annotations

import asyncio
import base64
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import asyncssh
import click

from shell_bucket.config import ClipConfig, TmuxConfig, bucket_dir, known_hosts_path
from shell_bucket.file_delivery import Bucket
from shell_bucket.known_hosts import TOFUStore
from shell_bucket.tmux_fetch import DEFAULT_SOURCE as TMUX_DEFAULT_SOURCE
from shell_bucket.tmux_fetch import PLATFORMS as TMUX_PLATFORMS
from shell_bucket.tmux_fetch import fetch_tmux
from shell_bucket.wrapper import build_connect_kwargs, run_session


@dataclass(frozen=True)
class Destination:
    user: str
    host: str
    path: str | None = None  # populated by parse_download_spec


def parse_destination(spec: str) -> Destination:
    """Parse `user@host`. Raises click.UsageError on malformed input."""
    user, sep, host = spec.partition("@")
    if not sep or not user or not host:
        raise click.UsageError(
            "Destination must be in user@host form (non-empty user and host)."
        )
    return Destination(user=user, host=host)


def parse_download_spec(spec: str) -> Destination:
    """Parse `user@host:/path/to/file` into user, host, and path."""
    user_at_host, sep, path = spec.partition(":")
    if not sep or not path:
        raise click.UsageError(
            "Download spec must be user@host:/path/to/file (host and path required)."
        )
    dest = parse_destination(user_at_host)
    return Destination(user=dest.user, host=dest.host, path=path)


def _read_password() -> str:
    line = sys.stdin.readline()
    if not line:
        raise click.UsageError("--password-on-stdin set but stdin was empty.")
    return line.rstrip("\n")


# ─── shared options ────────────────────────────────────────────────────────


def _auth_options(f):
    """Decorator: --password-on-stdin and --identity-file (mutually exclusive)."""
    f = click.option(
        "--password-on-stdin",
        is_flag=True,
        help="Read one newline-terminated line from stdin as the password.",
    )(f)
    f = click.option(
        "--identity-file",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        metavar="PATH",
        help="Use SSH private key (alternative to --password-on-stdin).",
    )(f)
    return f


def _validate_auth(password_on_stdin: bool, identity_file: Path | None) -> None:
    if password_on_stdin and identity_file is not None:
        raise click.UsageError(
            "Specify exactly one of --password-on-stdin or --identity-file, not both."
        )
    if not password_on_stdin and identity_file is None:
        raise click.UsageError(
            "Specify one of --password-on-stdin or --identity-file."
        )


# ─── group + commands ──────────────────────────────────────────────────────


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """shell-bucket — SSH wrapper with iTerm2 integration and lazy helper delivery."""


@cli.command(
    help="Connect to user@host with our injection (RC + lazy helpers + sb propagation)."
)
@click.argument("destination", metavar="USER@HOST")
@_auth_options
@click.option(
    "--no-known-hosts",
    is_flag=True,
    help="Skip host-key verification entirely (for VPN-only ephemeral hosts).",
)
@click.option(
    "--tmux",
    "tmux_session",
    metavar="SESSION",
    help="Launch remote in `tmux new -A -s SESSION` after RC injection. "
    "Requires tmux 3.3+ on the remote for APC passthrough.",
)
@click.option(
    "--shell",
    "shell",
    default="bash",
    metavar="SHELL",
    help="Login shell to launch (name or path; default bash). "
    "ksh/zsh are supported up to the fetch layer only.",
)
def connect(
    destination: str,
    password_on_stdin: bool,
    identity_file: Path | None,
    no_known_hosts: bool,
    tmux_session: str | None,
    shell: str,
) -> None:
    _validate_auth(password_on_stdin, identity_file)
    dest = parse_destination(destination)
    password = _read_password() if password_on_stdin else None

    store: TOFUStore | None = (
        None if no_known_hosts else TOFUStore(known_hosts_path())
    )
    try:
        rc = asyncio.run(
            run_session(
                user=dest.user,
                host=dest.host,
                password=password,
                identity_file=identity_file,
                store=store,
                bucket=Bucket(bucket_dir()),
                shell=shell,
                tmux_session=tmux_session,
                tmux_config=TmuxConfig.from_config(),
                clip_config=ClipConfig.from_config(),
            )
        )
    except asyncssh.PermissionDenied as e:
        click.echo(f"shell-bucket: authentication failed: {e}", err=True)
        sys.exit(1)
    except (asyncssh.HostKeyError, asyncssh.DisconnectError, OSError) as e:
        click.echo(f"shell-bucket: connection failed: {e}", err=True)
        sys.exit(1)

    sys.exit(rc)


# ─── download ──────────────────────────────────────────────────────────────


def _iterm_inline_image(name: str, data: bytes) -> bytes:
    """OSC 1337 File= sequence for iTerm2 inline image display."""
    name_b64 = base64.b64encode(name.encode("utf-8")).decode("ascii")
    data_b64 = base64.b64encode(data).decode("ascii")
    return (
        f"\033]1337;File=name={name_b64};size={len(data)};inline=1:{data_b64}\007"
    ).encode("ascii")


_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".tif", ".svg"}


async def _download(
    dest: Destination,
    out_path: Path,
    password: str | None,
    identity_file: Path | None,
    store: TOFUStore | None,
) -> tuple[Path, int]:
    kwargs = build_connect_kwargs(
        host=dest.host,
        user=dest.user,
        password=password,
        identity_file=identity_file,
        store=store,
    )
    async with asyncssh.connect(**kwargs) as conn:
        # SFTP is the right hammer — handles binary cleanly, no pty echo issues.
        async with conn.start_sftp_client() as sftp:
            await sftp.get(dest.path, str(out_path))
    return out_path, out_path.stat().st_size


@cli.command(
    help=(
        "Download user@host:/remote/path locally. Designed for iTerm2's Semantic "
        "History (cmd+click) over an existing connection's hosts. In iTerm2, "
        "image files are also displayed inline; in other terminals only the "
        "local save path is printed."
    )
)
@click.argument("remote_spec", metavar="USER@HOST:REMOTE_PATH")
@_auth_options
@click.option(
    "--no-known-hosts",
    is_flag=True,
    help="Skip host-key verification entirely.",
)
@click.option(
    "-o",
    "--output",
    "output",
    type=click.Path(dir_okay=False, path_type=Path),
    metavar="PATH",
    help="Local save path (default: ~/Downloads/<basename>).",
)
def download(
    remote_spec: str,
    password_on_stdin: bool,
    identity_file: Path | None,
    no_known_hosts: bool,
    output: Path | None,
) -> None:
    _validate_auth(password_on_stdin, identity_file)
    dest = parse_download_spec(remote_spec)
    password = _read_password() if password_on_stdin else None
    store = None if no_known_hosts else TOFUStore(known_hosts_path())

    out_path = output if output is not None else (
        Path.home() / "Downloads" / Path(dest.path).name
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        local_path, size = asyncio.run(
            _download(dest, out_path, password, identity_file, store)
        )
    except asyncssh.PermissionDenied as e:
        click.echo(f"shell-bucket: authentication failed: {e}", err=True)
        sys.exit(1)
    except (asyncssh.HostKeyError, asyncssh.DisconnectError, OSError) as e:
        click.echo(f"shell-bucket: download failed: {e}", err=True)
        sys.exit(1)

    click.echo(f"shell-bucket: saved {size} bytes → {local_path}")

    # iTerm2-only enhancement: inline-display images. Guarded so it never
    # breaks or interferes with other terminals (or with a tmux/screen session
    # whose host iTerm isn't reachable through).
    if (
        os.environ.get("TERM_PROGRAM") == "iTerm.app"
        and "TMUX" not in os.environ
        and local_path.suffix.lower() in _IMAGE_EXTS
    ):
        sys.stdout.buffer.write(_iterm_inline_image(local_path.name, local_path.read_bytes()))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()


# ─── fetch-tmux ─────────────────────────────────────────────────────────────


@cli.command(
    name="fetch-tmux",
    help=(
        "Populate the bucket with upstream static tmux binaries (from "
        "tmux/tmux-builds) for in-band delivery to remotes that lack tmux. "
        "Run on the wrapper host. Fetches all platforms at the latest release "
        "by default."
    ),
)
@click.option(
    "--version",
    "version",
    metavar="TAG",
    help="Release tag to fetch (e.g. v3.6b). Default: the source's latest.",
)
@click.option(
    "--platform",
    "platforms",
    metavar="PLATFORM",
    multiple=True,
    type=click.Choice(list(TMUX_PLATFORMS)),
    help="Platform(s) to fetch (repeatable). Default: all.",
)
@click.option(
    "--source",
    "source",
    metavar="OWNER/REPO",
    default=TMUX_DEFAULT_SOURCE,
    show_default=True,
    help="GitHub owner/repo publishing the release tarballs.",
)
def fetch_tmux_cmd(version: str | None, platforms: tuple[str, ...], source: str) -> None:
    bucket = bucket_dir()
    bucket.mkdir(parents=True, exist_ok=True)
    try:
        installed = fetch_tmux(
            bucket,
            version=version,
            platforms=list(platforms) or None,
            source=source,
        )
    except (OSError, ValueError) as e:
        click.echo(f"shell-bucket: fetch-tmux failed: {e}", err=True)
        sys.exit(1)
    for platform, path in installed:
        click.echo(f"shell-bucket: {platform} → {path}")


if __name__ == "__main__":
    cli()
