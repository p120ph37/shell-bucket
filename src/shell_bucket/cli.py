"""CLI entrypoint for shell-bucket."""

from __future__ import annotations

import asyncio
import sys

import click

from shell_bucket.config import ClipConfig, TmuxConfig, bucket_dir
from shell_bucket.file_delivery import Bucket
from shell_bucket.tmux_fetch import DEFAULT_SOURCE as TMUX_DEFAULT_SOURCE
from shell_bucket.tmux_fetch import PLATFORMS as TMUX_PLATFORMS
from shell_bucket.tmux_fetch import fetch_tmux
from shell_bucket.transport import CommandTransport
from shell_bucket.wrapper import run_session


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """shell-bucket — wrap any tty tool with lazy helper delivery + iTerm2 integration."""


# ─── wrap ────────────────────────────────────────────────────────────────────


@cli.command(
    context_settings={"ignore_unknown_options": True},
    help=(
        "Wrap any tty tool to bring your tooling into the session "
        "(RC + lazy helpers + sb propagation).\n\n"
        "The tool is whatever gives you a shell over a terminal — ssh, "
        "aws ecs execute-command, docker exec -it, bash, screen, … — given after `--`:\n\n"
        "\b\n"
        "  shell-bucket wrap -- ssh user@host\n"
        "  shell-bucket wrap -- aws ecs execute-command --cluster c --command /bin/bash …\n"
        "  shell-bucket wrap -- bash\n"
        "\n"
        "Authentication and host-key handling are the tool's own concern; the wrapper "
        "assumes the command lands you in a shell with no interactive preamble."
    ),
)
@click.option(
    "--tmux",
    "tmux_session",
    metavar="SESSION",
    help="Launch the remote in `tmux new -A -s SESSION` after RC setup. "
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
@click.argument("command", metavar="-- COMMAND [ARGS...]", nargs=-1, type=click.UNPROCESSED)
def wrap(tmux_session: str | None, shell: str, command: tuple[str, ...]) -> None:
    argv = list(command)
    if not argv:
        raise click.UsageError(
            "Provide a command to wrap, e.g. `shell-bucket wrap -- ssh user@host`."
        )

    transport = CommandTransport(argv)
    try:
        rc = asyncio.run(
            run_session(
                transport,
                bucket=Bucket(bucket_dir()),
                shell=shell,
                tmux_session=tmux_session,
                tmux_config=TmuxConfig.from_config(),
                clip_config=ClipConfig.from_config(),
            )
        )
    except OSError as e:
        click.echo(f"shell-bucket: could not run {argv[0]!r}: {e}", err=True)
        sys.exit(1)

    sys.exit(rc)


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
