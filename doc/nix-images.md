# Nix-Based Container Images

A repository with a Nix flake can give Airut tasks exactly its development
shell: the same tools, at the same versions, as developers and CI use. This
guide shows how to build the repo image from the flake and lists the pitfalls
that are easy to miss.

Airut is Nix-agnostic; it provides the generic pieces this relies on:

- **CA trust without Debian tooling** -- `NIX_SSL_CERT_FILE` and
  `GIT_SSL_CAINFO` point at the network sandbox's CA, and the system bundle is
  extended even without `update-ca-certificates`
  ([network-sandbox.md](../spec/network-sandbox.md#ca-certificate-trust)).
- **The environment hook** -- `/etc/airut/env.sh`, loaded before every task
  ([image.md](../spec/image.md#environment-hook)). The image captures the
  devShell there with `nix print-dev-env`.
- **Symlinks in the build context** -- `.airut/container/flake.nix` can link to
  the repository's flake, so the image follows `flake.lock`
  ([image.md](../spec/image.md#file-locations)).

The image itself has to supply what Airut cannot: the dynamic loader for the
Claude Code binary, `gh`, and a few paths tools expect
([Image Requirements](../spec/image.md#image-requirements)).

## Recipe

Link the flake into the build context (and any local files it imports, e.g. a
`nix/` directory):

```bash
ln -s ../../flake.nix .airut/container/flake.nix
ln -s ../../flake.lock .airut/container/flake.lock
```

`.airut/container/Dockerfile`:

```dockerfile
# Pin Nix by digest. The tag's digest is a multi-arch manifest list. Use the
# fully qualified name: rootless podman's short-name resolution varies.
FROM docker.io/nixos/nix:<version>@sha256:<digest>

# /etc/nix/nix.conf is a link into the read-only store: replace it with a copy
# rather than appending through the link. The image already sets
# sandbox = false (a container cannot use Nix's build sandbox).
RUN cat /etc/nix/nix.conf > /etc/nix/nix.conf.new \
    && printf '%s\n' 'experimental-features = nix-command flakes' \
         'flake-registry = ' >> /etc/nix/nix.conf.new \
    && mv /etc/nix/nix.conf.new /etc/nix/nix.conf

WORKDIR /opt/flake
# Plus any linked directories the flake imports, e.g. COPY nix ./nix
COPY flake.nix flake.lock ./

# Fetch every flake input, so evaluating the flake in a task needs no network.
RUN nix flake archive

# The environment hook: the devShell, loaded before every task.
RUN mkdir -p /etc/airut && nix print-dev-env > /etc/airut/env.sh

# Only if agents are told to run `nix develop`: it also needs
# bash-interactive, which print-dev-env does not fetch.
RUN nix develop -c true

# Tools the agent needs that the devShell does not carry.
RUN nix profile add --inputs-from . nixpkgs#gh nixpkgs#ripgrep

# The glibc loader at its standard path, for the Claude Code binary Airut
# mounts and for prebuilt binaries such as manylinux wheels. Note glibc^out,
# and the --version call, which fails the build if the link dangles.
RUN nix build --inputs-from . 'nixpkgs#glibc^out' --out-link /opt/glibc \
    && mkdir -p /lib64 \
    && ln -s /opt/glibc/lib/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2 \
    && /lib64/ld-linux-x86-64.so.2 --version > /dev/null

# Parts of Claude Code run /bin/bash directly.
RUN ln -s /root/.nix-profile/bin/bash /bin/bash

COPY gitconfig /root/.gitconfig
WORKDIR /workspace
```

Older Nix releases call `nix profile add` `nix profile install`.

The onboarding gitconfig's `!gh auth git-credential` works as is (`gh` is on
`PATH`). A gitconfig that hard-codes `/usr/bin/gh` does not: there, use
`/root/.nix-profile/bin/gh`.

## Pitfalls

**`nix build nixpkgs#glibc` does not give you the loader.** `nix build` builds
the package's `outputsToInstall`, which for glibc is the `bin` output, and names
the link for a non-`out` output `<out-link>-bin`. `--out-link /opt/glibc` then
creates `/opt/glibc-bin`, `/opt/glibc` never exists, and `ln -s` happily creates
a dangling `/lib64/ld-linux-x86-64.so.2`. Every task then fails with
`cannot execute: required file not found` (the entrypoint adds that the loader
is missing), and prebuilt binaries fail the same way, e.g. `uv run ruff` with
`Failed to spawn`. Build `nixpkgs#glibc^out` and run the loader in the same
step, as in the recipe.

**`/etc/nix/nix.conf` is a symlink into the store.** Appending with `>>` as root
writes through it into a read-only store path. Nothing fails, but the store path
no longer matches its hash: `nix store verify` flags it and `nix store repair`
would silently drop the settings. Copy, append, and move the copy over the link.

**`flake-registry =` needs `--inputs-from .`.** An empty registry avoids
fetching the global registry and keeps `nixpkgs#...` on the flake's locked
nixpkgs, but every `nixpkgs#` reference then needs `--inputs-from .`.

**`print-dev-env` versus `nix develop`.** The hook alone gives tasks the
devShell: `nix print-dev-env` keeps the caller's `PATH` after the shell's, so
the base image's tools stay reachable. If the repository's instructions tell
agents to run `nix develop -c ...`, that also needs `bash-interactive`, which
`print-dev-env` does not fetch; without `RUN nix develop -c true` the first
`nix develop` in every task downloads it. The devShell's `shellHook` runs on
every task start, so keep it fast and offline.

**`nixos/nix` lacks `/bin/bash`, `gh` and `/lib64`.** It has `/bin/sh`,
`/usr/bin/env`, `/tmp`, and `bash`, `git` and `curl` in
`/root/.nix-profile/bin`, which covers the entrypoint, but not the `/bin/bash`
Claude Code expects (see
[Image Requirements](../spec/image.md#image-requirements)).

**Match the host's architecture.** The image works only on hosts whose system
the flake's devShell defines. An arm64 Airut host needs `aarch64-linux` in the
flake and the loader at `/lib/ld-linux-aarch64.so.1`.

**Tools that rewrite files can replace context symlinks.** A formatter that
rewrites `.airut/container/flake.nix` (`nixfmt` does) replaces the symlink with
a regular file: nothing fails, but the image silently stops following the flake.
Exclude the build context from formatter and linter file lists (e.g.
`':!:.airut/'` in a `git ls-files` pathspec).

## Network Allowlist

The image is built with the server's network, outside the sandbox, so the
allowlist only matters for what tasks fetch beyond the image: a devShell changed
on a branch, or a package the image does not hold. For those:

```yaml
url_prefixes:
  # Nix binary cache. Nix checks package signatures, so TLS interception by the
  # proxy does not weaken integrity.
  - host: cache.nixos.org
    path: ""
    methods: [GET, HEAD]
  # GitHub flake inputs, per input (owner/repo as in flake.lock; paths are
  # case-sensitive). Nix resolves branches through the API and downloads
  # tarballs, which redirect to codeload.github.com.
  - host: api.github.com
    path: /repos/NixOS/nixpkgs/*
    methods: [GET, HEAD]
  - host: codeload.github.com
    path: /NixOS/nixpkgs/*
    methods: [GET, HEAD]
```

With `flake-registry =` in `nix.conf`, Nix does not need `channels.nixos.org`.
The network log (`network-sandbox.log`, or `--network-log-live` with
`airut-sandbox`) shows the exact paths requested and any further blocked
requests.

## Rebuilds and Cost

Repo images are rebuilt with `--no-cache` once they are older than 24 hours. For
a Nix image that means downloading the whole closure again (nixpkgs source, the
devShell, glibc, ...), which takes minutes, and the first task after the image
expires waits for it. Unlike an apt-based image, a rebuild of an image pinned by
digest and `flake.lock` picks up nothing new; updates come from changing the
lock file, which rebuilds the image anyway.

## Trust

The image runs Nix with `sandbox = false`, and tasks evaluate the flake. Code
from the flake's inputs therefore runs in tasks outside any Nix build sandbox
(inside the container), and `nix print-dev-env` runs nixpkgs code during the
image build, which has the server's unrestricted network. A repository that
adopts this trusts its flake inputs as it would any build dependency; see
[security.md](security.md#container-image-build-isolation).

## Testing Before Merge

Test image changes on a branch with `airut-sandbox` before merging, as described
in
[Testing Image Changes Before Merge](repo-onboarding.md#testing-image-changes-before-merge).
