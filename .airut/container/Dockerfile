FROM ubuntu:24.04

# Install system dependencies and GitHub CLI in a single layer.
# Merging these avoids a redundant apt-get update and reduces image layers.
RUN apt-get update \
    && apt-get install -y \
        curl \
        git \
        ca-certificates \
        ripgrep \
        librsvg2-bin \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# Add ~/.local/bin to PATH — uv installs here.
ENV PATH="/root/.local/bin:$PATH"

# /workspace is a host mount (ext4) while the uv cache lives on the container
# overlay filesystem.  Hardlinks cannot cross filesystem boundaries, so uv
# falls back to copies and prints a noisy warning on every invocation.
# Setting COPY mode up-front silences the warning.
ENV UV_LINK_MODE=copy

# Install uv and Python 3.13 in a single layer.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && uv python install 3.13

# Configure git with gh credential helper.
# NOTE: Using COPY instead of heredoc because Podman's image builder
# incorrectly interprets lines starting with '[' as Dockerfile instructions.
COPY gitconfig /root/.gitconfig

WORKDIR /workspace
