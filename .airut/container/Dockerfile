FROM ubuntu:24.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    ca-certificates \
    ripgrep \
    librsvg2-bin \
    && rm -rf /var/lib/apt/lists/*

# Install GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y gh

# Install Claude Code
# NOTE: Run from a temp directory to work around OOM bug in installer when run
# as root during container build (https://github.com/anthropics/claude-code/issues/22536)
RUN mkdir /tmp/claude-install && cd /tmp/claude-install \
    && curl -fsSL https://claude.ai/install.sh | bash \
    && rm -rf /tmp/claude-install

# Add ~/.local/bin to PATH — Airut requires `claude` to be in PATH
# (also needed for `uv` below)
ENV PATH="/root/.local/bin:$PATH"

# Install uv (to ~/.local/bin)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Python 3.13 via uv
RUN uv python install 3.13

# Configure git with gh credential helper
# NOTE: Using COPY instead of heredoc because Podman's image builder
# incorrectly interprets lines starting with '[' as Dockerfile instructions
COPY gitconfig /root/.gitconfig

WORKDIR /workspace
