# Dashboard Screenshot Generator

Generates screenshots of the Airut dashboard for documentation. Starts a
dashboard server populated with rich mock data, then uses Playwright to capture
each page in both light and dark color schemes. ImageMagick downscales the raw
captures to final sizes.

## Output

Each page is captured at 2x resolution (2560x1800) and downscaled to:

- **Main** — 1280x900 (`{page}-{scheme}.png`)
- **Thumbnail** — 320x225 (`{page}-{scheme}-thumb.png`)

An `index.html` linking all screenshots is also generated.

## Prerequisites

### System dependencies

- **Chromium system libraries** — libnspr4, libnss3, libatk, libdbus, libgbm,
  libxkbcommon, libasound2, and others required by Playwright's Chromium binary
- **ImageMagick** — `magick` (v7) or `convert` (v6) for downscaling

On Ubuntu/Debian, install everything with:

```bash
# Chromium dependencies (what `playwright install-deps chromium` installs)
apt-get install -y libnss3 libnspr4 libatk1.0-0t64 libatk-bridge2.0-0t64 \
    libatspi2.0-0t64 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libxkbcommon0 libasound2t64 libdbus-1-3

# ImageMagick
apt-get install -y imagemagick
```

### Python dependencies

The `screenshots/` directory is a standalone uv project that depends on the
`airut` package (via path reference) and `playwright`:

```bash
uv sync --project screenshots
```

### Playwright browser

After syncing, install the Chromium browser binary:

```bash
uv run --project screenshots playwright install chromium
```

This downloads from `cdn.playwright.dev` and
`storage.googleapis.com/chrome-for-testing-public/*`, both of which are in the
network allowlist.

## Usage

Run from the repository root:

```bash
# Generate all pages in both light and dark schemes
uv run --project screenshots python screenshots/generate.py

# Verbose output
uv run --project screenshots python screenshots/generate.py -v

# Custom output directory
uv run --project screenshots python screenshots/generate.py --output /tmp/shots

# Single color scheme
uv run --project screenshots python screenshots/generate.py --scheme dark

# Single page
uv run --project screenshots python screenshots/generate.py --page dashboard

# Combine options
uv run --project screenshots python screenshots/generate.py --scheme light --page task-executing -v
```

### Available pages

| Name               | URL pattern                                           |
| ------------------ | ----------------------------------------------------- |
| `dashboard`        | `/`                                                   |
| `task-executing`   | `/task/{executing_task}`                              |
| `task-completed`   | `/task/{completed_task}`                              |
| `conversation`     | `/conversation/{completed_conv}`                      |
| `repo-live`        | `/repo/{live_repo}`                                   |
| `repo-failed`      | `/repo/{failed_repo}`                                 |
| `actions`          | `/conversation/{executing_conv}/actions`              |
| `network`          | `/conversation/{executing_conv}/network`              |
| `config-global`    | `/config`                                             |
| `config-repo`      | `/config/repos/{config_repo}`                         |
| `config-schedules` | `/config/repos/{config_repo}` (scrolled to schedules) |

Output goes to `screenshots/output/` by default (gitignored).

## Running in the Airut sandbox

The sandbox container runs as root with a minimal capability set (`CHOWN`,
`DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`). Standard tools like `apt-get` and
`npm` work without special workarounds.

### Step-by-step

```bash
# 1. Install system dependencies
apt-get update
apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0t64 libatk-bridge2.0-0t64 \
    libatspi2.0-0t64 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libxkbcommon0 libasound2t64 libdbus-1-3 \
    imagemagick

# 2. Install Playwright browser (downloads ~280 MiB)
uv run --project screenshots playwright install chromium

# 3. Generate screenshots
uv run --project screenshots python screenshots/generate.py -v
```

The network allowlist already permits the required domains:

- `cdn.playwright.dev` — browser download index and CDN fallback
- `storage.googleapis.com/chrome-for-testing-public/*` — Chromium binaries
- `archive.ubuntu.com/ubuntu/*` and `security.ubuntu.com/ubuntu/*` — apt repos

### Alternative: bake dependencies into the container image

To avoid installing at runtime, add the system dependencies to
`.airut/container/Dockerfile`:

```dockerfile
# Add after the existing apt-get install block:
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libnss3 libnspr4 libatk1.0-0t64 libatk-bridge2.0-0t64 \
        libatspi2.0-0t64 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
        libgbm1 libxkbcommon0 libasound2t64 libdbus-1-3 \
        imagemagick \
    && rm -rf /var/lib/apt/lists/*
```

Then only steps 2 and 3 above are needed inside the sandbox.

## How it works

1. `create_mock_dashboard()` in `mock_data.py` builds a `DashboardServer` with
   realistic task, repo, conversation, and config data covering all visual
   states (queued, executing, completed, failed, unauthorized, timed out).

2. `generate.py` starts this mock server on a random port, then iterates over
   each page/scheme combination using Playwright's Chromium in headless mode.

3. Screenshots are captured at 2x device scale (2560x1800), then ImageMagick
   downscales them to main (1280x900) and thumbnail (320x225) sizes using
   Lanczos filtering.

4. Dimension verification catches any resolution mismatches, and an `index.html`
   index file is generated for easy browsing.
