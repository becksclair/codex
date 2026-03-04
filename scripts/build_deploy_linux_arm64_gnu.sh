#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build and deploy codex-cli for aarch64-unknown-linux-gnu.

Usage:
  ./scripts/build_deploy_linux_arm64_gnu.sh [--host HOST] [--remote-bin PATH] [--aarch64-config PATH]

Options:
  --host HOST        SSH host to deploy to (default: orion)
  --remote-bin PATH  Remote install path (absolute, or relative to remote $HOME;
                     default: .local/bin/codex)
  --aarch64-config   Host path to tuned Cargo config for aarch64 Docker builds
                     (default: ~/.cargo/config.aarch64.toml)
  --release          Accepted for compatibility; this script always builds release.
  --debug            Unsupported; this script always builds release.
  -h, --help         Show this help text
EOF
}

host="orion"
remote_bin=".local/bin/codex"
aarch64_config="${AARCH64_CONFIG_PATH:-${HOME}/.cargo/config.aarch64.toml}"
# Override if needed, e.g.:
#   SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no"
: "${SSH_OPTS:=-o BatchMode=yes -o StrictHostKeyChecking=accept-new}"

read -r -a ssh_opts <<<"${SSH_OPTS}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --)
      shift
      continue
      ;;
    --host)
      host="${2:?missing value for --host}"
      shift 2
      ;;
    --remote-bin)
      remote_bin="${2:?missing value for --remote-bin}"
      shift 2
      ;;
    --aarch64-config)
      aarch64_config="${2:?missing value for --aarch64-config}"
      shift 2
      ;;
    --release)
      shift
      ;;
    --debug)
      echo "--debug is no longer supported; this script always builds release artifacts" >&2
      exit 1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "${remote_bin}" == *"'"* ]]; then
  echo "--remote-bin cannot contain single quotes" >&2
  exit 1
fi

if [[ "${aarch64_config}" == *"'"* ]]; then
  echo "--aarch64-config cannot contain single quotes" >&2
  exit 1
fi

if [[ ! -f "${aarch64_config}" ]]; then
  echo "aarch64 config file not found: ${aarch64_config}" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required but was not found in PATH" >&2
  exit 1
fi
if ! command -v ssh >/dev/null 2>&1; then
  echo "ssh is required but was not found in PATH" >&2
  exit 1
fi
if ! command -v scp >/dev/null 2>&1; then
  echo "scp is required but was not found in PATH" >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
target="aarch64-unknown-linux-gnu"
remote_tmp="/tmp/codex-${target}"
build_image="rustlang/rust:nightly-bookworm"
artifact="${repo_root}/codex-rs/target/${target}/release/codex"

echo "==> Building codex-cli for ${target} in a linux/amd64 nightly Bookworm container (release profile)"
docker run --rm \
  --platform linux/amd64 \
  -v "${repo_root}:/work" \
  -v "${aarch64_config}:/tmp/config.aarch64.toml:ro" \
  -w /work/codex-rs \
  "${build_image}" \
  bash -lc '
    set -euo pipefail
    # Official rust docker images expose cargo/rustup via this env file.
    source /usr/local/cargo/env
    export DEBIAN_FRONTEND=noninteractive
    dpkg --add-architecture arm64
    apt-get update
    apt-get install -y --no-install-recommends \
      gcc-aarch64-linux-gnu \
      g++-aarch64-linux-gnu \
      libc6-dev-arm64-cross \
      pkg-config \
      libssl-dev:arm64 \
      liblzma-dev:arm64 \
      libcap-dev:arm64 \
      libasound2-dev:arm64
    rustup target add --toolchain nightly aarch64-unknown-linux-gnu
    export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
    export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    export PKG_CONFIG_ALLOW_CROSS=1
    export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig
    cargo +nightly \
      --config /tmp/config.aarch64.toml \
      --config "target.aarch64-unknown-linux-gnu.linker=\"aarch64-linux-gnu-gcc\"" \
      build -p codex-cli --release --target aarch64-unknown-linux-gnu --bin codex
  '

if [[ ! -x "${artifact}" ]]; then
  echo "Expected build artifact is missing: ${artifact}" >&2
  exit 1
fi

echo "==> Copying binary to ${host}:${remote_tmp}"
scp "${ssh_opts[@]}" "${artifact}" "${host}:${remote_tmp}"

echo "==> Installing and verifying on ${host}"
ssh "${ssh_opts[@]}" "${host}" "set -euo pipefail; remote_bin='${remote_bin}'; if [[ \"\$remote_bin\" = /* ]]; then install_path=\"\$remote_bin\"; else install_path=\"\$HOME/\$remote_bin\"; fi; install -Dm755 '${remote_tmp}' \"\$install_path\"; rm -f '${remote_tmp}'; \"\$install_path\" --version"

echo "Done. ${remote_bin} is now updated on ${host}."
