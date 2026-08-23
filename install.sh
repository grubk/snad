#!/bin/sh
# Installs the latest snad release for Linux/macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/grubk/snad/main/install.sh | sh
#
# Override the install directory with SNAD_INSTALL_DIR (default: ~/.local/bin).

set -eu

repo="grubk/snad"
install_dir="${SNAD_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
case "$os" in
	Linux) os="linux" ;;
	Darwin) os="darwin" ;;
	*)
		echo "snad: unsupported OS: $os (only Linux and macOS are supported)" >&2
		exit 1
		;;
esac

arch="$(uname -m)"
case "$arch" in
	x86_64 | amd64) arch="amd64" ;;
	arm64 | aarch64) arch="arm64" ;;
	*)
		echo "snad: unsupported architecture: $arch" >&2
		exit 1
		;;
esac

tag="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" |
	grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"

if [ -z "$tag" ]; then
	echo "snad: could not determine the latest release tag" >&2
	exit 1
fi

archive="snad_${os}_${arch}.tar.gz"
base_url="https://github.com/${repo}/releases/download/${tag}"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

echo "snad: downloading ${archive} (${tag})..."
curl -fsSL -o "${work_dir}/${archive}" "${base_url}/${archive}"
curl -fsSL -o "${work_dir}/checksums.txt" "${base_url}/checksums.txt"

echo "snad: verifying checksum..."
(
	cd "$work_dir"
	if command -v sha256sum >/dev/null 2>&1; then
		grep " ${archive}\$" checksums.txt | sha256sum -c -
	elif command -v shasum >/dev/null 2>&1; then
		grep " ${archive}\$" checksums.txt | shasum -a 256 -c -
	else
		echo "snad: no sha256sum or shasum found, skipping checksum verification" >&2
	fi
)

tar -xzf "${work_dir}/${archive}" -C "$work_dir" snad

mkdir -p "$install_dir"
mv "${work_dir}/snad" "${install_dir}/snad"
chmod +x "${install_dir}/snad"

echo "snad: installed to ${install_dir}/snad"

case ":$PATH:" in
	*":$install_dir:"*) ;;
	*)
		echo ""
		echo "warning: ${install_dir} is not on your PATH."
		echo "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
		echo ""
		echo "  export PATH=\"${install_dir}:\$PATH\""
		echo ""
		;;
esac
