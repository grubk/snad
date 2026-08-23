# snad <sub><img width="35" height="35" alt="Snad Block" src="https://github.com/user-attachments/assets/922457ae-13a3-4322-af56-c80b95cb34f5" /></sub>

Send files to other devices over your local network peer-to-peer through a TUI interface.
Running this in a directory discovers other instances from other devices on your local network.
Pick a device and send files directly through an authenticated and encrypted connection.

**Origin Story**

I wanted to build a local file transferring application. I planned for devices to discover each other
on something I originally called a "sandbox". I mistyped this as "snadbox". Instead of correcting the mistake,
I let the name of the project be "snad" as a shortened version of this feature.


**Benefits**

- Fully local. No server, no accounts, no internet required
- Encrypted.
- Fast. Type a couple of commands instead of going through an overcomplicated interface.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/grubk/snad/main/install.sh | sh
```

This downloads the latest release for your OS/architecture (Linux and macOS,
amd64/arm64) and installs it to `~/.local/bin` — no Go toolchain required.
Make sure that directory is on your `PATH` (the script tells you if it
isn't).

Prefer not to pipe a script into `sh`? Grab a binary directly from the
[releases page](https://github.com/grubk/snad/releases) instead.

## Usage

Run from any directory:

```sh
snad file1.txt file2.txt   # sender+receiver: offers these files to a picked peer
snad                        # receiver-only: just waits for incoming files
```

Every instance is always a receiver in the background, regardless of
whether you pass files — files received land in the directory `snad` was
launched from. Use the arrow keys (or `j`/`k`) to pick a discovered peer
and `enter` to send; `q` or `ctrl+c` to quit.

## How it works

- **Snadbox (Discover devices)**: An instance of snad announces itself every 2 seconds over UDP
  multicast (`224.0.0.250:9999`) with a unique identifier and unique nickname visible to peers on the network.
- **Transfer**: once you pick a peer, files stream over a direct TCP
  connection wrapped in TLS, with a SHA-256 checksum verified on both ends.

## Security model

`snad` is designed for a **trusted local network** (e.g. your home LAN),
not the open internet or an untrusted network. Specifically:

- **Identity is ephemeral and self-signed**: each process generates a fresh
  ECDSA P-256 keypair and self-signed certificate on startup — there is no
  certificate authority and no persisted identity across runs.
- **Discovery is authenticated**: every UDP announcement is signed by the
  sender's identity key and carries a monotonic sequence number, so a
  device on the network cannot forge announcements to impersonate an
  already-seen peer or forge a "goodbye" message to evict one, and cannot
  replay a captured message after the real peer re-announces.
- **Transfers use mutual TLS**: the sender pins the connection to the
  fingerprint it learned via discovery, and the receiver requires the
  sender's certificate to match a peer it has itself discovered — an
  unrelated device on the network cannot push files to a `snad` receiver.
- **Residual limitation — trust-on-first-use race**: because there's no
  pre-shared root of trust, the very _first_ time a given name is heard,
  whichever identity announces it first is trusted as that name for the
  rest of that process's runtime. This is an inherent property of pure
  TOFU (trust-on-first-use) systems; it's not something signed discovery
  can fix without a shared secret or CA.
- Received files are written with `0600` permissions.

## Development

```sh
go build ./...
go vet ./...
gofmt -l .          # should print nothing
go test ./... -race
```

Build a local binary with `go build -o snad .`.

### Cutting a release

Push a version tag and CI builds and publishes binaries automatically:

```sh
git tag v0.1.0
git push origin v0.1.0
```

This triggers `.github/workflows/release.yml`, which runs
[GoReleaser](https://goreleaser.com) (config in `.goreleaser.yaml`) to build
Linux/macOS binaries for amd64/arm64 and publish them as a GitHub Release.
