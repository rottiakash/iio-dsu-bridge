# iio-dsu-bridge

iio-dsu-bridge turns Industrial I/O (IIO) IMU data from the ROG Ally into [DSU](https://cemuhook.sshnuke.net/) packets so motion-enabled Switch/WiiU emulators can consume Ally gyro and accelerometer events. It runs as a user-level systemd service on SteamOS, streaming motion telemetry to Ryujinx, Yuzu, Cemu, and any other DSU-compatible client.

## About This Fork
- Upstream project: [Sebalvarez97/iio-dsu-bridge](https://github.com/Sebalvarez97/iio-dsu-bridge).
- This fork lives at [rottiakash/iio-dsu-bridge](https://github.com/rottiakash/iio-dsu-bridge) and focuses on:
	- Correcting pitch/yaw orientation for ROG Ally motion in Ryujinx and Cemuhook-compatible clients.
	- Updating installers to fetch release assets from this fork.
	- Expanded documentation covering cross-compilation, manual deployment, and troubleshooting.
- Expect periodic merges from upstream; noteworthy fork-specific changes are tagged in release notes.

## What It Does
- Reads gyro and accelerometer values from `/sys/bus/iio/devices/*` on SteamOS.
- Applies a configurable mount matrix so the Ally’s physical orientation matches game expectations.
- Serves DSU packets over UDP slot 0, compatible with Cemuhook protocol consumers.
- Provides ready-made install/uninstall desktop shortcuts for Steam Deck UI and a scriptable installer for advanced setups.

## Requirements
- SteamOS 3.x or another Linux distribution with systemd --user support.
- A device exposing motion sensors through the Linux IIO subsystem (tested on ASUS ROG Ally).
- DSU-capable client (Ryujinx, Yuzu, Cemu, etc.) running on the same network.

## Quick Start (SteamOS Desktop Mode)
1. Grab the assets from the [latest release](https://github.com/rottiakash/iio-dsu-bridge/releases/latest).
2. Right-click `install-iio-dsu-bridge.desktop` in Dolphin → **Allow Launching**.
3. Double-click the shortcut; a terminal downloads the latest binary and registers the service.
4. In your emulator, add a DSU client pointing to the Ally/Deck IP (`127.0.0.1:26760` when local).

View live logs with:

```
journalctl --user -u iio-dsu-bridge -f
```

## Installation Options

### Desktop Shortcut (Recommended)
- Provides one-click install with progress messages.
- Downloads `install.sh` and the binary from the release page and sets up the systemd unit.

### Manual Install
1. Copy the `iio-dsu-bridge` binary to `~/.local/bin/iio-dsu-bridge` and make it executable.
2. Place the following unit at `~/.config/systemd/user/iio-dsu-bridge.service`:

	 ```
	 [Unit]
	 Description=IIO -> DSU Bridge (ROG Ally)
	 After=network.target

	 [Service]
	 ExecStart=%h/.local/bin/iio-dsu-bridge -rate=250 -addr=127.0.0.1:26760
	 Restart=on-failure

	 [Install]
	 WantedBy=default.target
	 ```

3. Reload systemd and start the service:

	 ```
	 systemctl --user daemon-reload
	 systemctl --user enable --now iio-dsu-bridge.service
	 ```

## Updating
Re-run the install desktop shortcut or re-copy your compiled binary, then restart the service:

```
systemctl --user restart iio-dsu-bridge.service
```

## Uninstall
- Download `uninstall-iio-dsu-bridge.desktop` from the [latest release](https://github.com/rottiakash/iio-dsu-bridge/releases/latest) and double-click it **or** run:

	```
	systemctl --user disable --now iio-dsu-bridge.service
	rm -f ~/.config/systemd/user/iio-dsu-bridge.service
	rm -f ~/.local/bin/iio-dsu-bridge
	systemctl --user daemon-reload
	```

## Configuration
- Optional YAML config: `~/.config/iio-dsu-bridge.yaml`

	```yaml
	iio_path: /sys/bus/iio/devices/iio:device0
	addr: 127.0.0.1:26760
	rate: 250
	log_every: 25
	mount_matrix:
		x: [1, 0, 0]
		y: [0, -1, 0]
		z: [0, 0, -1]
	```

- Environment variables override YAML values (for example `IIO_DSU_RATE=200`).
- Command-line flags override both when running manually (see `--help`).

## Building From Source

### Cross-compiling on macOS (Apple Silicon)

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/iio-dsu-bridge-linux-amd64 .
```

### Building on SteamOS/Linux

```
go build -o build/iio-dsu-bridge .
```

Copy the resulting binary to `~/.local/bin/iio-dsu-bridge` on the target device and restart the service:

```
systemctl --user daemon-reload
systemctl --user restart iio-dsu-bridge.service
```

## Troubleshooting
- **Service will not start:** check `journalctl --user -u iio-dsu-bridge` for missing IIO paths or permission errors.
- **No motion detected in emulator:** confirm the DSU client points to the Ally IP and port `26760`. Use `netstat -anu | grep 26760` to ensure the server is listening.
- **Axes feel inverted:** adjust the `mount_matrix` in the YAML config and restart the service.
- **SSH/SCP deployment:** enable `sshd` (`sudo systemctl enable --now sshd`) on SteamOS to transfer binaries from another machine.
