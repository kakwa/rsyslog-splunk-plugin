# rsyslog-splunk-plugin

[![CI](https://github.com/kakwa/rsyslog-splunk-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/kakwa/rsyslog-splunk-plugin/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/kakwa/rsyslog-splunk-plugin/branch/main/graph/badge.svg)](https://codecov.io/gh/kakwa/rsyslog-splunk-plugin)

rsyslog output module for Splunk using the native Splunk-to-Splunk (S2S) protocol with TLS support.

Protocol implementation based on [go-s2s](https://github.com/mikedickey/go-s2s) from mike [at] mikedickey.com.

Also provides a single `logger`-style cli utility to push message in splunk on-demand.

# Disclaimer

This implementation is fairly limited (custom fields not working, no compression, partial s2s protocol support) and has been mostly vibe coded.

However, it's working, and is way simpler to deploy compared to the universal forwarder if you have basic needs.

# Build

## Build & Install

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install gcc cmake libssl-dev libjson-c-dev zlib1g-dev libestr-dev

# RHEL/CentOS/Fedora
sudo dnf install gcc cmake openssl-devel json-c-devel zlib-devel libestr-devel
```


### Build from Source

```bash
git clone https://github.com/kakwa/rsyslog-splunk-plugin
cd rsyslog-splunk-plugin
# Initialize git submodules (includes rsyslog headers)
git submodule update --init --recursive

# Build and install
cmake .
make
sudo make install
```

### Installation Locations

After installation, the following files are installed (Debian/Ubuntu, your location may vary):

```
/usr/lib/x86_64-linux-gnu/rsyslog/omsplunks2s.so   # rsyslog plugin module
/usr/bin/splunk-logger                             # CLI utility
```

## Configuration

### Basic Usage

```conf
module(load="omsplunks2s")

*.* action(
    type="omsplunks2s"
    server="splunk.example.com"
    port="9997"
)
```

### With TLS

```conf
module(load="omsplunks2s")

*.* action(
    type="omsplunks2s"
    server="splunk.example.com"
    port="9997"
    tls="on"
    tls.verify="on"
)
```

### With Client Certificate TLS

```conf
*.* action(
    type="omsplunks2s"
    server="splunk.example.com"
    port="9997"
    tls="on"
    tls.cacert="/etc/rsyslog/ca.pem"
    tls.cert="/etc/rsyslog/client-cert.pem"
    tls.key="/etc/rsyslog/client-key.pem"
)
```

### Complete Example with All Parameters

```conf
module(load="omsplunks2s")

*.* action(
    type="omsplunks2s"
    server="splunk.example.com"
    port="9998"
    index="momentum_dev"
    host="myhost.example.com"
    sourcetype="syslog"
    source="rsyslog"
    reconnect.interval="30"
    tls="on"
    tls.verify="off"
    tls.cacert="/etc/rsyslog/ca.pem"
    tls.cert="/etc/rsyslog/client-cert.pem"
    tls.key="/etc/rsyslog/client-key.pem"
)
```

### Parameters

| Parameter            | Required | Default         | Description                               |
|----------------------|----------|-----------------|-------------------------------------------|
| `server`             | Yes      | -               | Splunk server hostname/IP                 |
| `port`               | No       | `9997`          | Splunk S2S port                           |
| `index`              | No       | -               | Target Splunk index                       |
| `host`               | No       | System hostname | Host field for events in Splunk           |
| `source`             | No       | `rsyslog`       | Source field for events in Splunk         |
| `sourcetype`         | No       | `syslog`        | Sourcetype field for events in Splunk     |
| `reconnect.interval` | No       | `5`             | Reconnection interval in seconds          |
| `tls`                | No       | `off`           | Enable TLS encryption                     |
| `tls.verify`         | No       | `off`           | Enable TLS certificate verification       |
| `tls.cacert`         | No       | -               | CA certificate path (for verification)    |
| `tls.cert`           | No       | -               | Client certificate path (for mutual auth) |
| `tls.key`            | No       | -               | Client private key path (for mutual auth) |

## CLI Utility (splunk-logger)

A standalone command-line utility to send individual messages to Splunk, similar to the `logger` command.

### Basic Usage

```bash
# Send a simple message
splunk-logger -H splunk.example.com "Test message"

# Send with custom index and sourcetype
splunk-logger -H splunk.example.com -i main -t application "Application started"

# Send with TLS
splunk-logger -H splunk.example.com -T -V "Secure message"

# Read from stdin
echo "Log entry" | splunk-logger -H splunk.example.com
```

### CLI Options

```bash
Usage: splunk-logger [OPTIONS] <message>

Send a single message to Splunk indexer via S2S protocol.

Required:
  -H, --host=HOST          Splunk indexer hostname or IP

Optional:
  -p, --port=PORT          Splunk S2S port (default: 9997)
  -i, --index=INDEX        Target Splunk index
  -s, --source=SOURCE      Source field
  -t, --sourcetype=TYPE    Sourcetype field (default: syslog)
  -f, --field=KEY=VALUE    Add custom field (can be used multiple times)
  -T, --tls                Enable TLS encryption
  -V, --tls-verify         Enable TLS certificate verification
      --tls-no-verify      Disable TLS certificate verification
      --ca-file=FILE       CA certificate file (PEM)
      --cert-file=FILE     Client certificate file (PEM)
      --key-file=FILE      Client private key file (PEM)
  -h, --help               Show this help message

Examples:
  splunk-logger -H splunk.example.com "Test message"
  splunk-logger -H 192.168.1.100 -i main -t syslog "Error occurred"
  splunk-logger -H splunk.local -f severity=high -f app=myapp "Alert message"
  splunk-logger -H splunk.local -T -V --ca-file=/etc/ssl/ca.pem "Secure message"
  echo "Log entry" | splunk-logger -H splunk.local
```

## Misc

### Build Options

```bash
cmake -DBUILD_RSYSLOG_PLUGIN=ON \
      -DBUILD_CLI=ON \
      -DENABLE_TLS=ON \
      -DUSE_SYSTEM_RSYSLOG=OFF \
      -DDEBUG=ON \
      -DRSYSLOG_MODDIR=/custom/path \
      ..
```

- `BUILD_RSYSLOG_PLUGIN` - Build rsyslog plugin (default: ON)
- `BUILD_CLI` - Build splunk-logger CLI utility (default: ON)
- `BUILD_S2S_LIB` - Build standalone S2S library (default: OFF)
- `USE_SYSTEM_RSYSLOG` - Use system rsyslog headers instead of submodule (default: OFF)
- `RSYSLOG_VERSION` - Rsyslog version to use from submodule (default: v8.2504.0)
- `ENABLE_TLS` - Enable TLS support (default: ON)
- `BUILD_TESTS` - Build test programs (default: OFF)
- `DEBUG` - Enable debug build with symbols (default: OFF)
- `RSYSLOG_MODDIR` - Custom rsyslog module install directory

### Build Debian Package

To build a `.deb` package for Debian or Ubuntu:

```bash
# Install additional packaging dependencies
sudo apt-get install debhelper pbuilder

# Build package for Debian Trixie
cd pkg
make deb_chroot DIST=trixie

# Output packages will be in pkg/out/
# - rsyslog-splunk-plugin_*.deb (main package)
```

## License

MIT
