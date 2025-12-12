# rsyslog-splunk-plugin

rsyslog output module for Splunk using the native Splunk-to-Splunk (S2S) protocol with TLS support.

Protocol implementation based on [go-s2s](https://github.com/mikedickey/go-s2s).

## Build & Install

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install gcc cmake libssl-dev libjson-c-dev

# RHEL/CentOS/Fedora
sudo dnf install gcc cmake openssl-devel json-c-devel
```

### Build

```bash
mkdir build && cd build
cmake ..
make
sudo make install
```

## Configuration

### Basic Usage

```conf
module(load="omsplunks2s")

action(
    type="omsplunks2s"
    target="splunk.example.com"
    port="9997"
)
```

### With TLS (Recommended)

```conf
module(load="omsplunks2s")

action(
    type="omsplunks2s"
    target="splunk.example.com"
    port="9997"
    tls="on"
    tls.verify="off"
)
```

### With Mutual TLS

```conf
action(
    type="omsplunks2s"
    target="splunk.example.com"
    port="9997"
    tls="on"
    tls.cacert="/etc/rsyslog/ca.pem"
    tls.cert="/etc/rsyslog/client-cert.pem"
    tls.key="/etc/rsyslog/client-key.pem"
)
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `target`  | Yes      | -       | Splunk server hostname/IP |
| `port` | No | `9997` | Splunk S2S port |
| `tls` | No | `off` | Enable TLS encryption |
| `tls.cacert` | No | - | CA certificate path |
| `tls.cert` | No | - | Client certificate path |
| `tls.key` | No | - | Client private key path |

## Testing

```bash
# Restart rsyslog
sudo systemctl restart rsyslog

# Send test message
logger "Test message to Splunk"

# Verify configuration
sudo rsyslogd -N1
```

## Build Options

```bash
cmake -DBUILD_RSYSLOG_PLUGIN=ON \
      -DENABLE_TLS=ON \
      -DRSYSLOG_MODDIR=/custom/path \
      ..
```

- `BUILD_RSYSLOG_PLUGIN` - Build plugin (default: ON)
- `ENABLE_TLS` - Enable TLS (default: ON)
- `BUILD_TESTS` - Build tests (default: OFF)
- `RSYSLOG_MODDIR` - Custom install directory

## License

MIT
