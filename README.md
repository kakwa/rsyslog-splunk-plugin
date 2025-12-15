# rsyslog-splunk-plugin

rsyslog output module for Splunk using the native Splunk-to-Splunk (S2S) protocol with TLS support.

Protocol implementation based on [go-s2s](https://github.com/mikedickey/go-s2s) from mike [at] mikedickey.com.

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

### With TLS

```conf
module(load="omsplunks2s")

action(
    type="omsplunks2s"
    target="splunk.example.com"
    port="9997"
    tls="on"
    tls.verify="on"
)
```

### With Client Certificate TLS

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

```
Required:
  -H, --host=HOST          Splunk indexer hostname or IP

Optional:
  -p, --port=PORT          Splunk S2S port (default: 9997)
  -i, --index=INDEX        Target Splunk index
  -s, --source=SOURCE      Source field
  -t, --sourcetype=TYPE    Sourcetype field (default: syslog)
  -T, --tls                Enable TLS encryption
  -V, --tls-verify         Enable TLS certificate verification
      --tls-no-verify      Disable TLS certificate verification
      --ca-file=FILE       CA certificate file (PEM)
      --cert-file=FILE     Client certificate file (PEM)
      --key-file=FILE      Client private key file (PEM)
```

### Build CLI Only

```bash
mkdir build && cd build
cmake -DBUILD_RSYSLOG_PLUGIN=OFF -DBUILD_CLI=ON ..
make
sudo make install
```

## Testing

### Test rsyslog plugin

```bash
# Restart rsyslog
sudo systemctl restart rsyslog

# Send test message
logger "Test message to Splunk"

# Verify configuration
sudo rsyslogd -N1
```

### Test CLI utility

```bash
# Send test message
splunk-logger -H your-splunk-server.com "Test from CLI"
```

## Build Options

```bash
cmake -DBUILD_RSYSLOG_PLUGIN=ON \
      -DBUILD_CLI=ON \
      -DENABLE_TLS=ON \
      -DDEBUG=ON \
      -DRSYSLOG_MODDIR=/custom/path \
      ..
```

- `BUILD_RSYSLOG_PLUGIN` - Build rsyslog plugin (default: ON)
- `BUILD_CLI` - Build splunk-logger CLI utility (default: ON)
- `BUILD_S2S_LIB` - Build standalone S2S library (default: OFF)
- `ENABLE_TLS` - Enable TLS support (default: ON)
- `BUILD_TESTS` - Build test programs (default: OFF)
- `DEBUG` - Enable debug build with symbols (default: OFF)
- `RSYSLOG_MODDIR` - Custom rsyslog module install directory

## License

MIT
