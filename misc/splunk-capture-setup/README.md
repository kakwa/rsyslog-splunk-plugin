# Local Splunk Lab for capturing S2S exchange

## Deploy

Q&D Splunk deploy for a server and forwarding instances
```bash
ansible-playbook splunk.yml
```

## Capture Steps

Start network capture:
```
tcpdump -i any port 9997 -w /tmp/crap.pcap
```

launch:
```
cd ~/splunk_lab && ./launch-indexer.sh && ./launch-forwarder.sh
```

```bash
echo "Your log message $(date)" >> ~/splunk_lab/test.log
```
