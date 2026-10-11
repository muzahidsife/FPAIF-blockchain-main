# Docker containers have no internet (TTL fix)

## Symptom

`./network.sh deployCC ...` fails at install with:

```
docker build failed ... npm error Exit handler never called!
```

Containers cannot reach DNS or the internet, so the peer's `npm ci --omit=dev`
build hangs. The host itself reaches npm fine.

## Cause

The upstream network drops outbound packets with TTL < 64. Docker NAT lowers
every container packet's TTL by one, so container traffic is dropped.

Quick check (should show 0% packet loss once fixed):

```bash
docker run --rm hyperledger/fabric-nodeenv:2.5 sh -c 'ping -c1 -W3 8.8.8.8'
```

## Temporary fix (lost on reboot)

```bash
sudo iptables -t mangle -I POSTROUTING -o eth0 -j TTL --ttl-set 64
```

## Permanent fix (systemd service)

```bash
sudo tee /etc/systemd/system/ttl64.service >/dev/null <<'EOF'
[Unit]
Description=Set outbound TTL to 64 so Docker-NATed traffic is not dropped upstream
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t mangle -C POSTROUTING -o eth0 -j TTL --ttl-set 64 2>/dev/null || iptables -t mangle -I POSTROUTING -o eth0 -j TTL --ttl-set 64'
ExecStop=/bin/sh -c 'iptables -t mangle -D POSTROUTING -o eth0 -j TTL --ttl-set 64 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now ttl64.service
sudo iptables -t mangle -S POSTROUTING   # expect one --ttl-set 64 rule
```

## Notes

- If Docker is restarted: `sudo systemctl restart ttl64.service` (normally not needed).
- If the VM interface is not `eth0`, change `-o eth0` in the service file.
- To undo: `sudo systemctl disable --now ttl64.service`.

## Other fixes made in this repo (same debugging session)

- `network.sh`: `createOrg2` was commented out (~line 244), so Org2 certificates
  were never generated. Re-enabled.
- `organizations/ccp-generate.sh`: missing execute bit. Fixed with `chmod +x`.

## Redeploy

```bash
cd fabric-samples/test-network
./network.sh down
./network.sh up createChannel -c mychannel -ca
./network.sh deployCC -ccn AgentIdentityContract \
  -ccp ../asset-transfer-basic/chaincode-typescript -ccl typescript
```
