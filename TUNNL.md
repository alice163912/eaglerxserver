# tunnl.gg integration

EaglerXServer can expose its configured Eaglercraft listener through [tunnl.gg](https://tunnl.gg) without requiring an operating-system SSH executable.

## How it works

- On startup, EaglerXServer creates a small `tunnl.properties` file if it does not exist.
- The integration is enabled by default and opens an SSH reverse tunnel to `proxy.tunnl.gg`.
- Apache MINA SSHD is bundled inside the EaglerXServer JAR. No external `ssh`, `autossh`, or tunneling program is required.
- An RSA-3072 SSH identity is generated automatically and stored under `plugins/EaglercraftXServer/tunnl-gg/`. The same identity is reused so the public address remains stable after restarts.
- The SSH server host key is checked against tunnl.gg's published SHA-256 fingerprint.
- The SSH client sends OpenSSH-compatible keepalives so tunnl.gg does not mistake an idle session for a dead client. If the SSH session drops or tunnl.gg closes the free tunnel because of its time limits, EaglerXServer reconnects automatically.
- The tunnel is closed when EaglerXServer shuts down.

## Configuration

The generated `tunnl.properties` file is:

```properties
enabled=true
listener=default
```

- `enabled`: set to `false` to disable the public tunnel.
- `listener`: name of the EaglerXServer listener to expose. On a server with only one listener, that listener is selected automatically if the configured name does not exist.

The private key is local to the server and must not be shared. Do not delete the `tunnl-gg` folder if you want to retain the same stable URL.

## Important limitations

tunnl.gg's free service currently limits tunnels to 3 simultaneous tunnels per source IP, 5 GB of daily transfer, 2 hours without requests or open WebSockets, and 24 hours per SSH session. The integration reconnects automatically; a reconnect using the same key restores the stable address. These limits are imposed by tunnl.gg, not EaglerXServer.

The tunnel requires the selected listener to use plain HTTP internally (`tls_config.enable_tls=false`) and cannot provide EaglerXServer's custom `forward_secret` header, so `forward_secret` must be disabled. If `forward_ip=true`, set `forward_ip_header=X-Forwarded-For` to use tunnl.gg's visitor-IP header. The tunnel makes the selected Eaglercraft listener reachable from the public internet. Anyone who knows the public URL can attempt to connect. Keep server authentication, permissions, and rate limits configured appropriately.
