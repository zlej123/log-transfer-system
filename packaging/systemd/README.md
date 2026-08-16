# systemd deployment

`log-transfer-server.service` runs the Linux server as a supervised system
service. It is intentionally `Type=simple`: systemd owns supervision, so the
built-in `--daemon` double fork is not used here.

## Install

```bash
# 1. binary
sudo install -m 0755 dist/linux/log_server /usr/local/bin/log_server

# 2. unprivileged service account
sudo useradd --system --no-create-home --shell /usr/sbin/nologin lgx

# 3. TLS material (use organization PKI in production)
./scripts/generate_test_certs.sh certs
sudo install -d -m 0755 /etc/log-transfer
sudo install -m 0644 certs/server.crt certs/ca.crt /etc/log-transfer/
sudo install -m 0640 -g lgx certs/server.key /etc/log-transfer/server.key

# 4. unit
sudo install -m 0644 packaging/systemd/log-transfer-server.service \
    /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now log-transfer-server.service
```

`systemd` creates `/var/lib/log-transfer` through `StateDirectory=`, owned by
the service account with mode `0700`. Do not place certificates or the upload
store under `/tmp`: the service runs with `PrivateTmp=yes`, and many
distributions clear `/tmp` on boot.

## Operate

```bash
systemctl status log-transfer-server
journalctl -u log-transfer-server -f
sudo systemctl stop log-transfer-server      # SIGTERM; uploads stay resumable
```

Change options (port, threads, queue, quotas, authorized client subject) with
`sudo systemctl edit log-transfer-server` so the shipped unit stays untouched.
A drop-in **must** clear the inherited command first, otherwise the unit refuses
to load with "Service has more than one ExecStart= setting":

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/log_server --port 45777 --workdir /var/lib/log-transfer     --cert /etc/log-transfer/server.crt --key /etc/log-transfer/server.key     --client-ca /etc/log-transfer/ca.crt --threads 8 --queue 64
```

Run `sudo systemd-analyze verify log-transfer-server.service` after editing: a
bad drop-in leaves the running instance untouched, so the failure would
otherwise stay hidden until the next start.

If the unit stopped because the start limit tripped, restarting is not enough;
clear the latch first:

```bash
sudo systemctl reset-failed log-transfer-server
sudo systemctl start log-transfer-server
```

The limit window counts administrative restarts too, so a manual restart shortly
before a crash can trip it earlier than five attempts.

## Behavior

| Situation | Result |
|---|---|
| Missing or mismatched TLS material | Exits non-zero with the reason in the journal; after `StartLimitBurst` attempts the unit stops in `failed` instead of looping. Recover with `reset-failed` |
| `systemctl stop` | `SIGTERM`, bounded pool drains, exit status 0, well inside `TimeoutStopSec`, partial uploads remain resumable |
| Process crash | `Restart=on-failure` brings it back automatically |
| Host reboot | `WantedBy=multi-user.target` starts it again |

## Hardening

The unit drops all capabilities and applies `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
`RestrictAddressFamilies=AF_INET AF_INET6`, `MemoryDenyWriteExecute`,
`SystemCallArchitectures=native` and `SystemCallFilter=@system-service`. The
service needs one TCP port above 1024 and its own state directory, so no
capability is required.

## Verification performed

Validated in an Ubuntu 24.04 container running systemd 255 as PID 1:

- unit accepted by `systemd-analyze verify`
- starts as the unprivileged `lgx` account with `/var/lib/log-transfer` at `0700`
- real mutual-TLS transfer succeeds under the full sandbox, so the syscall
  filter does not block `signalfd`, `flock`, `poll` or TLS
- `systemctl stop` returns `Result=success` with exit status 0, far inside the
  60 s stop timeout
- `SIGKILL` is followed by an automatic restart, and results stay identical
- with TLS material absent the unit ends in `failed` after the configured
  attempts, and `reset-failed` restores normal operation
- the unit is `enabled` through `WantedBy=multi-user.target`, and the service
  came back `active` on its own when the container's systemd was restarted

Not verified: startup on a real machine reboot, which a container cannot
reproduce.

The server prints its own timestamp, so journal lines carry both the journal
timestamp and the application timestamp.
