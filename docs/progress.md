# Progress

## Done (v0.1)

- Project rules (`AGENTS.md`), architecture notes, CI, automatic deploy with rollback.
- Login with one admin account, CSRF protection, login throttling, security headers.
- English and Chinese UI, English default.
- Server check, quick and deep: SSH login, system facts, swap, disk, BBR, LXD fit,
  ports, existing stacks, versions against tested ones, IP region and type,
  return routes to the three carriers, reachability from abroad and China,
  GFW block classification, Globalping, manual test links.
- Cloudflare token and DNS check (read-only).
- Proxy test: exit IP, network type, sticky or rotating.
- Admin: China probe with encrypted, write-only login (password swapped for a
  dedicated key by default), pinned host key, Globalping token.
- Deploy prompt generator with presets, save locations, optional LXC split,
  traffic limit, secrets kept out by default.
- Subscription converter: vless, vmess, trojan, ss, hysteria2, tuic, socks5;
  filters, renames, flags, dedupe, group templates, rule toggles, DNS options;
  YAML, share links, QR codes, hosted subscription URL.
- History with downloads (Markdown/JSON reports, prompt, configs, YAML, links).
- Findings for databases and admin panels open to the internet, and for Docker
  ports that bypass UFW.

## Live test (2026-11-03)

- Quick and deep checks ran through the public site against a Guangzhou VPS
  (SSH facts, 9 carrier routes) and a Los Angeles VPS (network only, from the
  China probe and Globalping). The forward route showed ChinaNet 163 → Cogent,
  matching the expected path.
- The first run found four bugs, all fixed with regression tests: KVM read as a
  container, failed TLS read as success, BBR module not detected, closed ports
  shown as reachable.
- Generated prompts and the admin page were checked for leaked secrets: none.

## Next

- sing-box JSON output in the converter.
- Real proxy-protocol test from the China probe (run a Mihomo client there and
  fetch through each node) to catch protocol-level blocking.
- Scheduled re-checks of saved servers with change alerts.
- Streaming / AI unlock checks from the target.
- Per-port history graph of China reachability.

## Known limits

- Automatic deploys from CI are switched off until the restricted deploy key is
  added on the server (see `docs/architecture.md`, Deployment). Until then,
  deploy with `/usr/local/sbin/vps-console-deploy deploy <sha>` on the server.

- Globalping has few probes in China; results may be empty.
- ip-api network type is a hint, not proof.
- The China probe is a Tencent Cloud server: its routes show a datacenter
  path, not a home broadband one.
