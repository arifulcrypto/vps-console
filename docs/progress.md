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

## Next

- sing-box JSON output in the converter.
- Real proxy-protocol test from the China probe (run a Mihomo client there and
  fetch through each node) to catch protocol-level blocking.
- Scheduled re-checks of saved servers with change alerts.
- Streaming / AI unlock checks from the target.
- Per-port history graph of China reachability.

## Known limits

- Globalping has few probes in China; results may be empty.
- ip-api network type is a hint, not proof.
- The China probe is a Tencent Cloud server: its routes show a datacenter
  path, not a home broadband one.
