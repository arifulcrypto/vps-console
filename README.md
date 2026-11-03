# VPS Console

A mobile-first web console for the VPS skills. It checks a server before you deploy, tests whether it is reachable from China, tests proxies and Cloudflare tokens, converts subscriptions, and writes a ready-to-paste prompt for [vps-deploy-skill](https://github.com/arifulcrypto/vps-deploy-skill) and [vps-lxc-skill](https://github.com/arifulcrypto/vps-lxc-skill).

面向手机的 VPS 部署前检测台：检测服务器、国内连通性和墙的封锁、代理与 Cloudflare 令牌，订阅转换，并生成可直接粘贴给智能体的部署提示词。界面支持中英文。

## Features

- **Quick check** (about 30 s) and **deep check** (a few minutes), read-only:
  OS and support dates, CPU, RAM, swap, disk, BBR, LXD fit, ports in use,
  existing proxy stacks, versions against tested ones, IP region and type,
  return routes to China Telecom, Unicom and Mobile (CN2 GIA, 9929, CMIN2…),
  detour hints.
- **GFW test** from your own China probe and Globalping: tells IP, port and TLS
  blocking apart, with links to ITDOG, ping.pe and IP.NET.COFFEE for manual checks.
- **Proxy test** for residential, dynamic and static ISP proxies: exit IP,
  network type, sticky or rotating.
- **Cloudflare check**: token, zones, DNS records, proxied or not.
- **Deploy prompt**: protocol presets, save location, optional LXD split and
  traffic limit. No secrets in the prompt unless you ask.
- **Subscription converter**: vless, vmess, trojan, ss, hysteria2, tuic, socks5;
  filters, renames, flags, groups, rules, DNS options; YAML, links, QR codes and a
  hosted subscription URL.

## Docs

- [AGENTS.md](AGENTS.md): rules and verification commands
- [docs/architecture.md](docs/architecture.md): design and decisions
- [docs/progress.md](docs/progress.md): status and next steps

## License

MIT
