# WAF Virtual Server Summary

| Virtual Server | Partition | Destination | HTTP Profile | WAF Status | Attached WAF Policies |
|----------------|-----------|-------------|--------------|------------|-----------------------|
| `vs_no_http` | Common | /Common/192.168.10.10:22 | — | Not Applicable | — |
| `vs_http_capable` | Common | /Common/192.168.10.11:80 | /Common/http | WAF Capable | — |
| `vs_direct_waf` | Common | /Common/192.168.10.12:443 | /Common/http | WAF Enabled | 1 |
| `vs_legacy_waf` | Common | /Common/192.168.10.13:443 | /Common/http | WAF Enabled | 1 |
| `vs_ltm_host` | Common | /Common/192.168.10.14:443 | /Common/http | WAF Enabled | 2 |
| `vs_ltm_any` | Common | /Common/192.168.10.15:443 | /Common/http-explicit | WAF Enabled | 1 |