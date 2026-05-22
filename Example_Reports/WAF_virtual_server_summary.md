# WAF Virtual Server Summary

| Virtual Server | Partition | Destination | HTTP Profile | WAF Status | Attached WAF Policies |
|----------------|-----------|-------------|--------------|------------|-----------------------|
| `vs_no_http` | Common | /Common/10.0.0.10:9999 | — | Not Applicable | — |
| `vs_capable_only` | Common | /Common/10.0.0.11:80 | /Common/http | WAF Capable | — |
| `vs_direct` | Common | /Common/10.0.0.12:443 | /Common/http | WAF Enabled | 1 |
| `vs_ltm_host` | Common | /Common/10.0.0.13:443 | /Common/http | WAF Enabled | 2 |
| `vs_app1` | AWS | /AWS/172.16.0.5:443 | /AWS/http | WAF Enabled | 1 |
| `vs_app2` | AWS | /AWS/172.16.0.6:80 | /AWS/http | WAF Enabled | 1 |