# WAFcontrol

WAFcontrol applies Cloudflare zone security settings and custom WAF rules across multiple domains using a YAML configuration file and the Cloudflare API. It is designed to run as a GitHub Actions workflow.

## What it does

The script `scripts/apply_cloudflare.py` reads `config/cloudflare.yaml`, validates the configuration, and calls Cloudflare's API to set the following per-zone settings:

- **Security Level** — `off`, `essentially_off`, `low`, `medium`, `high`, or `under_attack`
- **Browser Integrity Check** — `on` or `off`
- **Automatic HTTPS Rewrites** — `on` or `off`
- **Custom WAF Rules** — create or update rules in the zone's `http_request_firewall_custom` ruleset (actions: `block`, `challenge`, `allow`, `log`, `bypass`)

A `default` section in the config applies to all zones. Settings in a zone's own block override the defaults.

> **Note:** Custom WAF rules (rulesets) require a Cloudflare paid plan. Zone-level firewall settings (security level, browser integrity check, automatic HTTPS rewrites) are available on all plans.

## Prerequisites

- Python 3.9 or higher
- A Cloudflare API token with **Zone Settings: Edit** permission
- A GitHub repository secret named `CLOUDFLARE_API_TOKEN`

Install dependencies:

```bash
pip install pydantic requests PyYAML tenacity
```

## Configuration

Edit `config/cloudflare.yaml`. Settings defined under `default` apply to every zone unless overridden.

```yaml
cloudflare:
  waf:
    default:
      firewall_settings:
        security_level: "high"
        browser_integrity_check: "on"
        automatic_https_rewrites: "on"
      rules:
        - description: "Block bad user agents"
          expression: '(http.user_agent contains "bad-bot")'
          action: "block"
    zones:
      - id: "your-zone-id"
        domain: "your-domain.com"
        waf:
          firewall_settings:
            security_level: "under_attack"
            browser_integrity_check: "off"   # overrides default
            automatic_https_rewrites: "on"
          rules:
            - description: "Challenge suspicious requests"
              expression: '(ip.geoip.country eq "RU")'
              action: "challenge"
```

## Running manually

```bash
export CLOUDFLARE_API_TOKEN=your-token-here
python scripts/apply_cloudflare.py --config config/cloudflare.yaml
```

## GitHub Actions

The workflow at `.github/workflows/cloudflare_deploy.yml` runs on:

- Push to `main` (when `config/`, `scripts/`, or `.github/workflows/` files change)
- Pull requests to `main` (same path filter)
- A daily schedule at midnight UTC
- Manual dispatch via the GitHub Actions UI

The workflow verifies the API token before applying settings and requires a `CLOUDFLARE_API_TOKEN` repository secret and a `production` environment configured in the repository settings.

## Example output

```
2024-01-01 00:00:00 - INFO - Processing zone example.com (zone-id)...
2024-01-01 00:00:00 - INFO - Applying WAF settings for zone zone-id...
2024-01-01 00:00:00 - INFO - Successfully updated security level to under_attack
2024-01-01 00:00:00 - INFO - Successfully updated browser integrity check to off
2024-01-01 00:00:00 - INFO - Successfully updated automatic https rewrites to on
```

When run inside GitHub Actions, log lines use the `::INFO ::` prefix format instead.

## Security

- Store your API token in GitHub Secrets, never in the repository.
- Use a GitHub environment protection rule to restrict production deployments.
- Verify zone IDs before applying settings.

## Troubleshooting

**API token errors**
- Confirm the token has `Zone Settings: Edit` permission.
- Check the token has not expired.
- Confirm the secret name in the repository matches `CLOUDFLARE_API_TOKEN`.

**Configuration errors**
- Verify zone IDs are correct (found in the Cloudflare dashboard overview page for each domain).
- Confirm YAML syntax is valid.
- Check that `security_level` is one of the accepted values listed above.

## Contributing

Open an issue to discuss significant changes before submitting a pull request.

## License

MIT — see the [LICENSE](LICENSE) file.
