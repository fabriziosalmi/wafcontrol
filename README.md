# 🌐 WAFcontrol (Cloudflare WAF Settings Automation)

Welcome to **WAFcontrol**, a powerful, scalable, and fully automated solution for managing Cloudflare Web Application Firewall (WAF) rules across multiple zones. This tool allows you to define default configurations and customize WAF settings for individual domains, all while leveraging Cloudflare’s robust API to enhance your security posture.

> [!NOTE]
> Current code will not work as expected, this will be fixed as soon as possible.

## 🚀 Project Summary

**WAFcontrol** provides a centralized and automated solution to manage WAF settings for multiple Cloudflare domains using a YAML configuration file. You can define WAF rules, IP access lists, bot protection settings, and sensitivity levels in a declarative manner, and easily apply these settings using a single script.

## ✨ Features Overview

### Core Features
- **Multi-Zone Support**: Manage WAF settings across multiple domains using a unified configuration.
- **Declarative YAML Configuration**: Simplify security management with a human-readable YAML file.
- **Custom Rules**: Define IP access, User-Agent rules, and custom WAF expressions.
- **Free Plan Compatibility**: Compatible with Cloudflare's free plan features.
- **Automation**: Easily integrate with GitHub Actions or other CI/CD tools.

### WAF Features Managed
- **WAF Sensitivity Level**: Control sensitivity (`low`, `medium`, `high`).
- **Bot Fight Mode**: Enable/disable Cloudflare Bot Fight Mode.
- **IP Access Rules**: Define IP addresses/ranges to allow or block.
- **User-Agent Rules**: Create rules to block or challenge specific User-Agent strings.
- **Custom WAF Rules**: Use custom expressions to define WAF actions (`block`, `challenge`, `allow`).

## 🛠️ How It Works

1. **Configuration**: Define all WAF settings in a YAML file. Use common configurations under a `default` section, and customize specific zones with overrides.
2. **Execution**: The script reads the configuration, applies the settings using Cloudflare’s API, and logs the results.
3. **Automation**: Seamlessly integrate with GitHub Actions or other CI/CD tools to automate the process.

## 📄 YAML Configuration Example

The configuration is written in YAML format for simplicity. Below is an example that defines default WAF settings and customizations for specific zones.

```yaml
ip_lists:
  trusted_partners:
    - "203.0.113.0/24"
    - "198.51.100.12"
  suspicious_ips:
    - "192.0.2.0/24"
    - "198.51.100.45"

waf:
  default:
    enable_waf: true
    sensitivity: "medium"
    bot_fight_mode: true
    ip_access_rules: 
      - "$trusted_partners"
    user_agent_rules: 
      - "BadBot"
    custom_rules:
      - name: "Block Suspicious IPs"
        expression: "(ip.src in $suspicious_ips)"
        action: "block"
        description: "Block requests from suspicious IPs"

  zones:
    - id: "1234567890abcdef1234567890abcdef"
      domain: "example.com"
      waf:
        sensitivity: "high"
        custom_rules:
          - name: "Challenge Traffic from CN"
            expression: "(ip.geoip.country eq 'CN')"
            action: "challenge"
            description: "Challenge all traffic from China"
```

## 🏗️ Setup Instructions

### 1. Prerequisites
- **Cloudflare Account**: Ensure you have an active Cloudflare account and an API token with appropriate permissions (`Zone Settings: Edit`, `Firewall Services: Edit`).
- **GitHub Repository**: Prepare a GitHub repository containing your YAML configuration file and this script.
- **GitHub Actions Setup**: The solution is designed to work seamlessly with GitHub Actions for automation.

### 2. Installation
Clone the repository:

```bash
git clone https://github.com/fabriziosalmi/wafcontrol.git
cd wafcontrol
```

### 3. Configuration
- **Cloudflare API Token**: Create an API token via the Cloudflare dashboard and add it as a secret in your GitHub repository (`CLOUDFLARE_API_TOKEN`).
- **YAML Configuration**: Edit `config/cloudflare.yaml` to define your WAF settings.

### 4. Running the Script
Run the script manually for testing:

```bash
python scripts/cloudflare_apply.py --config config/cloudflare.yaml
```

### 5. Automating with GitHub Actions
Create a workflow file in `.github/workflows/cloudflare_deploy.yml` to automate updates:

```yaml
name: Cloudflare WAF Management

on:
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * *'  # Runs daily at midnight

jobs:
  apply-waf-settings:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          python -m venv venv
          source venv/bin/activate
          python -m pip install --upgrade pip
          pip install requests pydantic tenacity pyyaml

      - name: Run WAF Control script
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
        run: |
          source venv/bin/activate
          python scripts/cloudflare_apply.py --config config/cloudflare.yaml
```

## 📊 Example Output

Here’s an example log output showing a successful update:

```plaintext
::INFO:: Cloudflare API token is valid.
::INFO:: Processing zone 1234567890abcdef1234567890abcdef for domain example.com...
::INFO:: Applying WAF settings for zone 1234567890abcdef1234567890abcdef...
::INFO:: Successfully updated sensitivity to high.
::INFO:: Successfully enabled Bot Fight Mode.
::INFO:: Successfully added IP access rule for trusted partner IPs.
::INFO:: Successfully added custom WAF rule: Challenge Traffic from CN.
```

## 🛡️ Security Considerations

### Token and Secret Management
- **API Token**: **Never** store your Cloudflare API token in the repository. Use GitHub Secrets to protect sensitive information.

### Error Handling
- The script handles errors gracefully, skipping unsupported configurations and logging detailed information to ensure your workflow isn’t disrupted.

## 🔧 Customization and Extensibility

- **Custom Rules**: You can add new WAF rules in the YAML file to adapt to changing security requirements.
- **Integration**: Modify the workflow to integrate with other CI/CD systems, or extend the script to support more Cloudflare API features.

## 👨‍💻 Contributing

Contributions are welcome! If you have new feature suggestions or find bugs, feel free to open an issue or submit a pull request.

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for more details.
