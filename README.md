# 🌐 WAFcontrol (Cloudflare WAF Settings Automation)

Welcome to **WAFcontrol**, a streamlined solution for managing Cloudflare Web Application Firewall (WAF) security levels across multiple zones. This tool allows you to manage security levels for individual domains through a simple YAML configuration.

## 🚀 Project Summary

**WAFcontrol** provides a centralized and automated solution to manage security levels for multiple Cloudflare domains using a YAML configuration file. You can define default security settings and customize them for individual domains, all managed through GitHub Actions automation.

## ✨ Features Overview

### Core Features
- **Multi-Zone Support**: Manage security settings across multiple domains using a unified configuration
- **Declarative YAML Configuration**: Simplify security management with a human-readable YAML file
- **Free Plan Compatibility**: Works with Cloudflare's free plan
- **GitHub Actions Integration**: Built-in automation support

### Security Features Managed
- **Security Level Control**: Set security levels for each zone
  - Available options: `off`, `essentially_off`, `low`, `medium`, `high`, `under_attack`
- **Default Settings**: Define default security levels that apply to all zones
- **Zone-Specific Overrides**: Customize security levels for individual domains

## 🛠️ How It Works

1. **Configuration**: Define security levels in a YAML file, with common settings under `default` and zone-specific overrides
2. **Execution**: The script applies the settings using Cloudflare's API and logs the results
3. **Automation**: Runs automatically through GitHub Actions on schedule or manual trigger

## 📄 YAML Configuration Example

```yaml
cloudflare:
  waf:
    default:
      firewall_settings:
        security_level: "high"
    zones:
      - id: "your-zone-id"
        domain: "your-domain.com"
        waf:
          firewall_settings:
            security_level: "under_attack"
```

## 🏗️ Setup Instructions

### 1. Prerequisites
- Cloudflare Account with API token
- GitHub repository
- Python 3.9 or higher

Required API token permissions:
- Zone Settings:Edit

### 2. Installation

1. Clone the repository:
```bash
git clone https://github.com/fabriziosalmi/wafcontrol.git
cd wafcontrol
```

2. Install dependencies:
```bash
pip install pydantic requests PyYAML tenacity
```

### 3. Configuration

1. Create Cloudflare API token:
   - Go to Cloudflare Dashboard → Profile → API Tokens
   - Create token with `Zone Settings:Edit` permission
   - Add token to GitHub repository secrets as `CLOUDFLARE_API_TOKEN`

2. Configure your zones:
   - Edit `config/cloudflare.yaml` with your zone IDs and domains
   - Set desired security levels for each zone

### 4. GitHub Actions Setup

The workflow runs automatically:
- On push to main branch (affecting relevant files)
- Daily at midnight UTC
- Manual trigger through GitHub Actions UI

Workflow file `.github/workflows/waf-control.yml`:
```yaml
name: WAF Control

on:
  push:
    branches: [ main ]
    paths:
      - 'config/**'
      - 'scripts/**'
      - '.github/workflows/**'
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * *'

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    
    env:
      CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
    
    steps:
    - uses: actions/checkout@v4
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.9'
        cache: 'pip'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install pydantic requests PyYAML tenacity
    
    - name: Apply WAF settings
      run: python scripts/apply_cloudflare.py --config config/cloudflare.yaml
```

## 📊 Example Output

```plaintext
::INFO :: Cloudflare API token is valid.
::INFO :: Processing zone example.com (zone-id)...
::INFO :: Applying WAF settings for zone zone-id...
::INFO :: Successfully updated security level to under_attack
```

## 🛡️ Security Considerations

- Never commit API tokens to the repository
- Use GitHub Secrets for sensitive information
- Use environment protection rules for production deployments
- Double-check zone IDs and domains before deployment

## 🔧 Supported Zones

You can apply the security settings to any Cloudflare zone, including free domains. The security level control works with all Cloudflare plans.

## 👨‍💻 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

Guidelines for contributing:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 🐛 Troubleshooting

Common issues and solutions:

1. **API Token Issues**:
   - Ensure the token has `Zone Settings:Edit` permission
   - Verify the token is correctly added to GitHub Secrets
   - Check the token is not expired

2. **Configuration Issues**:
   - Verify zone IDs are correct
   - Ensure YAML syntax is valid
   - Check security level values are valid options

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

If you encounter any issues or need help:
1. Check the troubleshooting guide above
2. Look through existing GitHub Issues
3. Open a new issue if needed

## 🙏 Acknowledgments

- Thanks to Cloudflare for their excellent API
- Contributors who have helped improve this tool
- The open-source community for inspiration and support
