import os
import sys
import json
import logging
import yaml
import requests
from typing import List, Dict, Optional
from pydantic import BaseModel, ValidationError, field_validator
from tenacity import retry, stop_after_attempt, wait_exponential
import argparse

# Check if running in a GitHub Actions environment
GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS') == 'true'

# Configure logging
if GITHUB_ACTIONS:
    logging.basicConfig(level=logging.INFO, format='::%(levelname)s :: %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Cloudflare WAF settings validation using Pydantic
class WAFRule(BaseModel):
    name: str
    expression: str
    action: str
    description: Optional[str] = None


class CloudflareWAFSettings(BaseModel):
    enable_waf: Optional[bool] = True
    sensitivity: Optional[str] = "medium"
    bot_fight_mode: Optional[bool] = True
    ip_access_rules: Optional[List[str]] = []
    user_agent_rules: Optional[List[str]] = []
    custom_rules: Optional[List[WAFRule]] = []

    @field_validator("sensitivity")
    def validate_sensitivity(cls, value):
        if value not in {"low", "medium", "high"}:
            raise ValueError("Invalid sensitivity level. Choose one of 'low', 'medium', 'high'.")
        return value

    @field_validator("custom_rules", each_item=True)
    def validate_action(cls, value):
        if value.action not in {"block", "challenge", "allow"}:
            raise ValueError("Invalid action. Choose one of 'block', 'challenge', 'allow'.")
        return value


# Config class to hold all zones
class Config(BaseModel):
    ip_lists: Dict[str, List[str]] = {}
    waf: Dict[str, Any]


# Function to validate the API token by calling the Cloudflare API
def validate_api_token(api_token: str) -> bool:
    url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Will raise HTTPError for 4xx/5xx status codes
        logging.info("Cloudflare API token is valid.")
        return True
    except requests.RequestException as e:
        logging.error(f"API token validation failed: {e}")
        return False


# Retry with exponential backoff for API errors
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def apply_waf_settings(api_token: str, zone_id: str, settings: CloudflareWAFSettings) -> Dict[str, Any]:
    logging.info(f"Applying WAF settings for zone {zone_id}...")

    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }

    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall"

    # Applying WAF rules
    settings_dict = settings.dict(exclude_none=True)
    updated_settings = {}

    if settings.enable_waf:
        logging.info("WAF is enabled by default.")

    # Update Sensitivity
    if settings.sensitivity:
        sensitivity_url = f"{base_url}/waf/sensitivity"
        try:
            response = requests.patch(sensitivity_url, headers=headers, json={"value": settings.sensitivity})
            response.raise_for_status()
            updated_settings["sensitivity"] = response.json()
            logging.info(f"Successfully updated sensitivity to {settings.sensitivity}.")
        except requests.RequestException as e:
            logging.error(f"Failed to update WAF sensitivity: {e}")

    # Update Bot Fight Mode
    if settings.bot_fight_mode:
        bot_fight_url = f"{base_url}/settings/bot_fight_mode"
        try:
            response = requests.patch(bot_fight_url, headers=headers, json={"value": "on"})
            response.raise_for_status()
            updated_settings["bot_fight_mode"] = response.json()
            logging.info("Successfully enabled Bot Fight Mode.")
        except requests.RequestException as e:
            logging.error(f"Failed to enable Bot Fight Mode: {e}")

    # Apply IP Access Rules
    for ip in settings.ip_access_rules:
        ip_rule_url = f"{base_url}/access_rules/rules"
        payload = {
            "mode": "block",
            "configuration": {
                "target": "ip",
                "value": ip
            },
            "notes": "Blocking IP based on configuration"
        }
        try:
            response = requests.post(ip_rule_url, headers=headers, json=payload)
            response.raise_for_status()
            updated_settings[f"ip_access_rule_{ip}"] = response.json()
            logging.info(f"Successfully added IP access rule for {ip}.")
        except requests.RequestException as e:
            logging.error(f"Failed to add IP access rule for {ip}: {e}")

    # Apply User Agent Rules
    for user_agent in settings.user_agent_rules:
        ua_rule_url = f"{base_url}/access_rules/rules"
        payload = {
            "mode": "block",
            "configuration": {
                "target": "ua",
                "value": user_agent
            },
            "notes": "Blocking User-Agent based on configuration"
        }
        try:
            response = requests.post(ua_rule_url, headers=headers, json=payload)
            response.raise_for_status()
            updated_settings[f"user_agent_rule_{user_agent}"] = response.json()
            logging.info(f"Successfully added User-Agent rule for {user_agent}.")
        except requests.RequestException as e:
            logging.error(f"Failed to add User-Agent rule for {user_agent}: {e}")

    # Apply Custom WAF Rules
    for rule in settings.custom_rules:
        custom_rule_url = f"{base_url}/waf/custom_rules"
        payload = {
            "description": rule.description or "",
            "action": rule.action,
            "filter": {
                "expression": rule.expression
            },
            "paused": False
        }
        try:
            response = requests.post(custom_rule_url, headers=headers, json=payload)
            response.raise_for_status()
            updated_settings[f"custom_rule_{rule.name}"] = response.json()
            logging.info(f"Successfully added custom WAF rule: {rule.name}.")
        except requests.RequestException as e:
            logging.error(f"Failed to add custom WAF rule {rule.name}: {e}")

    return updated_settings


# Main function to handle all domains
def main(config_path: str):
    try:
        with open(config_path, 'r') as file:
            config_data = yaml.safe_load(file)
    except Exception as e:
        logging.error(f"Failed to read configuration file: {e}")
        sys.exit(1)

    try:
        config = Config.parse_obj(config_data)
    except ValidationError as e:
        logging.error(f"Invalid configuration file: {e}")
        sys.exit(1)

    api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    if not api_token:
        logging.error("Cloudflare API token not found in environment variables.")
        sys.exit(1)

    # Validate the API token before proceeding
    if not validate_api_token(api_token):
        logging.error("API token validation failed. Exiting.")
        sys.exit(1)

    # Get default WAF settings
    default_waf_settings = config.waf.get('default', {})

    # Loop through each domain/zone and apply the settings
    for zone in config.waf.get('zones', []):
        zone_id = zone.get('id')
        fqdn = zone.get('domain')
        zone_settings = zone.get('waf', {})

        if not zone_id or not fqdn:
            logging.error(f"Zone ID or domain not found for one of the zones.")
            continue

        # Merge default and zone-specific settings
        merged_settings = {**default_waf_settings, **zone_settings}
        settings = CloudflareWAFSettings(**merged_settings)

        logging.info(f"Processing zone {zone_id} for domain {fqdn}...")
        apply_waf_settings(api_token, zone_id, settings)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare WAF settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    main(args.config)
