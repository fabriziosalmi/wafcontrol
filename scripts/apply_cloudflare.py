import os
import sys
import json
import logging
import yaml
import requests
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, validator
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

    @validator('action')
    def validate_rule_action(cls, value):
        if value not in {"block", "challenge", "allow"}:
            raise ValueError("Invalid action. Choose one of 'block', 'challenge', 'allow'.")
        return value


class CloudflareWAFSettings(BaseModel):
    enable_waf: Optional[bool] = True
    sensitivity: Optional[str] = "medium"
    bot_fight_mode: Optional[bool] = True
    ip_access_rules: Optional[List[str]] = []
    user_agent_rules: Optional[List[str]] = []
    custom_rules: Optional[List[WAFRule]] = []

    @validator("sensitivity")
    def validate_sensitivity(cls, value):
        if value not in {"low", "medium", "high"}:
            raise ValueError("Invalid sensitivity level. Choose one of 'low', 'medium', 'high'.")
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
        response = requests.get(url, headers=headers, timeout=30)  # Added timeout
        response.raise_for_status()
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
    updated_settings = {}

    # Helper function for API requests
    def make_request(method: str, url: str, json_data: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                timeout=30  # Added timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logging.error(f"API request failed: {e}")
            raise

    if settings.enable_waf:
        logging.info("WAF is enabled by default.")

    # Update Sensitivity
    if settings.sensitivity:
        try:
            sensitivity_url = f"{base_url}/waf/sensitivity"
            result = make_request("PATCH", sensitivity_url, {"value": settings.sensitivity})
            updated_settings["sensitivity"] = result
            logging.info(f"Successfully updated sensitivity to {settings.sensitivity}.")
        except requests.RequestException as e:
            logging.error(f"Failed to update WAF sensitivity: {e}")

    # Update Bot Fight Mode
    if settings.bot_fight_mode:
        try:
            bot_fight_url = f"{base_url}/settings/bot_fight_mode"
            result = make_request("PATCH", bot_fight_url, {"value": "on"})
            updated_settings["bot_fight_mode"] = result
            logging.info("Successfully enabled Bot Fight Mode.")
        except requests.RequestException as e:
            logging.error(f"Failed to enable Bot Fight Mode: {e}")

    # Apply IP Access Rules
    for ip in settings.ip_access_rules:
        try:
            ip_rule_url = f"{base_url}/access_rules/rules"
            payload = {
                "mode": "block",
                "configuration": {
                    "target": "ip",
                    "value": ip
                },
                "notes": "Blocking IP based on configuration"
            }
            result = make_request("POST", ip_rule_url, payload)
            updated_settings[f"ip_access_rule_{ip}"] = result
            logging.info(f"Successfully added IP access rule for {ip}.")
        except requests.RequestException as e:
            logging.error(f"Failed to add IP access rule for {ip}: {e}")

    # Apply User Agent Rules
    for user_agent in settings.user_agent_rules:
        try:
            ua_rule_url = f"{base_url}/access_rules/rules"
            payload = {
                "mode": "block",
                "configuration": {
                    "target": "ua",
                    "value": user_agent
                },
                "notes": "Blocking User-Agent based on configuration"
            }
            result = make_request("POST", ua_rule_url, payload)
            updated_settings[f"user_agent_rule_{user_agent}"] = result
            logging.info(f"Successfully added User-Agent rule for {user_agent}.")
        except requests.RequestException as e:
            logging.error(f"Failed to add User-Agent rule for {user_agent}: {e}")

    # Apply Custom WAF Rules
    if settings.custom_rules:
        for rule in settings.custom_rules:
            try:
                custom_rule_url = f"{base_url}/waf/custom_rules"
                payload = {
                    "description": rule.description or "",
                    "action": rule.action,
                    "filter": {
                        "expression": rule.expression
                    },
                    "paused": False
                }
                result = make_request("POST", custom_rule_url, payload)
                updated_settings[f"custom_rule_{rule.name}"] = result
                logging.info(f"Successfully added custom WAF rule: {rule.name}.")
            except requests.RequestException as e:
                logging.error(f"Failed to add custom WAF rule {rule.name}: {e}")

    return updated_settings


def main(config_path: str):
    # Validate config file exists
    if not os.path.exists(config_path):
        logging.error(f"Configuration file not found: {config_path}")
        sys.exit(1)

    try:
        with open(config_path, 'r') as file:
            config_data = yaml.safe_load(file)
    except yaml.YAMLError as e:
        logging.error(f"Failed to parse YAML configuration file: {e}")
        sys.exit(1)
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

    # Process zones in parallel if multiple zones exist
    for zone in config.waf.get('zones', []):
        zone_id = zone.get('id')
        fqdn = zone.get('domain')
        zone_settings = zone.get('waf', {})

        if not zone_id or not fqdn:
            logging.error(f"Zone ID or domain not found for one of the zones.")
            continue

        try:
            # Merge default and zone-specific settings
            merged_settings = {**default_waf_settings, **zone_settings}
            settings = CloudflareWAFSettings(**merged_settings)

            logging.info(f"Processing zone {zone_id} for domain {fqdn}...")
            apply_waf_settings(api_token, zone_id, settings)
        except Exception as e:
            logging.error(f"Failed to process zone {fqdn} ({zone_id}): {e}")
            continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare WAF settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    main(args.config)
