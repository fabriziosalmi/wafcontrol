import os
import sys
import json
import logging
import yaml
import requests
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, field_validator, ValidationError
from tenacity import retry, stop_after_attempt, wait_exponential
import argparse

# Check if running in a GitHub Actions environment
GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS') == 'true'

# Configure logging
if GITHUB_ACTIONS:
    logging.basicConfig(level=logging.INFO, format='::%(levelname)s :: %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Cloudflare WAF settings validation models
class WAFRule(BaseModel):
    name: str
    expression: str
    action: str
    description: Optional[str] = None

    @field_validator('action')
    @classmethod
    def validate_rule_action(cls, value: str) -> str:
        if value not in {"block", "challenge", "allow", "log", "bypass"}:
            raise ValueError("Invalid action. Choose one of 'block', 'challenge', 'allow', 'log', 'bypass'.")
        return value


class ManagedRule(BaseModel):
    id: str
    action: str
    description: str


class IPAccessRule(BaseModel):
    action: str
    value: str
    description: Optional[str] = None


class UserAgentRule(BaseModel):
    action: str
    value: str
    description: Optional[str] = None


class FirewallSettings(BaseModel):
    sensitivity: Optional[str] = "medium"
    bot_fight_mode: Optional[bool] = True
    ip_access_rules: Optional[List[IPAccessRule]] = []
    user_agent_rules: Optional[List[UserAgentRule]] = []
    security_level: Optional[str] = "medium"
    challenge_ttl: Optional[int] = 3600
    privacy_pass_support: Optional[bool] = True

    @field_validator("sensitivity")
    @classmethod
    def validate_sensitivity(cls, value: str) -> str:
        if value not in {"low", "medium", "high"}:
            raise ValueError("Invalid sensitivity level. Choose one of 'low', 'medium', 'high'.")
        return value

    @field_validator("security_level")
    @classmethod
    def validate_security_level(cls, value: str) -> str:
        valid_levels = {"off", "essentially_off", "low", "medium", "high", "under_attack"}
        if value not in valid_levels:
            raise ValueError(f"Invalid security level. Choose one of {valid_levels}")
        return value


class WAFSettings(BaseModel):
    enable_waf: Optional[bool] = True
    managed_rules: Optional[List[ManagedRule]] = []
    custom_rules: Optional[List[WAFRule]] = []
    firewall_settings: Optional[FirewallSettings] = FirewallSettings()


class IPList(BaseModel):
    name: str
    description: str
    ips: List[str]


class Zone(BaseModel):
    id: str
    domain: str
    waf: Optional[Dict[str, Any]] = {}


class CloudflareConfig(BaseModel):
    ip_lists: List[IPList]
    waf: Dict[str, Any]


class Config(BaseModel):
    cloudflare: CloudflareConfig


def validate_api_token(api_token: str) -> bool:
    url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        logging.info("Cloudflare API token is valid.")
        return True
    except requests.RequestException as e:
        logging.error(f"API token validation failed: {e}")
        return False


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def apply_waf_settings(api_token: str, zone_id: str, settings: WAFSettings) -> Dict[str, Any]:
    logging.info(f"Applying WAF settings for zone {zone_id}...")

    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }

    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
    updated_settings = {}

    def make_request(method: str, url: str, json_data: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logging.error(f"API request failed: {e}")
            raise

    # Enable/Disable WAF
    if settings.enable_waf is not None:
        try:
            waf_url = f"{base_url}/security/waf"
            payload = {"value": "on" if settings.enable_waf else "off"}
            result = make_request("PATCH", waf_url, payload)
            updated_settings["waf_enabled"] = result
            logging.info(f"Successfully {'enabled' if settings.enable_waf else 'disabled'} WAF.")
        except requests.RequestException as e:
            logging.error(f"Failed to update WAF status: {e}")

    # Apply Managed Rules
    if settings.managed_rules:
        for rule in settings.managed_rules:
            try:
                # Using the new rulesets API
                ruleset_url = f"{base_url}/rulesets/phases/http_request_firewall_managed/entrypoint"
                payload = {
                    "rules": [
                        {
                            "id": rule.id,
                            "action": rule.action,
                            "description": rule.description,
                            "enabled": True
                        }
                    ]
                }
                result = make_request("PUT", ruleset_url, payload)
                updated_settings[f"managed_rule_{rule.id}"] = result
                logging.info(f"Successfully configured managed rule {rule.id}")
            except requests.RequestException as e:
                logging.error(f"Failed to configure managed rule {rule.id}: {e}")

    # Apply Security Level
    if settings.firewall_settings and settings.firewall_settings.security_level:
        try:
            security_url = f"{base_url}/settings/security_level"
            payload = {"value": settings.firewall_settings.security_level}
            result = make_request("PATCH", security_url, payload)
            updated_settings["security_level"] = result
            logging.info(f"Successfully updated security level.")
        except requests.RequestException as e:
            logging.error(f"Failed to update security level: {e}")

    # Apply Bot Fight Mode
    if settings.firewall_settings and settings.firewall_settings.bot_fight_mode:
        try:
            bot_url = f"{base_url}/settings/bot_fight_mode"
            payload = {"value": "on" if settings.firewall_settings.bot_fight_mode else "off"}
            result = make_request("PATCH", bot_url, payload)
            updated_settings["bot_fight_mode"] = result
            logging.info(f"Successfully updated Bot Fight Mode.")
        except requests.RequestException as e:
            logging.error(f"Failed to update Bot Fight Mode: {e}")

    # Apply IP Access Rules
    if settings.firewall_settings and settings.firewall_settings.ip_access_rules:
        for rule in settings.firewall_settings.ip_access_rules:
            try:
                rules_url = f"{base_url}/firewall/rules"
                payload = {
                    "rules": [
                        {
                            "action": rule.action,
                            "expression": f"ip.src in {{{rule.value}}}",
                            "description": rule.description or "",
                            "enabled": True
                        }
                    ]
                }
                result = make_request("POST", rules_url, payload)
                updated_settings[f"ip_rule_{rule.value}"] = result
                logging.info(f"Successfully added IP rule for {rule.value}")
            except requests.RequestException as e:
                logging.error(f"Failed to add IP rule for {rule.value}: {e}")

    # Apply User Agent Rules
    if settings.firewall_settings and settings.firewall_settings.user_agent_rules:
        for rule in settings.firewall_settings.user_agent_rules:
            try:
                rules_url = f"{base_url}/firewall/rules"
                payload = {
                    "rules": [
                        {
                            "action": rule.action,
                            "expression": f"http.user_agent contains \"{rule.value}\"",
                            "description": rule.description or "",
                            "enabled": True
                        }
                    ]
                }
                result = make_request("POST", rules_url, payload)
                updated_settings[f"ua_rule_{rule.value}"] = result
                logging.info(f"Successfully added User-Agent rule for {rule.value}")
            except requests.RequestException as e:
                logging.error(f"Failed to add User-Agent rule for {rule.value}: {e}")

    # Apply Custom Rules
    if settings.custom_rules:
        try:
            rules_url = f"{base_url}/firewall/rules"
            rules = [
                {
                    "action": rule.action,
                    "expression": rule.expression,
                    "description": rule.description or "",
                    "enabled": True
                }
                for rule in settings.custom_rules
            ]
            payload = {"rules": rules}
            result = make_request("POST", rules_url, payload)
            updated_settings["custom_rules"] = result
            logging.info("Successfully added custom rules")
        except requests.RequestException as e:
            logging.error(f"Failed to add custom rules: {e}")

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
        config = Config.model_validate(config_data)
        cloudflare_config = config.cloudflare
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
    default_waf_settings = cloudflare_config.waf.get('default', {})

    # Process zones
    zones = cloudflare_config.waf.get('zones', [])
    if not zones:
        logging.warning("No zones found in configuration.")
        return

    for zone in zones:
        zone_id = zone.get('id')
        fqdn = zone.get('domain')
        zone_settings = zone.get('waf', {})

        if not zone_id or not fqdn:
            logging.error(f"Zone ID or domain not found for one of the zones.")
            continue

        try:
            # Merge default and zone-specific settings
            merged_settings = {**default_waf_settings, **zone_settings}
            settings = WAFSettings.model_validate(merged_settings)

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
