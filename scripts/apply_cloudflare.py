import os
import sys
import json
import logging
import yaml
import requests
from typing import List, Dict, Optional, Any, Union
from pydantic import BaseModel, field_validator, ValidationError
from tenacity import retry, stop_after_attempt, wait_exponential
import argparse
from datetime import datetime

# Check if running in a GitHub Actions environment
GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS') == 'true'

# Configure logging with timestamp
log_format = '::%(levelname)s :: %(message)s' if GITHUB_ACTIONS else '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(
    level=logging.INFO,
    format=log_format,
    handlers=[logging.StreamHandler()]
)

# Cloudflare WAF settings validation models
class WAFRule(BaseModel):
    name: str
    expression: str
    action: str
    description: Optional[str] = None

    @field_validator('action')
    @classmethod
    def validate_rule_action(cls, value: str) -> str:
        valid_actions = {"block", "challenge", "allow", "log", "bypass", "managed_challenge", "js_challenge"}
        if value not in valid_actions:
            raise ValueError(f"Invalid action. Choose one of {valid_actions}")
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


class CloudflareAPI:
    def __init__(self, api_token: str):
        self.api_token = api_token
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }

    def make_request(self, method: str, url: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=json_data,
                timeout=30
            )
            
            if response.status_code == 403:
                logging.error(f"Permission denied for {url}. Please check API token permissions.")
                return {"success": False, "errors": ["Permission denied"]}

            response_data = response.json()
            
            if not response_data.get('success', False):
                errors = response_data.get('errors', [])
                error_messages = '; '.join(str(error.get('message', 'Unknown error')) for error in errors)
                logging.error(f"API request failed: {error_messages}")
                return response_data

            return response_data

        except requests.RequestException as e:
            logging.error(f"API request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logging.error(f"Response content: {e.response.content.decode()}")
            raise

    def validate_token(self) -> bool:
        url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
        try:
            response = self.make_request("GET", url)
            return response.get('success', False)
        except Exception as e:
            logging.error(f"Token validation failed: {e}")
            return False


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def apply_waf_settings(api: CloudflareAPI, zone_id: str, settings: WAFSettings) -> Dict[str, Any]:
    logging.info(f"Applying WAF settings for zone {zone_id}...")
    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
    updated_settings = {}

    # Apply Security Level
    if settings.firewall_settings and settings.firewall_settings.security_level:
        try:
            security_url = f"{base_url}/settings/security_level"
            result = api.make_request(
                "PATCH",
                security_url,
                {"value": settings.firewall_settings.security_level}
            )
            if result.get('success'):
                updated_settings["security_level"] = result
                logging.info(f"Successfully updated security level.")
        except Exception as e:
            logging.error(f"Failed to update security level: {e}")

    # Apply Bot Management Settings
    if settings.firewall_settings and settings.firewall_settings.bot_fight_mode is not None:
        try:
            bot_url = f"{base_url}/settings/bot_management"
            result = api.make_request(
                "PATCH",
                bot_url,
                {"value": "on" if settings.firewall_settings.bot_fight_mode else "off"}
            )
            if result.get('success'):
                updated_settings["bot_management"] = result
                logging.info(f"Successfully updated bot management settings.")
        except Exception as e:
            logging.error(f"Failed to update bot management settings: {e}")

    # Apply Custom Rules using Firewall Rules API
    if settings.custom_rules:
        try:
            for rule in settings.custom_rules:
                # First create a filter
                filters_url = f"{base_url}/filters"
                filter_payload = {
                    "expression": rule.expression,
                    "description": rule.description or f"Filter for {rule.name}"
                }
                filter_result = api.make_request("POST", filters_url, filter_payload)
                
                if filter_result.get('success') and 'result' in filter_result:
                    filter_id = filter_result['result']['id']
                    
                    # Then create the firewall rule
                    rules_url = f"{base_url}/firewall/rules"
                    rule_payload = {
                        "filter": {"id": filter_id},
                        "action": rule.action,
                        "description": rule.description or "",
                        "paused": False
                    }
                    rule_result = api.make_request("POST", rules_url, rule_payload)
                    
                    if rule_result.get('success'):
                        updated_settings[f"custom_rule_{rule.name}"] = rule_result
                        logging.info(f"Successfully added custom rule: {rule.name}")
        except Exception as e:
            logging.error(f"Failed to add custom rules: {e}")

    # Apply WAF Configuration
    if settings.enable_waf is not None:
        try:
            waf_url = f"{base_url}/settings/waf"
            result = api.make_request(
                "PATCH",
                waf_url,
                {"value": "on" if settings.enable_waf else "off"}
            )
            if result.get('success'):
                updated_settings["waf_status"] = result
                logging.info(f"Successfully {'enabled' if settings.enable_waf else 'disabled'} WAF.")
        except Exception as e:
            logging.error(f"Failed to update WAF status: {e}")

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

    api = CloudflareAPI(api_token)

    # Validate the API token before proceeding
    if not api.validate_token():
        logging.error("API token validation failed. Exiting.")
        sys.exit(1)

    # Process zones
    zones = cloudflare_config.waf.get('zones', [])
    if not zones:
        logging.warning("No zones found in configuration.")
        return

    default_waf_settings = cloudflare_config.waf.get('default', {})

    for zone in zones:
        zone_id = zone.get('id')
        fqdn = zone.get('domain')
        zone_settings = zone.get('waf', {})

        if not zone_id or not fqdn:
            logging.error(f"Zone ID or domain not found for one of the zones.")
            continue

        try:
            merged_settings = {**default_waf_settings, **zone_settings}
            settings = WAFSettings.model_validate(merged_settings)

            logging.info(f"Processing zone {zone_id} for domain {fqdn}...")
            apply_waf_settings(api, zone_id, settings)
        except Exception as e:
            logging.error(f"Failed to process zone {fqdn} ({zone_id}): {e}")
            continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare WAF settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    main(args.config)
