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
log_format = '::%(levelname)s :: %(message)s' if GITHUB_ACTIONS else '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)

# Model definitions
class WAFRule(BaseModel):
    name: str
    expression: str
    action: str
    description: Optional[str] = None

    @field_validator('action')
    @classmethod
    def validate_rule_action(cls, value: str) -> str:
        valid_actions = {"block", "challenge", "allow", "log", "js_challenge"}
        if value not in valid_actions:
            raise ValueError(f"Invalid action. Choose one of {valid_actions}")
        return value


class FirewallSettings(BaseModel):
    security_level: Optional[str] = "medium"

    @field_validator("security_level")
    @classmethod
    def validate_security_level(cls, value: str) -> str:
        valid_levels = {"off", "essentially_off", "low", "medium", "high", "under_attack"}
        if value not in valid_levels:
            raise ValueError(f"Invalid security level. Choose one of {valid_levels}")
        return value


class WAFSettings(BaseModel):
    custom_rules: Optional[List[WAFRule]] = []
    firewall_settings: Optional[FirewallSettings] = None


class CloudflareConfig(BaseModel):
    ip_lists: List[Dict[str, Any]]
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
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def make_request(self, method: str, url: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=json_data,
                timeout=30
            )
            
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                logging.error(f"Failed to decode JSON response: {response.text}")
                return {"success": False, "errors": [{"message": "Invalid JSON response"}]}

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


def process_ip_lists(config_ip_lists: List[Dict[str, Any]]) -> Dict[str, str]:
    """Convert IP lists to expressions"""
    ip_list_map = {}
    for ip_list in config_ip_lists:
        if isinstance(ip_list, dict) and 'name' in ip_list and 'ips' in ip_list:
            ips = ip_list['ips']
            if isinstance(ips, list):
                ips_str = ','.join(f'"{ip}"' for ip in ips)
                ip_list_map[f"${ip_list['name']}"] = f"{{{ips_str}}}"
            else:
                logging.warning(f"Invalid IPs format for IP list {ip_list['name']}")
    return ip_list_map


def replace_ip_list_variables(expression: str, ip_list_map: Dict[str, str]) -> str:
    """Replace IP list variables in expressions"""
    result = expression
    for var_name, ip_set in ip_list_map.items():
        if var_name in result:
            result = result.replace(var_name, ip_set)
            logging.info(f"Replaced IP list variable {var_name} in expression")
    return result


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def apply_waf_settings(api: CloudflareAPI, zone_id: str, settings: WAFSettings, ip_list_map: Dict[str, str]) -> Dict[str, Any]:
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
                logging.info(f"Successfully updated security level to {settings.firewall_settings.security_level}")
        except Exception as e:
            logging.error(f"Failed to update security level: {e}")

    # Apply Firewall Rules
    if settings.custom_rules:
        try:
            rules = []
            for rule in settings.custom_rules:
                processed_expression = replace_ip_list_variables(rule.expression, ip_list_map)
                rule_data = {
                    "action": rule.action,
                    "expression": processed_expression,
                    "description": rule.description or "",
                    "enabled": True
                }
                rules.append(rule_data)

            if rules:
                create_url = f"{base_url}/firewall/rules"
                result = api.make_request("POST", create_url, {"rules": rules})
                if result.get('success'):
                    updated_settings["firewall_rules"] = result
                    logging.info(f"Successfully added {len(rules)} firewall rules")
                else:
                    logging.error(f"Failed to add firewall rules: {result.get('errors', [])}")
        except Exception as e:
            logging.error(f"Failed to add firewall rules: {e}")

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

    # Get Cloudflare API token
    api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    if not api_token:
        logging.error("Cloudflare API token not found in environment variables.")
        sys.exit(1)

    # Initialize API client
    api = CloudflareAPI(api_token)
    if not api.validate_token():
        logging.error("API token validation failed. Exiting.")
        sys.exit(1)

    # Process configuration
    cloudflare_config = config_data.get('cloudflare', {})
    if not cloudflare_config:
        logging.error("No Cloudflare configuration found in config file")
        sys.exit(1)

    # Process IP lists
    ip_lists = cloudflare_config.get('ip_lists', [])
    if not isinstance(ip_lists, list):
        logging.error("IP lists in configuration file is not a list")
        sys.exit(1)

    ip_list_map = process_ip_lists(ip_lists)
    logging.info(f"Processed {len(ip_list_map)} IP lists")

    # Process WAF configuration
    waf_config = cloudflare_config.get('waf', {})
    default_settings = waf_config.get('default', {})
    zones = waf_config.get('zones', [])

    if not zones:
        logging.warning("No zones found in configuration")
        return

    # Process each zone
    for zone in zones:
        zone_id = zone.get('id')
        domain = zone.get('domain')
        zone_settings = zone.get('waf', {})

        if not zone_id or not domain:
            logging.error("Zone ID or domain not found for a zone")
            continue

        try:
            # Merge default and zone-specific settings
            merged_settings = {**default_settings, **zone_settings}
            
            # Convert any rule expressions that use IP lists
            if 'custom_rules' in merged_settings:
                for rule in merged_settings['custom_rules']:
                    if 'expression' in rule:
                        rule['expression'] = replace_ip_list_variables(rule['expression'], ip_list_map)
            
            settings = WAFSettings.model_validate(merged_settings)
            logging.info(f"Processing zone {domain} ({zone_id})...")
            apply_waf_settings(api, zone_id, settings, ip_list_map)
            
        except Exception as e:
            logging.error(f"Failed to process zone {domain} ({zone_id}): {e}")
            continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare WAF settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    main(args.config)
