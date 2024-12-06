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

# Configure logging
GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS') == 'true'
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
        valid_actions = {"block", "challenge", "allow", "js_challenge"}
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

    def get_existing_rules(self, zone_id: str) -> List[Dict[str, Any]]:
        """Get existing firewall rules for a zone"""
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
        try:
            response = self.make_request("GET", url)
            if response.get('success'):
                return response.get('result', [])
            return []
        except Exception as e:
            logging.error(f"Failed to get existing rules: {e}")
            return []


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
                logging.info(f"Successfully updated security level to {settings.firewall_settings.security_level}")
        except Exception as e:
            logging.error(f"Failed to update security level: {e}")

    # Handle Custom Rules
    if settings.custom_rules:
        try:
            # Get existing rules
            existing_rules = api.get_existing_rules(zone_id)
            
            # Delete existing rules if any
            for rule in existing_rules:
                delete_url = f"{base_url}/firewall/rules/{rule['id']}"
                api.make_request("DELETE", delete_url)
                logging.info(f"Deleted existing rule: {rule.get('description', 'unnamed rule')}")

            # Ensure we don't exceed the free plan limit
            rules_to_create = settings.custom_rules[:5]
            if len(settings.custom_rules) > 5:
                logging.warning("More than 5 rules provided. Only the first 5 will be created (free plan limit).")

            # Create new rules
            if rules_to_create:
                rules_url = f"{base_url}/firewall/rules"
                rules_data = []
                
                for rule in rules_to_create:
                    rule_data = {
                        "description": rule.description or rule.name,
                        "expression": rule.expression,
                        "action": rule.action,
                        "enabled": True
                    }
                    rules_data.append(rule_data)

                result = api.make_request("POST", rules_url, {"rules": rules_data})
                if result.get('success'):
                    updated_settings["custom_rules"] = result
                    logging.info(f"Successfully created {len(rules_data)} WAF rules")
                else:
                    logging.error(f"Failed to create WAF rules: {result.get('errors', [])}")

        except Exception as e:
            logging.error(f"Failed to manage WAF rules: {e}")

    return updated_settings


def main(config_path: str):
    # [Previous main function code remains the same]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare WAF settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    main(args.config)
