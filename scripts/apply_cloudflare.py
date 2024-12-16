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
import time

# Configure logging
GITHUB_ACTIONS = os.getenv('GITHUB_ACTIONS') == 'true'
log_format = '::%(levelname)s :: %(message)s' if GITHUB_ACTIONS else '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)

# Model definitions
class FirewallSettings(BaseModel):
    security_level: Optional[str] = "medium"
    browser_integrity_check: Optional[str] = "on"
    automatic_https_rewrites: Optional[str] = "on"


    @field_validator("security_level")
    @classmethod
    def validate_security_level(cls, value: str) -> str:
        valid_levels = {"off", "essentially_off", "low", "medium", "high", "under_attack"}
        if value not in valid_levels:
            raise ValueError(f"Invalid security level. Choose one of {valid_levels}")
        return value

    @field_validator("browser_integrity_check")
    @classmethod
    def validate_browser_integrity_check(cls, value: str) -> str:
        valid_values = {"on", "off"}
        if value not in valid_values:
            raise ValueError(f"Invalid browser integrity check value. Choose one of {valid_values}")
        return value

    @field_validator("automatic_https_rewrites")
    @classmethod
    def validate_automatic_https_rewrites(cls, value: str) -> str:
        valid_values = {"on", "off"}
        if value not in valid_values:
            raise ValueError(f"Invalid automatic https rewrites value. Choose one of {valid_values}")
        return value


class WAFRule(BaseModel):
    description: str
    expression: str
    action: str

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        valid_actions = {"block", "challenge", "allow", "log", "bypass"}
        if value not in valid_actions:
            raise ValueError(f"Invalid WAF rule action. Choose one of {valid_actions}")
        return value

class WAFSettings(BaseModel):
    firewall_settings: Optional[FirewallSettings] = None
    rules: Optional[List[WAFRule]] = None

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


    # Apply Browser Integrity Check
    if settings.firewall_settings and settings.firewall_settings.browser_integrity_check:
        try:
            bic_url = f"{base_url}/settings/browser_check"
            result = api.make_request(
                "PATCH",
                bic_url,
                {"value": settings.firewall_settings.browser_integrity_check}
            )
            if result.get('success'):
                updated_settings["browser_integrity_check"] = result
                logging.info(f"Successfully updated browser integrity check to {settings.firewall_settings.browser_integrity_check}")
        except Exception as e:
            logging.error(f"Failed to update browser integrity check: {e}")

    # Apply Automatic HTTPS Rewrites
    if settings.firewall_settings and settings.firewall_settings.automatic_https_rewrites:
        try:
            https_url = f"{base_url}/settings/automatic_https_rewrites"
            result = api.make_request(
                "PATCH",
                https_url,
                {"value": settings.firewall_settings.automatic_https_rewrites}
            )
            if result.get('success'):
                updated_settings["automatic_https_rewrites"] = result
                logging.info(f"Successfully updated automatic https rewrites to {settings.firewall_settings.automatic_https_rewrites}")
        except Exception as e:
             logging.error(f"Failed to update automatic https rewrites: {e}")

    # Apply Custom WAF Rules
    if settings.rules:
         updated_settings["rules"] = apply_waf_rules(api, zone_id, settings.rules)


    return updated_settings

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def apply_waf_rules(api: CloudflareAPI, zone_id: str, rules: List[WAFRule]) -> List[Dict[str, Any]]:
    logging.info(f"Applying WAF rules for zone {zone_id}...")
    ruleset_id = get_ruleset_id(api, zone_id)
    if not ruleset_id:
        logging.error(f"Failed to retrieve or create WAF ruleset id for zone {zone_id}, WAF rules will not be applied")
        return []
    
    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}/rules"
    results = []

    for rule in rules:
       try:
            # Find existing rule with the same description:
            existing_rule_id = find_existing_rule_id(api, base_url, rule.description)

            if existing_rule_id:
                # Update the rule
                result = api.make_request(
                    "PUT",
                     f"{base_url}/{existing_rule_id}",
                     {"description": rule.description,
                     "expression": rule.expression,
                     "action": rule.action
                     }
                )
                if result.get("success"):
                    logging.info(f"Successfully updated WAF rule: {rule.description}")
                    results.append(result)
                else:
                    logging.error(f"Failed to update WAF rule: {rule.description}")
                    results.append(result)

            else:
                # Create new rule
                result = api.make_request(
                    "POST",
                     base_url,
                     {"description": rule.description,
                      "expression": rule.expression,
                      "action": rule.action
                    }
                )
                if result.get("success"):
                   logging.info(f"Successfully created WAF rule: {rule.description}")
                   results.append(result)
                else:
                   logging.error(f"Failed to create WAF rule: {rule.description}")
                   results.append(result)

       except Exception as e:
            logging.error(f"Failed to create/update rule {rule.description}: {e}")
            results.append({"success": False, "errors": [{"message": str(e)}]})
    return results

def get_ruleset_id(api: CloudflareAPI, zone_id: str) -> Optional[str]:
    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    try:
        response = api.make_request("GET", base_url)
        if response.get("success"):
             rulesets = response.get("result", [])
             for ruleset in rulesets:
                 if ruleset.get("phase") == "http_request_firewall_custom":
                     return ruleset.get("id")
        else:
             logging.error(f"Error fetching rulesets: {response}")
             logging.error(f"Response: {response}")
        
        # Create ruleset if not found
        logging.info(f"Ruleset not found creating default ruleset for {zone_id}")
        ruleset_id = create_default_ruleset(api, zone_id)
        return ruleset_id
    except Exception as e:
        logging.error(f"Error getting or creating ruleset id {e}")
        return None
    
def create_default_ruleset(api: CloudflareAPI, zone_id:str) -> Optional[str]:
    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    temp_rule = {
            "description": "Temporary rule to create ruleset",
            "expression": "true",
            "action": "log"
        }
    try:
        # Get the Ruleset ID
        ruleset_id = get_ruleset_id(api, zone_id)
        if not ruleset_id:
            logging.error(f"Failed to get ruleset ID in create_default_ruleset for zone {zone_id}")
            return None

        # Create a default rule in the ruleset to force its creation if it doesn't exist:
        response = api.make_request("POST", f"{base_url}/{ruleset_id}/rules", json_data=temp_rule)

        if response.get("success"):
            # Now that the ruleset was created we need to delete the temporary rule
            rule_id = response.get("result").get("id")
            time.sleep(5)
            delete_result = api.make_request("DELETE", f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}")
            if delete_result.get("success"):
                logging.info(f"Temporary rule deleted succesfully from zone: {zone_id}")
                return ruleset_id
            else:
                logging.error(f"Error deleting temporary rule: {delete_result}")
                logging.error(f"Response: {delete_result}")
                return None
        else:
            logging.error(f"Error creating default ruleset: {response}")
            logging.error(f"Response: {response}")
            return None

    except Exception as e:
        logging.error(f"Error creating default ruleset: {e}")
        return None
    

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def find_existing_rule_id(api: CloudflareAPI, base_url:str, description: str) -> Optional[str]:
    try:
        response = api.make_request("GET", base_url)
        if response.get("success"):
            rules = response.get("result", [])
            for rule in rules:
               if rule.get("description") == description:
                   return rule.get("id")
        else:
            logging.error(f"Error fetching rules {response}")
            return None

    except Exception as e:
        logging.error(f"Error finding existing rule: {e}")
        return None

    return None



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
            settings = WAFSettings.model_validate(merged_settings)
            logging.info(f"Processing zone {domain} ({zone_id})...")
            apply_waf_settings(api, zone_id, settings)
        except Exception as e:
            logging.error(f"Failed to process zone {domain} ({zone_id}): {e}")
            continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply Cloudflare WAF settings from a configuration file.")
    parser.add_argument('--config', type=str, required=True, help="Path to the configuration YAML file.")
    args = parser.parse_args()

    main(args.config)
