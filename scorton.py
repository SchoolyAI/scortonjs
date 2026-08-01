#!/usr/bin/env python3
"""
ScortonJS - Production-ready security auditing tool.

A comprehensive Framework and CLI for security scanning, scoring, and compliance auditing.
Supports multiple security tools and frameworks including DORA and NIS2.

Author: ScortonJS Team
License: MIT
Version: 1.0.0
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Version information
__version__ = "1.0.0"
__author__ = "ScortonJS Team"

# Mapping of CLI tool names to API endpoints
ENDPOINTS = {
    "cookie_scan": "cookie_scan",
    "dir_scan": "dir_scan", 
    "dns_enum": "dns_enum",
    "headers_check": "headers_check",
    "methods_scan": "methods_scan",
    "port_scan": "port_scan",
    "reverse_dns": "reverse_dns",
    "ssl_scan": "ssl_scan",
    "url_analyze": "url_analyze",
    "whois_scan": "whois_scan",
    "xss_scan": "xss_scan",
}

# Default configuration
DEFAULT_CONFIG = {
    "api_url": "http://localhost:8000",
    "timeout": 30,
    "max_retries": 3,
    "retry_backoff": 0.3,
}


class ScortonError(Exception):
    """Base exception for Scorton CLI errors."""
    pass


class APIError(ScortonError):
    """Exception raised for API-related errors."""
    pass


class ConfigurationError(ScortonError):
    """Exception raised for configuration-related errors."""
    pass


class ScortonClient:
    """Production-ready Scorton API client with retry logic and error handling."""
    
    def __init__(self, api_base: str, token: str, timeout: int = 30, max_retries: int = 3):
        """
        Initialize the Scorton API client.
        
        Args:
            api_base: Base URL of the Scorton API
            token: JWT authentication token
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.api_base = api_base.rstrip('/')
        self.token = token
        self.timeout = timeout
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "AUTH": token,
            "User-Agent": f"ScortonCLI/{__version__}"
        })
    
    def call_api(self, endpoint: str, target: str, mode: Optional[str] = None) -> Dict[str, Any]:
        """
        Make API call with proper error handling and retry logic.
        
        Args:
            endpoint: API endpoint to call
            target: Target domain or URL to analyze
            mode: Optional mode parameter (e.g., 'deep' for audit)
            
        Returns:
            Parsed JSON response as dictionary
            
        Raises:
            APIError: If API call fails after retries
        """
        url = f"{self.api_base}/{endpoint}"
        payload = {"target": target}
        if mode:
            payload["mode"] = mode
        
        logger.info(f"Making API call to {url} for target: {target}")
        
        try:
            response = self.session.post(
                url, 
                json=payload, 
                timeout=self.timeout
            )
            response.raise_for_status()
            
        except requests.exceptions.Timeout:
            raise APIError(f"Request timeout after {self.timeout}s for {url}")
        except requests.exceptions.ConnectionError as e:
            raise APIError(f"Connection error for {url}: {e}")

        except requests.exceptions.HTTPError as e:
            resp = getattr(e, "response", None)
            status = resp.status_code if resp is not None else "unknown"
            body_preview = resp.text[:400] if resp is not None else "No response body"
            raise APIError(f"HTTP error{status} for{url}:{body_preview}")

        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed for {url}: {e}")
        
        try:
            data = response.json()
        except ValueError as e:
            raise APIError(f"Invalid JSON response from {url}: {e}")
        
        # Normalize response format
        if isinstance(data, dict):
            return data
        elif isinstance(data, list):
            return {"status": "ok", "data": data}
        else:
            return {"status": "unknown", "raw": data}


def validate_url(url: str) -> bool:
    """Validate if the provided string is a valid URL."""
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def get_auth_config(args: argparse.Namespace) -> Tuple[str, str]:
    """
    Get API base URL and token from args or environment variables.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Tuple of (api_base_url, auth_token)
        
    Raises:
        ConfigurationError: If required configuration is missing
    """
    token = args.token or os.environ.get("SCORTON_TOKEN")
    if not token:
        raise ConfigurationError(
            "Authentication token is required. Provide --token or set SCORTON_TOKEN environment variable."
        )
    
    api_base = args.api or os.environ.get("SCORTON_API_URL", DEFAULT_CONFIG["api_url"])
    
    # Validate API URL
    if not validate_url(api_base):
        raise ConfigurationError(f"Invalid API URL: {api_base}")
    
    return api_base, token


def run_scan(args: argparse.Namespace) -> None:
    """Run a security scan using specified tool."""
    if args.tool not in ENDPOINTS:
        available_tools = ', '.join(sorted(ENDPOINTS.keys()))
        raise ScortonError(f"Unknown tool '{args.tool}'. Available tools: {available_tools}")
    
    try:
        api_base, token = get_auth_config(args)
        client = ScortonClient(api_base, token)
        
        result = client.call_api(ENDPOINTS[args.tool], args.target)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
    except (ConfigurationError, APIError, ScortonError) as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during scan: {e}")
        sys.exit(1)


def run_score(args: argparse.Namespace) -> None:
    """Calculate Cyberscore for target."""
    try:
        api_base, token = get_auth_config(args)
        client = ScortonClient(api_base, token)
        
        result = client.call_api("score", args.target)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
    except (ConfigurationError, APIError, ScortonError) as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during scoring: {e}")
        sys.exit(1)


def run_audit(args: argparse.Namespace) -> None:
    """Run deep CyberAudit for target."""
    try:
        api_base, token = get_auth_config(args)
        client = ScortonClient(api_base, token)
        
        result = client.call_api("score", args.target, mode="deep")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
    except (ConfigurationError, APIError, ScortonError) as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during audit: {e}")
        sys.exit(1)


def run_config(args: argparse.Namespace) -> None:
    """Show current configuration or help with setting environment variables."""
    config = {
        "SCORTON_API_URL": os.environ.get("SCORTON_API_URL", DEFAULT_CONFIG["api_url"]),
        "SCORTON_TOKEN": "***" if os.environ.get("SCORTON_TOKEN") else "Not set"
    }
    
    if args.set:
        try:
            key, value = args.set.split("=", 1)
            print(f"To set {key}={value}, run:")
            print(f"export {key}={value}")
            return
        except ValueError:
            raise ScortonError("Invalid format for --set. Use KEY=VALUE format.")
    
    print("Current Scorton CLI configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")


def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up the command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="scorton",
        description="Scorton security auditing CLI - Production-ready security scanning and compliance tool",
        epilog=f"Version {__version__} | For more information, visit https://github.com/scortonjs/scortonjs",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version=f"Scorton CLI {__version__}"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Common arguments for API commands
    def add_common_args(subparser):
        subparser.add_argument(
            "--api", 
            help="Base URL of the Scorton API (default: http://localhost:8000)"
        )
        subparser.add_argument(
            "--token", 
            help="JWT authentication token (can also be set via SCORTON_TOKEN env var)"
        )
        subparser.add_argument(
            "--timeout",
            type=int,
            default=DEFAULT_CONFIG["timeout"],
            help=f"Request timeout in seconds (default: {DEFAULT_CONFIG['timeout']})"
        )
    
    # Scan command
    scan_parser = subparsers.add_parser(
        "scan", 
        help="Run a security scan using specified tool"
    )
    scan_parser.add_argument(
        "tool", 
        help="Security tool to invoke",
        choices=sorted(ENDPOINTS.keys()),
        metavar="TOOL"
    )
    scan_parser.add_argument(
        "target", 
        help="Domain or URL to analyze",
        metavar="TARGET"
    )
    add_common_args(scan_parser)
    scan_parser.set_defaults(func=run_scan)
    
    # Score command
    score_parser = subparsers.add_parser(
        "score", 
        help="Calculate Cyberscore for target"
    )
    score_parser.add_argument(
        "target", 
        help="Domain or URL to analyze",
        metavar="TARGET"
    )
    add_common_args(score_parser)
    score_parser.set_defaults(func=run_score)
    
    # Audit command
    audit_parser = subparsers.add_parser(
        "audit", 
        help="Run deep CyberAudit for target"
    )
    audit_parser.add_argument(
        "target", 
        help="Domain or URL to analyze",
        metavar="TARGET"
    )
    add_common_args(audit_parser)
    audit_parser.set_defaults(func=run_audit)
    
    # Config command
    config_parser = subparsers.add_parser(
        "config", 
        help="Show current configuration or help with environment variables"
    )
    config_parser.add_argument(
        "--set", 
        help="Show export command for KEY=VALUE"
    )
    config_parser.set_defaults(func=run_config)
    
    return parser


def main(argv: Optional[list] = None) -> None:
    """Main entry point for the Scorton CLI."""
    try:
        parser = setup_argument_parser()
        args = parser.parse_args(argv)
        
        # Configure logging level
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Handle help command or no command
        if args.command in (None, "help"):
            parser.print_help()
            return
        
        # Execute the command
        args.func(args)
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

