#!/usr/bin/env python3
"""
Web Discovery Scanner - Enhanced Version
"""

import argparse
import asyncio
import csv
import json
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
import ipaddress
import socket
import ssl
import hashlib
import logging
from dataclasses import dataclass
import re
import colorama
from colorama import Fore, Back, Style
import msvcrt

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import xml.etree.ElementTree as ET
    from playwright.async_api import async_playwright
    from tqdm import tqdm
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install requests playwright tqdm colorama")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

# Custom colored logging
class ColoredFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            color = Fore.GREEN
        elif record.levelno == logging.WARNING:
            color = Fore.YELLOW
        elif record.levelno == logging.ERROR:
            color = Fore.RED
        elif record.levelno == logging.DEBUG:
            color = Fore.CYAN
        else:
            color = Fore.WHITE
        
        record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

# Setup colored logging
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

@dataclass
class WebService:
    ip: str
    port: int = 0
    protocol: str = ""
    title: str = ""
    status_code: int = 0
    headers: Dict[str, str] = None
    fingerprint: str = ""
    screenshot_file: str = ""
    service_type: str = ""
    specific_target: str = ""
    vulnerabilities: List[str] = None
    cert_expiry: Optional[str] = None
    cert_status: str = ""
    server_banner: str = ""
    html_snippet: str = ""
    cookies: List[str] = None
    subdomains: List[str] = None
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_sans: List[str] = None
    is_subdomain: bool = False
    original_target: str = ""
    discovered_paths: List[str] = None
    domain_name: str = ""  # Reverse DNS lookup result
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.cookies is None:
            self.cookies = []
        if self.subdomains is None:
            self.subdomains = []
        if self.cert_sans is None:
            self.cert_sans = []
        if self.discovered_paths is None:
            self.discovered_paths = []

class ProgressTracker:
    def __init__(self, total_targets: int, total_ports: int):
        self.total_targets = total_targets
        self.total_ports = total_ports
        self.total_tasks = total_targets * total_ports
        self.completed_tasks = 0
        self.current_target = ""
        self.current_port = 0
        self.current_status = "Initializing..."
        self.pbar = None
        self.lock = threading.Lock()
        self.skip_current = False
        self.keyboard_thread = None
    
    def start(self):
        print(f"{Fore.CYAN}🚀 {Style.BRIGHT}Starting Web Discovery Scanner{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📊 {Style.BRIGHT}Targets: {self.total_targets} | Ports: {self.total_ports} | Total Tasks: {self.total_tasks}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}⏱️  {Style.BRIGHT}Estimated time: {self.total_tasks * 3:.0f}s{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}⌨️  {Style.BRIGHT}Press 's' to skip current website scan{Style.RESET_ALL}")
        print("-" * 60)
        self.pbar = tqdm(total=self.total_tasks, desc="🔍 Scanning", unit="target:port", 
                        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]')
        
        # Start keyboard input thread
        self.keyboard_thread = threading.Thread(target=self._keyboard_listener, daemon=True)
        self.keyboard_thread.start()
    
    def _keyboard_listener(self):
        """Listen for keyboard input to skip current scan"""
        while True:
            try:
                if msvcrt.kbhit():
                    key = msvcrt.getch().decode('utf-8').lower()
                    if key == 's':
                        with self.lock:
                            self.skip_current = True
                        print(f"\n{Fore.YELLOW}⏭️  {Style.BRIGHT}Skipping current scan...{Style.RESET_ALL}")
            except:
                pass
            time.sleep(0.1)
    
    def update_status(self, target: str, port: int, status: str):
        with self.lock:
            self.current_target = target
            self.current_port = port
            self.current_status = status
            
            # Emoji mapping for different statuses
            status_emojis = {
                "Checking service...": "🔍",
                "Analyzing service...": "🔬",
                "Checking certificate...": "🔐",
                "Discovering subdomains...": "🌐",
                "Checking vulnerabilities...": "🛡️",
                "Taking screenshot...": "📸",
                "Starting main target scan...": "🎯",
                "Starting subdomain scan": "🔗",
                "Generating final report...": "📋"
            }
            
            emoji = status_emojis.get(status, "⚡")
            if self.pbar:
                self.pbar.set_description(f"{emoji} {target}:{port} - {status}")
    
    def increment(self):
        with self.lock:
            self.completed_tasks += 1
            self.skip_current = False  # Reset skip flag
            if self.pbar:
                self.pbar.update(1)
    
    def should_skip(self):
        """Check if current scan should be skipped"""
        with self.lock:
            return self.skip_current
    
    def close(self):
        if self.pbar:
            self.pbar.close()
        print(f"{Fore.GREEN}✅ {Style.BRIGHT}Scan completed!{Style.RESET_ALL}")

class WebDiscoveryScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.results = []
        self.vulnerability_groups = {}
        self.output_dir = Path(config.get('output', 'outputs'))
        self.screenshots_dir = self.output_dir / "screenshots"
        self.output_dir.mkdir(exist_ok=True)
        self.screenshots_dir.mkdir(exist_ok=True)
        
        self.ports = config.get('ports', [80, 443, 8080, 8000, 8443, 8888, 81, 82, 7000, 9443])
        self.progress_tracker = None
        self.original_targets = []  # Store original scan targets
        
        # Default credentials for testing (10 common pairs)
        self.default_credentials = [
            ('admin', 'admin'),
            ('admin', '123456'),
            ('admin', 'password'),
            ('admin', 'admin123'),
            ('root', 'root'),
            ('root', 'password'),
            ('user', 'user'),
            ('user', 'password'),
            ('guest', 'guest'),
            ('test', 'test')
        ]
        
        # Initialize credentials (will be loaded only if credential checking is enabled)
        self.credentials = []
        
        # Load credentials if credential checking is enabled
        if self.config.get('creds_check', False):
            self.credentials = self._load_credentials()
        
        self.session = self._create_session()
        
        # Service type patterns
        self.service_patterns = {
            'printer': [
                r'printer', r'print', r'hp', r'canon', r'epson', r'brother', r'lexmark',
                r'web interface', r'printer management', r'print server'
            ],
            'storage': [
                r'nas', r'san', r'storage', r'backup', r'synology', r'qnap', r'netgear',
                r'file server', r'storage management', r'raid'
            ],
            'login': [
                r'login', r'sign in', r'authentication', r'admin', r'user portal',
                r'access control', r'identity', r'sso'
            ],
            'camera': [
                r'camera', r'ip cam', r'surveillance', r'security', r'axis', r'hikvision',
                r'dahua', r'foscam', r'webcam'
            ],
            'router': [
                r'router', r'gateway', r'firewall', r'network', r'cisco', r'juniper',
                r'fortinet', r'checkpoint', r'ubiquiti'
            ],
            'database': [
                r'database', r'mysql', r'postgresql', r'oracle', r'sql server',
                r'mongodb', r'redis', r'phpmyadmin'
            ],
            'monitoring': [
                r'monitoring', r'grafana', r'kibana', r'prometheus', r'nagios',
                r'zabbix', r'observability', r'metrics'
            ],
            'development': [
                r'jenkins', r'gitlab', r'github', r'jira', r'confluence', r'sonarqube',
                r'nexus', r'artifactory', r'development'
            ],
            'ci_cd_lateral': [
                # CI/CD Systems
                r'jenkins', r'gitlab', r'github', r'bitbucket', r'jira', r'confluence',
                r'teamcity', r'bamboo', r'circleci', r'travis', r'gitlab-ci', r'github actions',
                r'azure devops', r'aws codebuild', r'gocd', r'tekton', r'argo', r'spinnaker',
                # Build Tools & Artifact Repositories
                r'nexus', r'artifactory', r'sonarqube', r'fortify', r'checkmarx',
                r'maven', r'gradle', r'npm', r'yarn', r'docker registry', r'harbor',
                # Container Orchestration & Management
                r'kubernetes', r'openshift', r'rancher', r'docker swarm', r'mesos',
                r'nomad', r'consul', r'etcd', r'vault', r'helm',
                # Infrastructure & Configuration Management
                r'ansible', r'terraform', r'chef', r'puppet', r'salt', r'cloudformation',
                r'pulumi', r'packer', r'vagrant',
                # Monitoring & Observability (CI/CD related)
                r'prometheus', r'grafana', r'kibana', r'elasticsearch', r'jaeger',
                r'zipkin', r'istio', r'linkerd', r'envoy',
                # Development Tools & IDEs
                r'vscode server', r'code-server', r'eclipse che', r'theia',
                r'gitpod', r'codespaces', r'cloud9',
                # Version Control & Collaboration
                r'gitea', r'gogs', r'gitblit', r'gerrit', r'phabricator',
                r'redmine', r'mantis', r'trello', r'asana', r'clickup',
                # Testing & Quality Assurance
                r'selenium', r'cypress', r'playwright', r'junit', r'testng',
                r'postman', r'newman', r'jmeter', r'gatling',
                # Security & Compliance
                r'fortify', r'checkmarx', r'sonarqube', r'veracode', r'coverity',
                r'blackduck', r'snyk', r'dependabot', r'whitesource',
                # Deployment & Release Management
                r'octopus deploy', r'xl deploy', r'urban code deploy', r'harness',
                r'gitops', r'flux', r'argocd', r'tekton', r'jenkins x',
                # Service Mesh & API Management
                r'istio', r'linkerd', r'consul connect', r'kong', r'apigee',
                r'aws api gateway', r'azure api management', r'google cloud endpoints'
            ]
        }
        
        # High-value lateral movement targets
        self.lateral_movement_targets = {
            'jenkins': ['jenkins', 'hudson'],
            'gitlab': ['gitlab'],
            'github': ['github'],
            'bitbucket': ['bitbucket'],
            'jira': ['jira'],
            'confluence': ['confluence'],
            'nexus': ['nexus', 'sonatype'],
            'artifactory': ['artifactory', 'jfrog'],
            'sonarqube': ['sonarqube'],
            'kubernetes': ['kubernetes', 'k8s', 'openshift'],
            'rancher': ['rancher'],
            'vault': ['vault', 'hashicorp'],
            'consul': ['consul', 'hashicorp'],
            'ansible': ['ansible', 'red hat'],
            'terraform': ['terraform', 'hashicorp'],
            'prometheus': ['prometheus'],
            'grafana': ['grafana'],
            'elasticsearch': ['elasticsearch', 'elastic'],
            'docker': ['docker', 'registry'],
            'harbor': ['harbor']
        }
        
        # Common subdomain patterns
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging', 'api',
            'cdn', 'static', 'media', 'img', 'images', 'assets', 'docs', 'help',
            'support', 'forum', 'community', 'shop', 'store', 'app', 'mobile',
            'webmail', 'remote', 'vpn', 'portal', 'dashboard', 'monitor', 'status',
            'jenkins', 'gitlab', 'github', 'jira', 'confluence', 'nexus', 'artifactory',
            'sonarqube', 'prometheus', 'grafana', 'kibana', 'elasticsearch', 'rancher',
            'kubernetes', 'k8s', 'openshift', 'vault', 'consul', 'ansible', 'terraform'
        ]
    
    def _create_session(self):
        session = requests.Session()
        # Faster retry strategy
        retry_strategy = Retry(total=2, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.timeout = self.config.get('timeout', 3)  # Reduced from 5
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        # Disable SSL warnings and verification
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        return session
    
    def _load_credentials(self) -> List[Tuple[str, str]]:
        """Load credentials from file or use defaults"""
        # Only load credentials if credential checking is enabled
        if not self.config.get('creds_check', False):
            return []
            
        creds_file = self.config.get('creds_file')
        
        if creds_file and Path(creds_file).exists():
            try:
                credentials = []
                with open(creds_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                username, password = parts[0].strip(), parts[1].strip()
                                credentials.append((username, password))
                logger.info(f"Loaded {len(credentials)} credentials from {creds_file}")
                return credentials
            except Exception as e:
                logger.error(f"Error loading credentials from {creds_file}: {e}")
        
        # Return default credentials if no file provided or file not found
        logger.info(f"Using {len(self.default_credentials)} default credentials")
        return self.default_credentials
    
    def parse_input(self, input_source: str, input_type: str) -> List[str]:
        if input_type == 'input':
            targets = []
            # Handle comma-separated values
            for item in input_source.split(','):
                item = item.strip()
                if not item:
                    continue
                try:
                    network = ipaddress.ip_network(item, strict=False)
                    targets.extend([str(ip) for ip in network.hosts()])
                except ValueError:
                    targets.append(item)
            return targets
        elif input_type == 'input_file':
            targets = []
            try:
                with open(input_source, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.extend(self.parse_input(line, 'input'))
            except FileNotFoundError:
                logger.error(f"Input file not found: {input_source}")
            return targets
        return []
    
    def scan_ports(self, target: str) -> List[int]:
        open_ports = []
        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Reduced from 2 seconds
                if sock.connect_ex((target, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports
    
    def _identify_service_type(self, service: WebService) -> str:
        """Identify the type of service based on title, headers, and content"""
        content_to_check = [
            service.title.lower(),
            service.server_banner.lower(),
            service.html_snippet.lower()
        ]
        
        # First check for CI/CD and lateral movement targets (highest priority)
        for service_type, patterns in self.service_patterns.items():
            for pattern in patterns:
                for content in content_to_check:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Log service type with color
                        service_colors = {
                            'jenkins': f"{Fore.BLUE}🔧 Jenkins CI/CD{Style.RESET_ALL}",
                            'gitlab': f"{Fore.GREEN}🐙 GitLab{Style.RESET_ALL}",
                            'github': f"{Fore.BLACK}🐙 GitHub{Style.RESET_ALL}",
                            'jira': f"{Fore.BLUE}📋 Jira{Style.RESET_ALL}",
                            'confluence': f"{Fore.BLUE}📚 Confluence{Style.RESET_ALL}",
                            'sonarqube': f"{Fore.CYAN}🔍 SonarQube{Style.RESET_ALL}",
                            'nexus': f"{Fore.YELLOW}📦 Nexus Repository{Style.RESET_ALL}",
                            'artifactory': f"{Fore.MAGENTA}🎨 Artifactory{Style.RESET_ALL}",
                            'docker': f"{Fore.BLUE}🐳 Docker Registry{Style.RESET_ALL}",
                            'kubernetes': f"{Fore.BLUE}☸️ Kubernetes{Style.RESET_ALL}",
                            'prometheus': f"{Fore.RED}📊 Prometheus{Style.RESET_ALL}",
                            'grafana': f"{Fore.CYAN}📈 Grafana{Style.RESET_ALL}",
                            'kibana': f"{Fore.BLUE}📊 Kibana{Style.RESET_ALL}",
                            'elasticsearch': f"{Fore.YELLOW}🔍 Elasticsearch{Style.RESET_ALL}",
                            'web': f"{Fore.GREEN}🌐 Web Service{Style.RESET_ALL}"
                        }
                        
                        colored_service = service_colors.get(service_type, f"{Fore.WHITE}{service_type}{Style.RESET_ALL}")
                        logger.info(f"🔍 Identified service type: {colored_service}")
                        return service_type
        
        logger.info(f"🔍 Identified service type: {Fore.GREEN}🌐 Web Service{Style.RESET_ALL}")
        return "web"
    
    def _identify_specific_target(self, service: WebService) -> str:
        """Identify specific lateral movement target type"""
        content_to_check = [
            service.title.lower(),
            service.server_banner.lower(),
            service.html_snippet.lower()
        ]
        
        for target_name, keywords in self.lateral_movement_targets.items():
            for keyword in keywords:
                for content in content_to_check:
                    if re.search(rf'\b{re.escape(keyword)}\b', content, re.IGNORECASE):
                        return target_name
        
        return ""
    
    def _check_vulnerabilities(self, service: WebService) -> List[str]:
        """Check for common vulnerabilities"""
        vulns = []
        
        # Check for expired certificates
        if service.protocol == 'https' and service.cert_status == "Expired":
            vulns.append("expired_certificate")
        
        # Check for default credentials indicators
        if any(keyword in service.title.lower() for keyword in ['admin', 'default', 'login']):
            if any(keyword in service.html_snippet.lower() for keyword in ['admin', 'password', 'username']):
                vulns.append("potential_default_creds")
        
        # Test actual default credentials
        working_creds = self._test_default_credentials(service)
        if working_creds:
            vulns.append(f"default_creds_working:{','.join(working_creds)}")
            logger.warning(f"🔑 {Fore.RED}Default credentials found: {', '.join(working_creds)}{Style.RESET_ALL}")
        
        # Check for server information disclosure with details
        if service.server_banner and len(service.server_banner) > 0:
            vulns.append(f"server_info_disclosure:{service.server_banner}")
            logger.warning(f"ℹ️ {Fore.CYAN}Server info disclosure: {service.server_banner}{Style.RESET_ALL}")
        
        # Check for expired certificates
        if service.protocol == 'https' and service.cert_status == "Expired":
            vulns.append("expired_certificate")
            logger.warning(f"⚠️ {Fore.RED}Expired certificate detected{Style.RESET_ALL}")
        
        return vulns
    
    def _test_default_credentials(self, service: WebService) -> List[str]:
        """Test default credentials against login pages and basic auth"""
        if not self.config.get('creds_check', False):  # Default to False (disabled)
            return []
        
        working_creds = []
        url = f"{service.protocol}://{service.ip}:{service.port}"
        
        # Test HTTP Basic Authentication first
        basic_auth_creds = self._test_basic_auth(url)
        if basic_auth_creds:
            working_creds.extend(basic_auth_creds)
        
        # Test form-based login if no basic auth found
        if not working_creds:
            form_creds = self._test_form_login(service, url)
            if form_creds:
                working_creds.extend(form_creds)
        
        return working_creds
    
    def _test_basic_auth(self, url: str) -> List[str]:
        """Test HTTP Basic Authentication with response comparison to reduce false positives"""
        working_creds = []
        
        # First, get the baseline response without authentication
        try:
            baseline_response = self.session.get(url, verify=False, timeout=5)
            baseline_body = baseline_response.text
            baseline_status = baseline_response.status_code
            logger.debug(f"🔍 Baseline response for {url}: status={baseline_status}, body_length={len(baseline_body)}")
        except Exception as e:
            logger.debug(f"Error getting baseline response for {url}: {e}")
            baseline_body = ""
            baseline_status = 0
        
        for username, password in self.credentials:
            try:
                # Test basic auth on the main URL
                auth_response = self.session.get(url, auth=(username, password), verify=False, timeout=5)
                
                # Compare responses to detect if credentials actually work
                if auth_response.status_code == 200:
                    auth_body = auth_response.text
                    
                    # If response body is identical to baseline, it's likely a false positive
                    if auth_body == baseline_body:
                        logger.debug(f"⚠️ False positive detected: identical response for {username}:{password} on {url}")
                        continue
                    
                    # Check if the response contains login success indicators
                    response_text = auth_body.lower()
                    success_indicators = ['dashboard', 'welcome', 'admin', 'panel', 'home', 'main']
                    failure_indicators = ['login', 'signin', 'auth', 'password', 'username', 'invalid', 'incorrect']
                    
                    # If we see success indicators and no failure indicators, it's likely successful
                    has_success = any(indicator in response_text for indicator in success_indicators)
                    has_failure = any(indicator in response_text for indicator in failure_indicators)
                    
                    if has_success and not has_failure:
                        working_creds.append(f"{username}:{password}")
                        logger.info(f"🔑 Basic auth credentials found: {username}:{password} on {url}")
                        logger.warning(f"🔑 Default credentials found: {username}:{password}")
                        break
                    else:
                        logger.debug(f"⚠️ 200 response but likely failed login for {username}:{password} on {url}")
                
                # Also test common basic auth paths
                basic_auth_paths = ['/admin', '/login', '/auth', '/api', '/management']
                for path in basic_auth_paths:
                    try:
                        auth_url = url + path
                        
                        # Get baseline for this path
                        try:
                            baseline_path_response = self.session.get(auth_url, verify=False, timeout=5)
                            baseline_path_body = baseline_path_response.text
                        except:
                            baseline_path_body = ""
                        
                        auth_response = self.session.get(auth_url, auth=(username, password), verify=False, timeout=5)
                        
                        if auth_response.status_code == 200:
                            auth_body = auth_response.text
                            
                            # If response body is identical to baseline, it's likely a false positive
                            if auth_body == baseline_path_body:
                                logger.debug(f"⚠️ False positive detected: identical response for {username}:{password} on {auth_url}")
                                continue
                            
                            # Check if the response contains login success indicators
                            response_text = auth_body.lower()
                            success_indicators = ['dashboard', 'welcome', 'admin', 'panel', 'home', 'main']
                            failure_indicators = ['login', 'signin', 'auth', 'password', 'username', 'invalid', 'incorrect']
                            
                            # If we see success indicators and no failure indicators, it's likely successful
                            has_success = any(indicator in response_text for indicator in success_indicators)
                            has_failure = any(indicator in response_text for indicator in failure_indicators)
                            
                            if has_success and not has_failure:
                                working_creds.append(f"{username}:{password}")
                                logger.info(f"🔑 Basic auth credentials found: {username}:{password} on {auth_url}")
                                logger.warning(f"🔑 Default credentials found: {username}:{password}")
                                break
                            else:
                                logger.debug(f"⚠️ 200 response but likely failed login for {username}:{password} on {auth_url}")
                            
                    except Exception as e:
                        logger.debug(f"Error testing basic auth {username}:{password} on {auth_url}: {e}")
                        continue
                
                if working_creds:
                    break
                    
            except Exception as e:
                logger.debug(f"Error testing basic auth {username}:{password} on {url}: {e}")
                continue
        
        return working_creds
    
    def _test_form_login(self, service: WebService, url: str) -> List[str]:
        """Test form-based login pages with response comparison to reduce false positives"""
        working_creds = []
        login_indicators = ['login', 'signin', 'auth', 'admin', 'portal', 'dashboard']
        
        # Check if this looks like a login page
        is_login_page = any(indicator in service.title.lower() for indicator in login_indicators) or \
                       any(indicator in service.html_snippet.lower() for indicator in login_indicators)
        
        if not is_login_page:
            return []
        
        # Common login form patterns
        login_paths = ['/login', '/admin', '/auth', '/signin', '/portal', '/dashboard', '/']
        
        for path in login_paths:
            try:
                login_url = url + path
                response = self.session.get(login_url, verify=False, timeout=5)
                
                if response.status_code == 200:
                    # Get baseline response for this login page
                    baseline_body = response.text
                    logger.debug(f"🔍 Baseline response for {login_url}: body_length={len(baseline_body)}")
                    
                    # Try each credential pair
                    for username, password in self.credentials:
                        try:
                            # Try POST with form data
                            data = {
                                'username': username,
                                'password': password,
                                'user': username,
                                'pass': password,
                                'admin': username,
                                'admin_pass': password,
                                'login': username,
                                'pwd': password
                            }
                            
                            # Try different content types
                            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                            post_response = self.session.post(login_url, data=data, headers=headers, verify=False, timeout=5, allow_redirects=False)
                            
                            # Check if login was successful (not redirected to login page, different status, etc.)
                            if post_response.status_code != 200 or 'login' not in post_response.url.lower():
                                post_body = post_response.text
                                
                                # If response body is identical to baseline, it's likely a false positive
                                if post_body == baseline_body:
                                    logger.debug(f"⚠️ False positive detected: identical response for {username}:{password} on {login_url}")
                                    continue
                                
                                # Additional check: look for success indicators in response
                                response_text = post_body.lower()
                                success_indicators = ['dashboard', 'welcome', 'admin', 'panel', 'home', 'main', 'logout']
                                failure_indicators = ['login', 'signin', 'auth', 'password', 'username', 'invalid', 'incorrect', 'failed']
                                
                                has_success = any(indicator in response_text for indicator in success_indicators)
                                has_failure = any(indicator in response_text for indicator in failure_indicators)
                                
                                if has_success and not has_failure:
                                    working_creds.append(f"{username}:{password}")
                                    logger.info(f"🔑 Form login credentials found: {username}:{password} on {login_url}")
                                    logger.warning(f"🔑 Default credentials found: {username}:{password}")
                                    break
                                else:
                                    logger.debug(f"⚠️ Form login attempt but likely failed for {username}:{password} on {login_url}")
                            
                            # Also try with JSON
                            json_data = {'username': username, 'password': password}
                            headers = {'Content-Type': 'application/json'}
                            json_response = self.session.post(login_url, json=json_data, headers=headers, verify=False, timeout=5, allow_redirects=False)
                            
                            if json_response.status_code != 200 or 'login' not in json_response.url.lower():
                                json_body = json_response.text
                                
                                # If response body is identical to baseline, it's likely a false positive
                                if json_body == baseline_body:
                                    logger.debug(f"⚠️ False positive detected: identical response for {username}:{password} on {login_url}")
                                    continue
                                
                                # Additional check: look for success indicators in response
                                response_text = json_body.lower()
                                success_indicators = ['dashboard', 'welcome', 'admin', 'panel', 'home', 'main', 'logout']
                                failure_indicators = ['login', 'signin', 'auth', 'password', 'username', 'invalid', 'incorrect', 'failed']
                                
                                has_success = any(indicator in response_text for indicator in success_indicators)
                                has_failure = any(indicator in response_text for indicator in failure_indicators)
                                
                                if has_success and not has_failure:
                                    working_creds.append(f"{username}:{password}")
                                    logger.info(f"🔑 Form login credentials found: {username}:{password} on {login_url}")
                                    logger.warning(f"🔑 Default credentials found: {username}:{password}")
                                    break
                                else:
                                    logger.debug(f"⚠️ Form login attempt but likely failed for {username}:{password} on {login_url}")
                                
                        except Exception as e:
                            logger.debug(f"Error testing form credentials {username}:{password} on {login_url}: {e}")
                            continue
                    
                    # If we found working credentials, no need to try other paths
                    if working_creds:
                        break
                        
            except Exception as e:
                logger.debug(f"Error testing login path {path} on {url}: {e}")
                continue
        
        return working_creds
    
    def _get_ssl_cert_info(self, target: str, port: int) -> Optional[Dict]:
        """Get SSL certificate information"""
        try:
            # Use OpenSSL directly to get certificate info
            import ssl
            import socket
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Get the certificate in binary form and decode it
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if cert_bin:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        
                        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                        
                        # Get expiry date
                        expiry_date = cert.not_valid_after_utc
                        from datetime import timezone
                        days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                        
                        if days_until_expiry < 0:
                            status = "Expired"
                        elif days_until_expiry < 15:
                            status = "Expiring Soon"
                        else:
                            status = "Valid"
                        
                        # Get subject and issuer
                        subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                        issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                        
                        subject_cn = subject[0].value if subject else "Unknown"
                        issuer_cn = issuer[0].value if issuer else "Unknown"
                        
                        # Get SANs
                        sans = []
                        try:
                            san_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            sans = [name.value for name in san_extension.value if isinstance(name, x509.DNSName)]
                        except:
                            pass
                        
                        cert_info = {
                            'expiry': expiry_date.strftime('%Y-%m-%d'),
                            'status': status,
                            'subject': subject_cn,
                            'issuer': issuer_cn,
                            'sans': sans
                        }
                        
                        return cert_info
                    else:
                        pass
        except Exception as e:
            pass
        
        return None
    
    def _discover_subdomains(self, domain: str) -> List[str]:
        """Discover subdomains for a given domain"""
        discovered_subdomains = []
        
        # Extract base domain (remove port if present)
        base_domain = domain.split(':')[0]
        
        # Only do active enumeration if enabled (default to True for better discovery)
        if self.config.get('subdomain_enum', True):
            # Use custom subdomain list if provided, otherwise use common ones
            subdomain_list = self.config.get('custom_subdomains', self.common_subdomains)
            
            # Test subdomains
            for subdomain in subdomain_list:
                test_domain = f"{subdomain}.{base_domain}"
                try:
                    # Try to resolve the subdomain
                    socket.gethostbyname(test_domain)
                    discovered_subdomains.append(test_domain)
                    logger.debug(f"Found subdomain: {test_domain}")
                except socket.gaierror:
                    continue
                except Exception as e:
                    logger.debug(f"Error checking subdomain {test_domain}: {e}")
                    continue
        
        return discovered_subdomains
    
    def _resolve_domain_name(self, ip: str) -> str:
        """Perform reverse DNS lookup to get domain name for IP address"""
        try:
            import socket
            domain_name = socket.gethostbyaddr(ip)[0]
            logger.info(f"🌐 {ip} → {domain_name}")
            return domain_name
        except socket.herror as e:
            logger.debug(f"Could not resolve domain name for {ip}: {e}")
            return ""
        except Exception as e:
            logger.debug(f"Unexpected error resolving domain name for {ip}: {e}")
            return ""
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if the target is an IP address"""
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, target))
    
    async def check_web_service(self, target: str, port: int) -> Optional[WebService]:
        protocols = ['http', 'https'] if port != 80 and port != 443 else ['http'] if port == 80 else ['https']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{target}:{port}"
                response = self.session.head(url, verify=False)
                
                if response.status_code < 400:
                    return await self.analyze_web_service(target, port, protocol, url)
            except:
                continue
        return None
    
    async def analyze_web_service(self, target: str, port: int, protocol: str, url: str) -> WebService:
        service = WebService(ip=target, port=port, protocol=protocol)
        
        try:
            if self.progress_tracker:
                self.progress_tracker.update_status(target, port, "Analyzing service...")
            
            logger.info(f"🔍 Starting analysis of {url}")
            
            # Perform reverse DNS lookup for IP addresses
            if self._is_ip_address(target):
                if self.progress_tracker:
                    self.progress_tracker.update_status(target, port, "Resolving domain name...")
                service.domain_name = self._resolve_domain_name(target)
            
            # Faster request with shorter timeout
            response = self.session.get(url, verify=False, timeout=5)
            service.status_code = response.status_code
            service.headers = dict(response.headers)
            service.server_banner = response.headers.get('Server', '')
            
            logger.info(f"📊 Response status: {response.status_code}, Server: {service.server_banner}")
            
            # Extract cookies
            if 'Set-Cookie' in response.headers:
                try:
                    cookies = response.headers.getall('Set-Cookie')
                    service.cookies = [cookie.split(';')[0].split('=')[0] for cookie in cookies if '=' in cookie]
                    logger.info(f"🍪 Found {len(service.cookies)} cookies")
                except Exception as e:
                    logger.warning(f"⚠️ Error extracting cookies: {e}")
                    service.cookies = []
            else:
                service.cookies = []
            
            # Extract title
            if 'text/html' in response.headers.get('content-type', ''):
                import re
                title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE)
                if title_match:
                    service.title = title_match.group(1).strip()
                    logger.info(f"📝 Found title: {service.title}")
                else:
                    logger.info(f"📝 No title found in HTML")
                
                # Extract HTML snippet
                service.html_snippet = response.text[:500]
            
            # Get SSL certificate info for HTTPS
            if protocol == 'https':
                if self.progress_tracker:
                    self.progress_tracker.update_status(target, port, "Checking certificate...")
                cert_info = self._get_ssl_cert_info(target, port)
                if cert_info:
                    service.cert_expiry = cert_info['expiry']
                    service.cert_status = cert_info['status']
                    service.cert_subject = cert_info['subject']
                    service.cert_issuer = cert_info['issuer']
                    service.cert_sans = cert_info['sans']
            
            # Discover subdomains (active enumeration + passive from certs)
            if self.progress_tracker:
                self.progress_tracker.update_status(target, port, "Discovering subdomains...")
            discovered_subdomains = self._discover_subdomains(target)
            logger.info(f"🔍 Active subdomain discovery found: {discovered_subdomains}")
            
            # Add subdomains from certificate SANs (passive discovery)
            if service.cert_sans:
                logger.info(f"🔍 Certificate SANs: {service.cert_sans}")
                for san in service.cert_sans:
                    if san.startswith('*.'):
                        # Wildcard certificate - extract base domain
                        wildcard_domain = san[2:]  # Remove '*.' prefix
                        if wildcard_domain not in discovered_subdomains:
                            discovered_subdomains.append(wildcard_domain)
                            logger.info(f"🔍 Added wildcard domain from cert: {wildcard_domain}")
                    elif '.' in san and san != target:
                        # Direct subdomain from SAN
                        if san not in discovered_subdomains:
                            discovered_subdomains.append(san)
                            logger.info(f"🔍 Added subdomain from cert: {san}")
            
            service.subdomains = discovered_subdomains
            
            # Identify service type and specific target
            service.service_type = self._identify_service_type(service)
            service.specific_target = self._identify_specific_target(service)
            
            logger.info(f"🔍 Identified service type: {service.service_type}")
            
            # Check vulnerabilities
            if self.progress_tracker:
                self.progress_tracker.update_status(target, port, "Checking vulnerabilities...")
            service.vulnerabilities = self._check_vulnerabilities(service)
            logger.info(f"🛡️ Found {len(service.vulnerabilities)} vulnerabilities")
            
            # Take screenshot (enabled by default)
            if not self.config.get('no_screenshots', False):
                logger.info(f"📸 Taking screenshot of {url}")
                screenshot_path = await self._take_screenshot(url, target, port, protocol)
                if screenshot_path:
                    service.screenshot_file = str(screenshot_path)
                    logger.info(f"📸 Screenshot saved: {screenshot_path}")
                else:
                    service.screenshot_file = ""
                    logger.info(f"📸 Screenshot failed")
            
            # Fuzz paths if enabled
            if self.config.get('enable_fuzzing', False):
                if self.progress_tracker:
                    self.progress_tracker.update_status(target, port, "Fuzzing paths...")
                logger.info(f"🔍 Fuzzing paths on {url}")
                service.discovered_paths = self._fuzz_paths(service, url)
                logger.info(f"🔍 Found {len(service.discovered_paths)} paths")
            else:
                logger.info(f"🔍 Path fuzzing disabled")
            
        except Exception as e:
            logger.error(f"❌ Error analyzing {url}: {e}")
            import traceback
            logger.error(f"❌ Traceback: {traceback.format_exc()}")
        
        logger.info(f"✅ Analysis completed for {url}")
        return service
    
    async def _take_screenshot(self, url: str, target: str, port: int, protocol: str) -> Optional[Path]:
        try:
            if self.progress_tracker:
                self.progress_tracker.update_status(target, port, "Taking screenshot...")
            
            async with async_playwright() as p:
                # Launch browser with SSL certificate error handling
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--ignore-certificate-errors",  # Handle self-signed/host-mismatch certs
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor"
                    ]
                )
                
                # Create context with SSL error handling
                context = await browser.new_context(
                    ignore_https_errors=True,  # Handle TLS/SSL issues
                    viewport={"width": 1280, "height": 720},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                )
                
                page = await context.new_page()
                
                # Enhanced page loading with much better timing
                try:
                    # First try to load the page with networkidle
                    await page.goto(url, wait_until='networkidle', timeout=15000)
                    
                    # Wait for the page to be fully loaded
                    await page.wait_for_load_state('networkidle', timeout=8000)
                    
                    # Wait for any JavaScript to finish executing
                    await asyncio.sleep(5)
                    
                    # Check if page has content (not just white)
                    content = await page.content()
                    if len(content.strip()) < 100:  # Very little content
                        logger.warning(f"⚠️ Page appears to have little content: {url}")
                        # Try waiting a bit more
                        await asyncio.sleep(3)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Page load timeout for {url}: {e}")
                    # Try alternative loading strategy
                    try:
                        await page.goto(url, wait_until='domcontentloaded', timeout=10000)
                        await asyncio.sleep(5)
                    except:
                        pass
                
                filename = f"{target}_{port}_{protocol}.png"
                screenshot_path = self.screenshots_dir / filename
                await page.screenshot(path=str(screenshot_path), full_page=True)
                await context.close()
                await browser.close()
                return screenshot_path
        except Exception as e:
            logger.debug(f"Error taking screenshot of {url}: {e}")
            return None
    
    def _update_vulnerability_groups(self, service: WebService, index: int):
        """Update vulnerability groups for the HTML report"""
        for vuln in service.vulnerabilities:
            if vuln not in self.vulnerability_groups:
                self.vulnerability_groups[vuln] = []
            self.vulnerability_groups[vuln].append({
                'index': index,
                'ip': service.ip,
                'port': service.port,
                'title': service.title
            })
    
    def generate_live_html_report(self):
        """Generate live-updating HTML report"""
        if self.config.get('no_html', False):
            return
            
        html_content = self._generate_html_content()
        report_file = self.output_dir / "report.html"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"📄 Live HTML report updated: {report_file}")
    
    def _generate_html_content(self) -> str:
        """Generate HTML report content with live updates"""
        html_template = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Discovery Scanner - Live Report</title>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/responsive/2.2.9/css/responsive.dataTables.min.css">
    <style>
        /* Fallback DataTables CSS in case CDN is slow */
        .dataTables_wrapper .dataTables_length, .dataTables_wrapper .dataTables_filter, .dataTables_wrapper .dataTables_info, .dataTables_wrapper .dataTables_processing, .dataTables_wrapper .dataTables_paginate { color: #333; }
        .dataTables_wrapper .dataTables_length select { border: 1px solid #ddd; border-radius: 4px; padding: 4px; }
        .dataTables_wrapper .dataTables_filter input { border: 1px solid #ddd; border-radius: 4px; padding: 4px; margin-left: 8px; }
        .dataTables_wrapper .dataTables_paginate .paginate_button { border: 1px solid #ddd; padding: 6px 12px; margin: 0 2px; cursor: pointer; border-radius: 4px; }
        .dataTables_wrapper .dataTables_paginate .paginate_button:hover { background: #f0f0f0; }
        .dataTables_wrapper .dataTables_paginate .paginate_button.current { background: #007bff; color: white; border-color: #007bff; }
        table.dataTable { border-collapse: collapse; width: 100%; }
        table.dataTable thead th { background: #f8f9fa; border: 1px solid #dee2e6; padding: 8px; font-weight: bold; }
        table.dataTable tbody td { border: 1px solid #dee2e6; padding: 8px; }
        table.dataTable tbody tr:nth-child(even) { background: #f8f9fa; }
        table.dataTable tbody tr:hover { background: #e9ecef; }
    </style>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #333; }
        .summary { background: #e8f4fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .vulnerabilities { background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .vuln-group { margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 4px; }
        .vuln-link { color: #007bff; text-decoration: none; margin-right: 10px; }
        .vuln-link:hover { text-decoration: underline; }
        .lateral-movement { background: #e8f5e8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .target-group { margin: 10px 0; padding: 10px; background: #f0f8f0; border-radius: 4px; border-left: 4px solid #28a745; }
        .target-link { color: #28a745; text-decoration: none; margin-right: 10px; font-weight: bold; }
        .target-link:hover { text-decoration: underline; }
        .screenshot { max-width: 200px; max-height: 150px; cursor: pointer; border: 1px solid #ddd; border-radius: 6px; transition: transform 0.2s ease, box-shadow 0.2s ease; }
        .screenshot:hover { transform: scale(4); box-shadow: 0 4px 12px rgba(0,0,0,0.3); z-index: 10; position: relative; }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.9); }
        .modal-content { margin: auto; display: block; max-width: 98%; max-height: 98%; margin-top: 1%; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.8); transition: transform 0.3s ease; }
        .modal-content:hover { transform: scale(1.02); }
        .close { position: absolute; top: 15px; right: 35px; color: #f1f1f1; font-size: 40px; font-weight: bold; cursor: pointer; }
        .service-type { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .type-web { background: #d4edda; color: #155724; }
        .type-printer { background: #d1ecf1; color: #0c5460; }
        .type-storage { background: #fff3cd; color: #856404; }
        .type-login { background: #f8d7da; color: #721c24; }
        .type-camera { background: #e2e3e5; color: #383d41; }
        .type-router { background: #d6d8db; color: #1b1e21; }
        .type-database { background: #cce5ff; color: #004085; }
        .type-monitoring { background: #d4edda; color: #155724; }
        .type-development { background: #f8d7da; color: #721c24; }
        .type-ci_cd_lateral { background: #ff6b6b; color: white; }
        .vuln-badge { background: #dc3545; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin-left: 5px; }
        .headers-section { max-height: 200px; max-width: 120px; overflow-y: auto; background: #f9f9f9; padding: 8px; border-radius: 6px; font-size: 11px; border: 1px solid #ddd; }
        .headers-section strong { color: #2c3e50; font-weight: 600; }
        .headers-section br { margin-bottom: 2px; }
        .table-responsive { overflow-x: auto; max-width: 100%; }
        .dataTables_wrapper { overflow-x: auto; }
        .dataTables_scrollBody { overflow-x: auto; }
        .cookies-section { max-height: 150px; overflow-y: auto; background: #fff8dc; padding: 8px; border-radius: 4px; }
        .cookie-badge { background: #ffc107; color: #212529; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin: 2px; display: inline-block; }
        .subdomains-section { max-height: 150px; overflow-y: auto; background: #e8f5e8; padding: 8px; border-radius: 4px; }
        .subdomain-badge { background: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin: 2px; display: inline-block; }
        .paths-section { max-height: 150px; overflow-y: auto; background: #f0f8ff; padding: 8px; border-radius: 4px; }
        .path-badge { background: #007bff; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin: 2px; display: inline-block; }
        .paths-collapsible { outline: none; }
        .paths-collapsible.active, .paths-collapsible:hover { background: #cbe7fa; }
        .paths-content { transition: all 0.2s ease; }
        .service-paths-group { margin: 10px 0; }
        .path-badge-success { background: #28a745; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-success:hover { background: #218838; color: white; text-decoration: none; }
        .path-badge-redirect { background: #ffc107; color: #212529; padding: 4px 8px; border-radius: 4px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-redirect:hover { background: #e0a800; color: #212529; text-decoration: none; }
        .path-badge-auth { background: #17a2b8; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-auth:hover { background: #138496; color: white; text-decoration: none; }
        .path-badge-forbidden { background: #dc3545; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-forbidden:hover { background: #c82333; color: white; text-decoration: none; }
        .path-badge-other { background: #6c757d; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-other:hover { background: #5a6268; color: white; text-decoration: none; }
        .cert-info { background: #f0f8ff; padding: 10px; border-radius: 4px; margin: 5px 0; }
        .status-expired { color: red; font-weight: bold; }
        .status-expiring { color: orange; font-weight: bold; }
        .status-valid { color: green; font-weight: bold; }
        .live-indicator { color: #28a745; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .collapsible { outline: none; }
        .collapsible.active, .collapsible:hover { background: #cbe7fa; }
        .content { transition: all 0.2s ease; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Web Discovery Scanner - Live Report <span class="live-indicator">●</span></h1>
        
        <div class="summary">
            <h3>📊 Scan Summary</h3>
            <p><strong>Scan Date:</strong> {scan_date}</p>
            <p><strong>Total Services Found:</strong> {total_services}</p>
            <p><strong>Service Types:</strong> {service_types}</p>

            <p><strong>HTTPS Services:</strong> {https_count}</p>
        </div>
        

        
        <div class="lateral-movement">
            <h3>🎯 CI/CD & Lateral Movement Targets</h3>
            {lateral_movement_sections}
        </div>
        
        <div class="discovered-paths">
            <h3>🔍 Discovered Paths & Files</h3>
            <div class="paths-collapsible-container">
                {discovered_paths_sections}
            </div>
        </div>
        
        <h3>🔍 Discovered Services</h3>
        <table id="resultsTable" class="display responsive nowrap" style="width:100%">
            <thead>
                <tr>
                    <th>Service</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Title</th>
                    <th>Status</th>
                    <th>Screenshot</th>
                    <th>Headers</th>
                    <th>Cookies</th>
                    <th>Subdomains</th>
                    <th>Certificate</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
        
        {subdomain_table}
    </div>
    
    <!-- Modal for screenshots -->
    <div id="screenshotModal" class="modal">
        <span class="close">&times;</span>
        <img class="modal-content" id="modalImage">
    </div>
    
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/responsive/2.2.9/js/dataTables.responsive.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#resultsTable').DataTable({
                responsive: true,
                pageLength: 10,
                order: [[0, 'asc']],
                scrollX: true,
                autoWidth: false,
                scrollCollapse: true,
                columnDefs: [
                    { targets: [5, 6, 7, 8, 9], orderable: false },
                    { targets: [6], width: '250px' },  // Headers column - reduced for better fit
                    { targets: [5], width: '100px' },  // Screenshot column
                    { targets: [7], width: '120px' },  // Cookies column
                    { targets: [8], width: '120px' },  // Subdomains column
                    { targets: [9], width: '180px' }   // Certificate column
                ]
            });
            
            // Initialize subdomain table if it exists
            if ($('#subdomainTable').length) {
                $('#subdomainTable').DataTable({
                    responsive: true,
                    pageLength: 10,
                    order: [[0, 'asc']],
                    scrollX: true,
                    autoWidth: false,
                    columnDefs: [
                        { targets: [5, 6, 7, 8], orderable: false },
                        { targets: [6], width: '250px' },  // Headers column - reduced for better fit
                        { targets: [5], width: '100px' },  // Screenshot column
                        { targets: [7], width: '120px' },  // Cookies column
                        { targets: [8], width: '180px' }   // Certificate column
                    ]
                });
            }
        }});
        
        // Modal functionality
        var modal = document.getElementById("screenshotModal");
        var modalImg = document.getElementById("modalImage");
        var span = document.getElementsByClassName("close")[0];
        
        function openModal(imgSrc) {
            modal.style.display = "block";
            modalImg.src = imgSrc;
        }
        
        span.onclick = function() {
            modal.style.display = "none";
        }
        
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = "none";
            }
        }
        
        // Auto-refresh every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
        """
        

        
        # Generate discovered paths sections
        discovered_paths_sections = ""
        services_with_paths = {}
        
        for i, service in enumerate(self.results):
            if service.discovered_paths:
                service_url = f"{service.protocol}://{service.ip}:{service.port}"
                services_with_paths[service_url] = {
                    'index': i,
                    'ip': service.ip,
                    'port': service.port,
                    'protocol': service.protocol,
                    'paths': service.discovered_paths
                }
        
        if services_with_paths:
            for service_url, service_info in services_with_paths.items():
                paths_html = ""
                status_counts = {'200': 0, '301': 0, '302': 0, '401': 0, '403': 0, 'other': 0}
                
                for path in service_info['paths']:
                    # Extract status code from path string (format: "/path (status)")
                    status_match = re.search(r'\((\d+)\)$', path)
                    status_code = status_match.group(1) if status_match else "200"
                    
                    # Count status codes
                    if status_code == "200":
                        status_counts['200'] += 1
                    elif status_code == "301":
                        status_counts['301'] += 1
                    elif status_code == "302":
                        status_counts['302'] += 1
                    elif status_code == "401":
                        status_counts['401'] += 1
                    elif status_code == "403":
                        status_counts['403'] += 1
                    else:
                        status_counts['other'] += 1
                    
                    # Clean path name (remove status code)
                    clean_path = re.sub(r'\s*\(\d+\)$', '', path)
                    full_url = f"{service_url}{clean_path}"
                    
                    # Color coding based on status
                    if status_code == "200":
                        badge_class = "path-badge-success"
                    elif status_code in ["301", "302"]:
                        badge_class = "path-badge-redirect"
                    elif status_code == "401":
                        badge_class = "path-badge-auth"
                    elif status_code == "403":
                        badge_class = "path-badge-forbidden"
                    else:
                        badge_class = "path-badge-other"
                    
                    paths_html += f'<a href="{full_url}" target="_blank" class="{badge_class}">{clean_path} ({status_code})</a> '
                
                # Create status summary
                status_summary = []
                if status_counts['200'] > 0:
                    status_summary.append(f"✅ {status_counts['200']} OK")
                if status_counts['301'] + status_counts['302'] > 0:
                    status_summary.append(f"🔄 {status_counts['301'] + status_counts['302']} Redirect")
                if status_counts['401'] > 0:
                    status_summary.append(f"🔐 {status_counts['401']} Auth")
                if status_counts['403'] > 0:
                    status_summary.append(f"🚫 {status_counts['403']} Forbidden")
                if status_counts['other'] > 0:
                    status_summary.append(f"❓ {status_counts['other']} Other")
                
                status_summary_text = " | ".join(status_summary)
                
                discovered_paths_sections += f"""
                <div class="service-paths-group">
                    <button type="button" class="paths-collapsible" style="background:#f0f8ff; color:#333; border:none; padding:8px 12px; border-radius:4px; font-weight:bold; cursor:pointer; width:100%; text-align:left;">
                        🌐 {service_info['ip']}:{service_info['port']} ({service_info['protocol'].upper()}) - {len(service_info['paths'])} paths found | {status_summary_text}
                    </button>
                    <div class="paths-content" style="display:none; padding:10px 15px 10px 15px; background:#f9f9f9; border-radius:0 0 4px 4px; border:1px solid #e0e0e0; border-top:none;">
                        {paths_html}
                    </div>
                </div>
                """
        else:
            discovered_paths_sections = "<p>No additional paths discovered yet.</p>"
        
        # Generate lateral movement target sections
        lateral_movement_sections = ""
        lateral_targets = {}
        
        for i, service in enumerate(self.results):
            if service.specific_target:
                if service.specific_target not in lateral_targets:
                    lateral_targets[service.specific_target] = []
                lateral_targets[service.specific_target].append({
                    'index': i,
                    'ip': service.ip,
                    'port': service.port,
                    'title': service.title,
                    'service_type': service.service_type
                })
        
        for target_name, items in lateral_targets.items():
            if items:
                target_links = ""
                for item in items:
                    target_links += f'<a href="#row-{item["index"]}" class="target-link">{item["ip"]}:{item["port"]} - {item["title"][:30]}... [{item["service_type"]}]</a>'
                
                target_display_name = target_name.replace('_', ' ').title()
                lateral_movement_sections += f"""
                <div class="target-group">
                    <strong>🎯 {target_display_name} ({len(items)} found):</strong><br>
                    {target_links}
                </div>
                """
        
        if not lateral_movement_sections:
            lateral_movement_sections = "<p>No CI/CD or lateral movement targets detected yet.</p>"
        
        # Generate table rows (main services only)
        table_rows = ""
        subdomain_rows = ""
        main_services = []
        subdomain_services = []
        
        for i, service in enumerate(self.results):
            if service.is_subdomain:
                subdomain_services.append((i, service))
            else:
                main_services.append((i, service))
        
        # Generate main services table
        for i, service in main_services:
            service_url = f"{service.protocol}://{service.ip}:{service.port}"
            
            # Service type badge
            type_class = f"type-{service.service_type}"
            type_badge = f'<span class="service-type {type_class}">{service.service_type.upper()}</span>'
            
            # Screenshot cell
            screenshot_cell = ""
            if service.screenshot_file:
                # Fix path for HTML display - use screenshots subdirectory
                screenshot_filename = Path(service.screenshot_file).name
                relative_path = f"screenshots/{screenshot_filename}"
                if Path(service.screenshot_file).exists():
                    screenshot_cell = f'<img src="{relative_path}" class="screenshot" onclick="openModal(\'{relative_path}\')" alt="Screenshot">'
                else:
                    screenshot_cell = f'<em>Screenshot not found: {screenshot_filename}</em>'
            else:
                screenshot_cell = '<em>No screenshot</em>'
            
            # Headers cell - show ALL headers
            headers_html = ""
            if service.headers:
                headers_html = '<div class="headers-section">'
                # Show ALL headers with expandable view
                for key, value in service.headers.items():
                    # Truncate very long values for display
                    display_value = value
                    if len(value) > 100:
                        display_value = value[:97] + "..."
                    headers_html += f'<strong>{key}:</strong> {display_value}<br>'
                headers_html += '</div>'
            
            # Cookies cell
            cookies_html = ""
            if service.cookies:
                cookies_html = '<div class="cookies-section">'
                for cookie in service.cookies:
                    cookies_html += f'<span class="cookie-badge">{cookie}</span> '
                cookies_html += '</div>'
            else:
                cookies_html = '<em>No cookies</em>'
            
            # Subdomains cell
            subdomains_html = ""
            if service.subdomains:
                subdomains_html = '<div class="subdomains-section">'
                for subdomain in service.subdomains:
                    subdomains_html += f'<span class="subdomain-badge">{subdomain}</span> '
                subdomains_html += '</div>'
            else:
                subdomains_html = '<em>No subdomains found</em>'
            
            # Certificate cell with detailed information
            cert_cell = ""
            if service.cert_expiry:
                status_class = f"status-{service.cert_status.lower().replace(' ', '-')}"
                cert_cell = f'<div class="cert-info">'
                cert_cell += f'<strong>Subject:</strong> {service.cert_subject}<br>'
                cert_cell += f'<strong>Issuer:</strong> {service.cert_issuer}<br>'
                cert_cell += f'<strong>Expires:</strong> {service.cert_expiry}<br>'
                cert_cell += f'<span class="{status_class}">{service.cert_status}</span>'
                if service.cert_sans:
                    cert_cell += f'<br><strong>SANs:</strong> {", ".join(service.cert_sans[:3])}'
                    if len(service.cert_sans) > 3:
                        cert_cell += f' (+{len(service.cert_sans) - 3} more)'
                cert_cell += '</div>'
            

            
            # Target badge
            target_cell = ""
            if service.specific_target:
                target_cell = f'<span class="service-type type-ci_cd_lateral">{service.specific_target.upper()}</span>'
            

            
            # Service cell with domain name if available
            service_cell = f'<a href="{service_url}" target="_blank">{service.ip}:{service.port}</a>'
            if service.domain_name:
                service_cell += f'<br><small style="color: #666;">🌐 {service.domain_name}</small>'
            
            table_rows += f"""
                <tr id="row-{i}">
                    <td>{service_cell}</td>
                    <td>{type_badge}</td>
                    <td>{target_cell}</td>
                    <td>{service.title}</td>
                    <td>{service.status_code}</td>
                    <td>{screenshot_cell}</td>
                    <td>{headers_html}</td>
                    <td>{cookies_html}</td>
                    <td>{subdomains_html}</td>
                    <td>{cert_cell}</td>
                </tr>
            """
        
        # Generate subdomain services table
        if subdomain_services:
            subdomain_table = f"""
            <div style="margin-top: 40px; padding-top: 20px; border-top: 3px solid #007bff; background: #f8f9fa; padding: 20px; border-radius: 8px;">
            <h3 style="color: #007bff; margin-bottom: 20px;">🔍 Discovered Subdomain Services (Not in Original Scope)</h3>
            <table id="subdomainTable" class="display responsive nowrap" style="width:100%">
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Type</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Screenshot</th>
                        <th>Headers</th>
                        <th>Cookies</th>
                        <th>Certificate</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            for i, service in subdomain_services:
                service_url = f"{service.protocol}://{service.ip}:{service.port}"
                
                # Service cell with domain name if available
                service_cell = f'<a href="{service_url}" target="_blank">{service.ip}:{service.port}</a>'
                if service.domain_name:
                    service_cell += f'<br><small style="color: #666;">🌐 {service.domain_name}</small>'
                
                # Service type badge
                type_class = f"type-{service.service_type}"
                type_badge = f'<span class="service-type {type_class}">{service.service_type.upper()}</span>'
                
                # Screenshot cell
                screenshot_cell = ""
                if service.screenshot_file:
                    # Fix path for HTML display - use screenshots subdirectory
                    screenshot_filename = Path(service.screenshot_file).name
                    relative_path = f"screenshots/{screenshot_filename}"
                    if Path(service.screenshot_file).exists():
                        screenshot_cell = f'<img src="{relative_path}" class="screenshot" onclick="openModal(\'{relative_path}\')" alt="Screenshot">'
                    else:
                        screenshot_cell = f'<em>Screenshot not found: {screenshot_filename}</em>'
                else:
                    screenshot_cell = '<em>No screenshot</em>'
                
                # Headers cell - compact version
                headers_html = ""
                if service.headers:
                                    headers_html = '<div class="headers-section">'
                # Show ALL headers for subdomains too
                for key, value in service.headers.items():
                    # Truncate very long values for display
                    display_value = value
                    if len(value) > 100:
                        display_value = value[:97] + "..."
                    headers_html += f'<strong>{key}:</strong> {display_value}<br>'
                headers_html += '</div>'
                
                # Cookies cell
                cookies_html = ""
                if service.cookies:
                    cookies_html = '<div class="cookies-section">'
                    for cookie in service.cookies:
                        cookies_html += f'<span class="cookie-badge">{cookie}</span> '
                    cookies_html += '</div>'
                else:
                    cookies_html = '<em>No cookies</em>'
                
                # Certificate cell
                cert_cell = ""
                if service.cert_expiry:
                    status_class = f"status-{service.cert_status.lower().replace(' ', '-')}"
                    cert_cell = f'<div class="cert-info">'
                    cert_cell += f'<strong>Subject:</strong> {service.cert_subject}<br>'
                    cert_cell += f'<strong>Issuer:</strong> {service.cert_issuer}<br>'
                    cert_cell += f'<strong>Expires:</strong> {service.cert_expiry}<br>'
                    cert_cell += f'<span class="{status_class}">{service.cert_status}</span>'
                    if service.cert_sans:
                        cert_cell += f'<br><strong>SANs:</strong> {", ".join(service.cert_sans[:3])}'
                        if len(service.cert_sans) > 3:
                            cert_cell += f' (+{len(service.cert_sans) - 3} more)'
                    cert_cell += '</div>'
                

                
                # Target badge
                target_cell = ""
                if service.specific_target:
                    target_cell = f'<span class="service-type type-ci_cd_lateral">{service.specific_target.upper()}</span>'
                
                subdomain_rows += f"""
                    <tr id="subdomain-row-{i}">
                        <td>{service_cell}</td>
                        <td>{type_badge}</td>
                        <td>{target_cell}</td>
                        <td>{service.title}</td>
                        <td>{service.status_code}</td>
                        <td>{screenshot_cell}</td>
                        <td>{headers_html}</td>
                        <td>{cookies_html}</td>
                        <td>{cert_cell}</td>
                    </tr>
                """
            
            subdomain_table += subdomain_rows + """
                </tbody>
            </table>
            </div>
            """
        else:
            subdomain_table = ""
        
        # Calculate summary statistics
        scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total_services = len(self.results)
        service_types = ", ".join(set(s.service_type for s in self.results))
        https_count = len([s for s in self.results if s.protocol == 'https'])
        
        # Format targets for display
        if len(self.original_targets) == 1 and '/' in self.original_targets[0]:
            # Single subnet
            targets_display = f"Subnet: {self.original_targets[0]}"
        elif len(self.original_targets) <= 5:
            # Show all targets if 5 or fewer
            targets_display = ", ".join(self.original_targets)
        else:
            # Show first 3 and count
            targets_display = f"{', '.join(self.original_targets[:3])}... (+{len(self.original_targets) - 3} more)"
        
        # Collect default credentials found
        default_creds_found = []
        for service in self.results:
            if service.vulnerabilities:
                for vuln in service.vulnerabilities:
                    if 'default_creds_working' in vuln:
                        cred_info = vuln.split('default_creds_working:')[1]
                        default_creds_found.append(f"{service.ip}:{service.port} - {cred_info}")
        
        creds_display = ""
        if default_creds_found:
            creds_display = f'<p><strong>🔑 Default Credentials Found:</strong> {len(default_creds_found)}</p>'
            creds_display += '<div style="background:#fff3cd; padding:10px; border-radius:4px; margin:5px 0;">'
            for cred in default_creds_found:
                creds_display += f'<div style="margin:2px 0;">• {cred}</div>'
            creds_display += '</div>'
        
        # Generate summary details for all main services (not subdomains)
        summary_details_html = '<div style="margin-top:15px;">'
        summary_details_html += '<h4>Service Details Preview</h4>'
        if main_services:
            for i, service in main_services:
                service_id = f"summary-details-{i}"
                summary_details_html += f'''
                <div style="margin-bottom:10px;">
                  <button type="button" class="collapsible" style="background:#e8f4fd; color:#333; border:none; padding:8px 12px; border-radius:4px; font-weight:bold; cursor:pointer; width:100%; text-align:left;">{service.ip}:{service.port} ({service.protocol.upper()}) - {service.title if service.title else ''}</button>
                  <div class="content" style="display:none; padding:10px 15px 10px 15px; background:#f9f9f9; border-radius:0 0 4px 4px; border:1px solid #e0e0e0; border-top:none;">
                    <div><strong>Headers:</strong><br>
                '''
                if service.headers:
                    summary_details_html += '<div class="headers-section">'
                    for key, value in service.headers.items():
                        summary_details_html += f'<strong>{key}:</strong> {value}<br>'
                    summary_details_html += '</div>'
                else:
                    summary_details_html += '<em>No headers</em>'
                summary_details_html += '</div>'
                summary_details_html += '<div><strong>Cookies:</strong><br>'
                if service.cookies:
                    summary_details_html += '<div class="cookies-section">'
                    for cookie in service.cookies:
                        summary_details_html += f'<span class="cookie-badge">{cookie}</span> '
                    summary_details_html += '</div>'
                else:
                    summary_details_html += '<em>No cookies</em>'
                summary_details_html += '</div>'
                summary_details_html += '<div><strong>Subdomains:</strong><br>'
                if service.subdomains:
                    summary_details_html += '<div class="subdomains-section">'
                    for subdomain in service.subdomains:
                        summary_details_html += f'<span class="subdomain-badge">{subdomain}</span> '
                    summary_details_html += '</div>'
                else:
                    summary_details_html += '<em>No subdomains found</em>'
                summary_details_html += '</div>'
                summary_details_html += '<div><strong>Certificate:</strong><br>'
                if service.cert_expiry:
                    status_class = f"status-{service.cert_status.lower().replace(' ', '-')}"
                    summary_details_html += f'<div class="cert-info">'
                    summary_details_html += f'<strong>Subject:</strong> {service.cert_subject}<br>'
                    summary_details_html += f'<strong>Issuer:</strong> {service.cert_issuer}<br>'
                    summary_details_html += f'<strong>Expires:</strong> {service.cert_expiry}<br>'
                    summary_details_html += f'<span class="{status_class}">{service.cert_status}</span>'
                    if service.cert_sans:
                        summary_details_html += f'<br><strong>SANs:</strong> {', '.join(service.cert_sans[:3])}'
                        if len(service.cert_sans) > 3:
                            summary_details_html += f' (+{len(service.cert_sans) - 3} more)'
                    summary_details_html += '</div>'
                else:
                    summary_details_html += '<em>No certificate info</em>'
                summary_details_html += '</div>'
                summary_details_html += '</div></div>'
        else:
            summary_details_html += '<em>No services found yet.</em>'
        summary_details_html += '</div>'
        
        # Add targets and credentials to summary BEFORE replacing placeholders
        html_template = html_template.replace(
            '<p><strong>Scan Date:</strong> {scan_date}</p>',
            f'<p><strong>Scan Date:</strong> {scan_date}</p>\n            <p><strong>🎯 Targets:</strong> {targets_display}</p>'
        )
        
        # Add credentials section after HTTPS services
        if creds_display:
            html_template = html_template.replace(
                '<p><strong>HTTPS Services:</strong> {https_count}</p>',
                f'<p><strong>HTTPS Services:</strong> {https_count}</p>\n            {creds_display}'
            )
        
        # Insert summary_details_html after the summary stats in the summary section
        html_template = html_template.replace(
            '<p><strong>HTTPS Services:</strong> {https_count}</p>\n        </div>',
            '<p><strong>HTTPS Services:</strong> {https_count}</p>\n        ' + summary_details_html + '\n        </div>'
        )
        
        # Replace placeholders in the summary section
        html_template = html_template.replace('{scan_date}', scan_date)
        html_template = html_template.replace('{total_services}', str(total_services))
        html_template = html_template.replace('{service_types}', service_types)
        html_template = html_template.replace('{https_count}', str(https_count))
        
        # Add collapsible JS and CSS
        collapsible_js = r"""
<script>
var coll = document.getElementsByClassName("collapsible");
for (var i = 0; i < coll.length; i++) {
  coll[i].addEventListener("click", function() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    if (content.style.display === "block") {
      content.style.display = "none";
    } else {
      content.style.display = "block";
    }
  });
}

var pathsColl = document.getElementsByClassName("paths-collapsible");
for (var i = 0; i < pathsColl.length; i++) {
  pathsColl[i].addEventListener("click", function() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    if (content.style.display === "block") {
      content.style.display = "none";
    } else {
      content.style.display = "block";
    }
  });
}
</script>
"""
        html_template = html_template.replace('</body>', collapsible_js + '\n</body>')
        
        # Use string replacement instead of format to avoid curly brace issues
        html_content = html_template
        html_content = html_content.replace('{scan_date}', scan_date)
        html_content = html_content.replace('{total_services}', str(total_services))
        html_content = html_content.replace('{service_types}', service_types)

        html_content = html_content.replace('{https_count}', str(https_count))

        html_content = html_content.replace('{lateral_movement_sections}', lateral_movement_sections)
        html_content = html_content.replace('{discovered_paths_sections}', discovered_paths_sections)
        html_content = html_content.replace('{table_rows}', table_rows)
        html_content = html_content.replace('{subdomain_table}', subdomain_table)
        
        return html_content
    
    def save_results(self):
        csv_file = self.output_dir / "found_web.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            if self.results:
                writer = csv.DictWriter(f, fieldnames=['ip', 'port', 'protocol', 'title', 'status_code', 'service_type', 'specific_target', 'vulnerabilities', 'cert_status', 'screenshot_file', 'cookies', 'subdomains', 'cert_subject', 'cert_issuer', 'cert_sans', 'is_subdomain', 'original_target', 'discovered_paths', 'domain_name'])
                writer.writeheader()
                for result in self.results:
                    writer.writerow({
                        'ip': result.ip,
                        'port': result.port,
                        'protocol': result.protocol,
                        'title': result.title,
                        'status_code': result.status_code,
                        'service_type': result.service_type,
                        'specific_target': result.specific_target,
                        'vulnerabilities': ', '.join(result.vulnerabilities),
                        'cert_status': result.cert_status,
                        'screenshot_file': result.screenshot_file,
                        'cookies': ', '.join(result.cookies),
                        'subdomains': ', '.join(result.subdomains),
                        'cert_subject': result.cert_subject,
                        'cert_issuer': result.cert_issuer,
                        'cert_sans': ', '.join(result.cert_sans),
                        'is_subdomain': result.is_subdomain,
                        'original_target': result.original_target,
                        'discovered_paths': ', '.join(result.discovered_paths),
                        'domain_name': result.domain_name
                    })
        logger.info(f"💾 Results saved to {self.output_dir}")
    
    async def run_scan(self, targets: List[str]):
        logger.info(f"🎯 Starting scan of {len(targets)} targets")
        
        # Store original targets for summary
        self.original_targets = targets.copy()
        
        # Initialize progress tracker
        total_ports = len(self.ports)
        self.progress_tracker = ProgressTracker(len(targets), total_ports)
        self.progress_tracker.start()
        
        # Generate initial HTML report
        self.generate_live_html_report()
        
        # Track discovered subdomains to avoid duplicates
        discovered_subdomains = set()
        scanned_combinations = set()  # Track target:port combinations to avoid duplicates
        
        # First pass: scan main targets
        self.progress_tracker.update_status("Main targets", 0, "Starting main target scan...")
        
        for target in targets:
            ports = self.scan_ports(target)
            for port in ports:
                combination = f"{target}:{port}"
                if combination in scanned_combinations:
                    self.progress_tracker.increment()
                    continue
                
                scanned_combinations.add(combination)
                self.progress_tracker.update_status(target, port, "Checking service...")
                
                # Check if user wants to skip
                if self.progress_tracker.should_skip():
                    logger.info(f"⏭️ Skipped {target}:{port}")
                    self.progress_tracker.increment()
                    continue
                
                try:
                    result = await self.check_web_service(target, port)
                    if result:
                        self.results.append(result)
                        logger.info(f"🌐 Found web service: {target}:{port} ({result.protocol}) - {result.title} [{result.service_type}]")
                        
                        # Collect subdomains for recursive scanning (avoid duplicates)
                        if self.config.get('recursive_scan', True):
                            for subdomain in result.subdomains:
                                if subdomain not in discovered_subdomains and subdomain != target:
                                    discovered_subdomains.add(subdomain)
                        
                        # Update HTML report after every discovery for live updates
                        self.generate_live_html_report()
                    
                except Exception as e:
                    logger.error(f"Error processing {target}:{port} - {e}")
                
                self.progress_tracker.increment()
        
        # Second pass: scan discovered subdomains (avoiding duplicates)
        if self.config.get('recursive_scan', True) and discovered_subdomains:
            subdomain_list = list(discovered_subdomains)
            self.progress_tracker.update_status("Subdomains", 0, f"Starting subdomain scan of {len(subdomain_list)} subdomains...")
            
            for subdomain in subdomain_list:
                ports = self.scan_ports(subdomain)
                for port in ports:
                    combination = f"{subdomain}:{port}"
                    if combination in scanned_combinations:
                        self.progress_tracker.increment()
                        continue
                    
                    scanned_combinations.add(combination)
                    self.progress_tracker.update_status(subdomain, port, "Checking subdomain service...")
                    
                    # Check if user wants to skip
                    if self.progress_tracker.should_skip():
                        logger.info(f"⏭️ Skipped subdomain {subdomain}:{port}")
                        self.progress_tracker.increment()
                        continue
                    
                    try:
                        result = await self.check_web_service(subdomain, port)
                        if result:
                            # Mark as subdomain service
                            result.is_subdomain = True
                            result.original_target = subdomain
                            self.results.append(result)
                            logger.info(f"🔗 Found subdomain service: {subdomain}:{port} ({result.protocol}) - {result.title} [{result.service_type}]")
                            
                            # Update HTML report after every discovery for live updates
                            self.generate_live_html_report()
                        
                    except Exception as e:
                        logger.error(f"Error processing subdomain {subdomain}:{port} - {e}")
                    
                    self.progress_tracker.increment()
        
        # Generate final HTML report
        self.progress_tracker.update_status("Finalizing", 0, "Generating final report...")
        self.generate_live_html_report()
        self.save_results()
        
        self.progress_tracker.close()
        
        # Display colorful summary
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📊 {Style.BRIGHT}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Count different types of services
        service_types = {}
        https_services = 0
        subdomain_services = 0
        
        for service in self.results:
            service_types[service.service_type] = service_types.get(service.service_type, 0) + 1
            if service.protocol == 'https':
                https_services += 1
            if service.is_subdomain:
                subdomain_services += 1
        
        print(f"{Fore.GREEN}✅ Total Services Found: {len(self.results)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}🔗 Subdomain Services: {subdomain_services}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔐 HTTPS Services: {https_services}{Style.RESET_ALL}")
        
        # Service type breakdown
        print(f"\n{Fore.YELLOW}🔍 Service Types Found:{Style.RESET_ALL}")
        for service_type, count in service_types.items():
            service_icons = {
                'web': '🌐',
                'jenkins': '🔧',
                'gitlab': '🐙',
                'jira': '📋',
                'confluence': '📚',
                'sonarqube': '🔍',
                'nexus': '📦',
                'artifactory': '🎨',
                'docker': '🐳',
                'kubernetes': '☸️',
                'prometheus': '📊',
                'grafana': '📈',
                'kibana': '📊',
                'elasticsearch': '🔍'
            }
            icon = service_icons.get(service_type, '🔧')
            print(f"  {icon} {service_type.title()}: {count}")
        
        print(f"\n{Fore.GREEN}💾 Results saved to: {self.output_dir}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}📄 HTML Report: {self.output_dir}/report.html{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 CSV Report: {self.output_dir}/found_web.csv{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        logger.info(f"🎉 Scan completed! Found {len(self.results)} web services.")
    
    def _fuzz_paths(self, service: WebService, url: str) -> List[str]:
        """Fuzz common paths and files on the web service"""
        discovered_paths = []
        
        # Default wordlist for path fuzzing
        default_paths = [
            '/admin', '/login', '/auth', '/api', '/management', '/dashboard', '/portal',
            '/wp-admin', '/administrator', '/admin.php', '/admin.html', '/admin.asp',
            '/phpmyadmin', '/mysql', '/database', '/db', '/sql',
            '/backup', '/backups', '/bak', '/old', '/archive',
            '/config', '/configuration', '/conf', '/settings',
            '/test', '/dev', '/development', '/staging', '/beta',
            '/robots.txt', '/sitemap.xml', '/.htaccess', '/.env', '/config.php',
            '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger', '/docs',
            '/console', '/shell', '/terminal', '/ssh', '/ftp',
            '/cpanel', '/plesk', '/webmin', '/phpinfo.php', '/info.php',
            '/status', '/health', '/ping', '/monitor', '/metrics',
            '/logs', '/log', '/error', '/debug', '/trace',
            '/upload', '/uploads', '/files', '/media', '/images',
            '/tmp', '/temp', '/cache', '/session', '/sessions'
        ]
        
        # Use custom wordlist if provided
        custom_wordlist = self.config.get('fuzz_wordlist', None)
        if custom_wordlist and Path(custom_wordlist).exists():
            try:
                with open(custom_wordlist, 'r') as f:
                    custom_paths = [line.strip() for line in f if line.strip()]
                fuzz_paths = custom_paths + default_paths
                logger.info(f"🔍 Using custom wordlist: {custom_wordlist} ({len(custom_paths)} paths)")
            except Exception as e:
                logger.warning(f"Error loading custom wordlist: {e}")
                fuzz_paths = default_paths
        else:
            fuzz_paths = default_paths
        
        logger.info(f"🔍 Fuzzing {len(fuzz_paths)} paths on {url}")
        
        for path in fuzz_paths:
            try:
                test_url = url + path
                response = self.session.get(test_url, verify=False, timeout=3, allow_redirects=False)
                
                # Consider paths with 200, 301, 302, 401, 403 as discovered
                if response.status_code in [200, 301, 302, 401, 403]:
                    discovered_paths.append(f"{path} ({response.status_code})")
                    logger.info(f"🔍 Found path: {path} - Status: {response.status_code}")
                
            except Exception as e:
                logger.debug(f"Error fuzzing path {path}: {e}")
                continue
        
        return discovered_paths


def main():
    # Display startup banner
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}🚀 WEB DISCOVERY SCANNER - ENHANCED VERSION{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}🔍 {Style.BRIGHT}Features:{Style.RESET_ALL}")
    print(f"  🌐 Web service discovery and analysis")
    print(f"  🔐 SSL/TLS certificate validation")
    print(f"  📸 Automated screenshots")
    print(f"  🔗 Subdomain enumeration")
    print(f"  🔍 Path fuzzing and discovery")
    print(f"  📊 Live HTML reports")
    print(f"  🎯 CI/CD and lateral movement detection")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    parser = argparse.ArgumentParser(description="Web Discovery Scanner - Enhanced Version")
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--input', help='Single IP/hostname/CIDR range')
    input_group.add_argument('--input-file', help='File containing targets')
    
    parser.add_argument('--ports', help='Comma-separated list of ports (default: common web ports)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    parser.add_argument('--threads', type=int, default=30, help='Number of threads (default: 30)')
    parser.add_argument('--output', default='outputs', help='Output directory (default: outputs)')
    parser.add_argument('--no-screenshots', action='store_true', help='Disable screenshot capture')
    parser.add_argument('--no-html', action='store_true', help='Disable HTML report generation')
    parser.add_argument('--creds-file', help='Custom credentials file (format: username:password per line)')
    parser.add_argument('--creds-check', action='store_true', help='Enable default credential checking (disabled by default)')
    parser.add_argument('--enable-fuzzing', action='store_true', help='Enable path fuzzing to discover additional paths and files')
    parser.add_argument('--fuzz-wordlist', help='Custom wordlist file for path fuzzing (one path per line)')
    parser.add_argument('--subdomain-enum', action='store_true', help='Enable active subdomain enumeration (enabled by default)')
    parser.add_argument('--no-subdomain-enum', action='store_true', help='Disable active subdomain enumeration')
    parser.add_argument('--subdomain-list', help='Custom subdomain list file (one subdomain per line)')
    parser.add_argument('--no-recursive', action='store_true', help='Disable recursive scanning of discovered subdomains (enabled by default)')
    
    args = parser.parse_args()
    
    config = vars(args)
    # Ensure default ports are set if not specified
    if args.ports:
        config['ports'] = [int(p.strip()) for p in args.ports.split(',')]
    else:
        config['ports'] = [80, 443, 8080, 8000, 8443, 8888, 81, 82, 7000, 9443]
    
    # Handle recursive scanning flag (inverted logic)
    config['recursive_scan'] = not args.no_recursive
    
    # Handle subdomain enumeration flags
    if args.no_subdomain_enum:
        config['subdomain_enum'] = False
    else:
        config['subdomain_enum'] = True  # Default to True
    
    # Load custom subdomain list if provided
    if args.subdomain_list and Path(args.subdomain_list).exists():
        try:
            with open(args.subdomain_list, 'r') as f:
                custom_subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                config['custom_subdomains'] = custom_subdomains
        except Exception as e:
            logger.error(f"Error loading subdomain list from {args.subdomain_list}: {e}")
            config['custom_subdomains'] = []
    else:
        config['custom_subdomains'] = []
    
    input_type = 'input' if args.input else 'input_file'
    input_source = args.input or args.input_file
    
    scanner = WebDiscoveryScanner(config)
    targets = scanner.parse_input(input_source, input_type)
    
    if not targets:
        logger.error("No valid targets found")
        sys.exit(1)
    
    asyncio.run(scanner.run_scan(targets))

if __name__ == "__main__":
    main() 