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
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        self.kill_scan = False  # New kill switch flag
        self.keyboard_thread = None
        self.running = True  # Control flag for keyboard thread
    
    def start(self):
        print(f"{Fore.CYAN}🚀 {Style.BRIGHT}Starting Web Discovery Scanner{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📊 {Style.BRIGHT}Targets: {self.total_targets} | Ports: {self.total_ports} | Total Tasks: {self.total_tasks}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}⏱️  {Style.BRIGHT}Estimated time: {self.total_tasks * 3:.0f}s{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}⌨️  {Style.BRIGHT}Press 's' to skip current website scan{Style.RESET_ALL}")
        print(f"{Fore.RED}⌨️  {Style.BRIGHT}Press 'k' to kill/stop the entire scan{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⌨️  {Style.BRIGHT}Press Ctrl+C to force exit{Style.RESET_ALL}")
        print("-" * 60)
        self.pbar = tqdm(total=self.total_tasks, desc="🔍 Scanning", unit="target:port", 
                        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]')
        
        # Start keyboard input thread
        self.keyboard_thread = threading.Thread(target=self._keyboard_listener, daemon=True)
        self.keyboard_thread.start()
    
    def _keyboard_listener(self):
        """Listen for keyboard input to skip current scan or kill scan"""
        while self.running:
            try:
                if msvcrt.kbhit():
                    key = msvcrt.getch().decode('utf-8').lower()
                    if key == 's':
                        with self.lock:
                            self.skip_current = True
                        print(f"\n{Fore.YELLOW}⏭️  {Style.BRIGHT}Skipping current scan...{Style.RESET_ALL}")
                    elif key == 'k':
                        with self.lock:
                            self.kill_scan = True
                        print(f"\n{Fore.RED}🛑 {Style.BRIGHT}KILL SWITCH ACTIVATED - Stopping scan...{Style.RESET_ALL}")
                        break
            except (UnicodeDecodeError, KeyboardInterrupt):
                pass
            except Exception as e:
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
    
    def should_kill(self):
        """Check if scan should be killed"""
        with self.lock:
            return self.kill_scan
    
    def stop(self):
        """Stop the keyboard listener thread"""
        self.running = False
        if self.keyboard_thread and self.keyboard_thread.is_alive():
            self.keyboard_thread.join(timeout=1)
    
    def close(self):
        self.stop()
        if self.pbar:
            self.pbar.close()
        if self.kill_scan:
            print(f"{Fore.RED}🛑 {Style.BRIGHT}Scan stopped by user!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ {Style.BRIGHT}Scan completed!{Style.RESET_ALL}")

class WebDiscoveryScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.results = []
        self.vulnerability_groups = {}
        
        # Create organized output directory with date, time, and scope
        self.scan_scope = config.get('scan_scope', 'unknown')
        self.scan_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create base output directory
        base_output = Path(config.get('output', 'outputs'))
        base_output.mkdir(exist_ok=True)
        
        # Create scan-specific directory
        self.output_dir = base_output / f"scan_{self.scan_timestamp}_{self.scan_scope}"
        self.screenshots_dir = self.output_dir / "screenshots"
        
        # Create directories
        self.output_dir.mkdir(exist_ok=True)
        self.screenshots_dir.mkdir(exist_ok=True)
        
        # Log the output directory
        logger.info(f"📁 Output directory: {self.output_dir}")
        logger.info(f"📸 Screenshots directory: {self.screenshots_dir}")
        
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
        # Faster retry strategy with shorter timeouts
        retry_strategy = Retry(total=1, backoff_factor=0.1)  # Reduced retries and backoff
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=50, pool_maxsize=100)  # Increased pool size
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.timeout = self.config.get('timeout', 2)  # Reduced timeout for faster scanning
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        # Limit redirects to prevent redirect loops
        session.max_redirects = 5
        
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
        
        # Use ThreadPoolExecutor for faster port scanning
        with ThreadPoolExecutor(max_workers=min(len(self.ports), 20)) as executor:
            def check_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)  # Very fast timeout
                    if sock.connect_ex((target, port)) == 0:
                        sock.close()
                        return port
                    sock.close()
                except:
                    pass
                return None
            
            # Submit all port checks
            future_to_port = {executor.submit(check_port, port): port for port in self.ports}
            
            # Collect results
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
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
            
            # Faster request with shorter timeout and better error handling
            try:
                response = self.session.get(url, verify=False, timeout=3, allow_redirects=True)
            except requests.exceptions.TooManyRedirects:
                logger.warning(f"⚠️ Too many redirects for {url}")
                service.title = "Redirect Loop Detected"
                service.status_code = 302
                return service
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"⚠️ Connection error for {url}: {e}")
                service.title = "Connection Error"
                service.status_code = 0
                return service
            except requests.exceptions.Timeout:
                logger.warning(f"⚠️ Timeout for {url}")
                service.title = "Timeout"
                service.status_code = 0
                return service
            except Exception as e:
                logger.error(f"❌ Error analyzing {url}: {e}")
                logger.error(f"❌ Traceback: {traceback.format_exc()}")
                service.title = f"Error: {str(e)[:50]}"
                service.status_code = 0
                return service
            service.status_code = response.status_code
            service.headers = dict(response.headers)
            service.server_banner = response.headers.get('Server', '')
            
            logger.info(f"📊 Response status: {response.status_code}, Server: {service.server_banner}")
            
            # Extract cookies
            if 'Set-Cookie' in response.headers:
                try:
                    # Handle both single and multiple cookies
                    set_cookie_header = response.headers.get('Set-Cookie', '')
                    if isinstance(set_cookie_header, list):
                        cookies = set_cookie_header
                    else:
                        cookies = [set_cookie_header]
                    
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
                # Only take screenshots for interesting services to speed up scanning
                interesting_services = ['login', 'ci_cd_lateral', 'router', 'database', 'monitoring']
                if (service.service_type in interesting_services or 
                    service.specific_target or 
                    service.vulnerabilities or
                    service.status_code != 200):
                    logger.info(f"📸 Taking screenshot of {url}")
                    screenshot_path = await self._take_screenshot(url, target, port, protocol)
                    if screenshot_path:
                        service.screenshot_file = str(screenshot_path)
                        logger.info(f"📸 Screenshot saved: {screenshot_path}")
                    else:
                        service.screenshot_file = ""
                        logger.info(f"📸 Screenshot failed")
                else:
                    service.screenshot_file = ""
                    logger.debug(f"📸 Skipping screenshot for {url} (not interesting)")
            
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
                
                # Faster page loading for screenshots
                try:
                    # Use domcontentloaded for faster loading
                    await page.goto(url, wait_until='domcontentloaded', timeout=8000)
                    
                    # Wait for basic content to load
                    await asyncio.sleep(2)
                    
                    # Check if page has content (not just white)
                    content = await page.content()
                    if len(content.strip()) < 100:  # Very little content
                        logger.warning(f"⚠️ Page appears to have little content: {url}")
                        # Try waiting a bit more
                        await asyncio.sleep(1)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Page load timeout for {url}: {e}")
                    # Try alternative loading strategy
                    try:
                        await page.goto(url, wait_until='domcontentloaded', timeout=5000)
                        await asyncio.sleep(1)
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
        
        # Calculate vulnerability statistics
        vulnerable_count = len([s for s in self.results if s.vulnerabilities])
        expired_certs_count = len([s for s in self.results if s.cert_status == "Expired"])
        lateral_count = len([s for s in self.results if s.specific_target])
        https_count = len([s for s in self.results if s.protocol == 'https'])
        total_services = len(self.results)
        
        # Determine card classes based on counts
        critical_class = "critical" if vulnerable_count > 0 else "success"
        warning_class = "warning" if expired_certs_count > 0 else "success"
        success_class = "success"
        info_class = "info" if lateral_count > 0 else "success"
        
        # Generate vulnerability explanations
        vulnerability_explanations = self._generate_vulnerability_explanations()
        
        # Generate table rows
        table_rows = self._generate_table_rows()
        
        # Generate discovered paths section
        discovered_paths_section = self._generate_discovered_paths_section()
        
        # Generate CI/CD and lateral movement section
        cicd_lateral_section = self._generate_cicd_lateral_section()
        
        # Only show real discovered paths, no sample data
        
        # Only show real CI/CD and lateral movement assets, no sample data
        
        # Use string replacement instead of format to avoid CSS conflicts
        html_content = self._get_html_template()
        
        # Replace placeholders
        html_content = html_content.replace('{vulnerable_count}', str(vulnerable_count))
        html_content = html_content.replace('{expired_certs_count}', str(expired_certs_count))
        html_content = html_content.replace('{total_services}', str(total_services))
        html_content = html_content.replace('{lateral_count}', str(lateral_count))
        html_content = html_content.replace('{critical_class}', critical_class)
        html_content = html_content.replace('{warning_class}', warning_class)
        html_content = html_content.replace('{success_class}', success_class)
        html_content = html_content.replace('{info_class}', info_class)
        html_content = html_content.replace('{vulnerability_explanations}', vulnerability_explanations)
        html_content = html_content.replace('{table_rows}', table_rows)
        html_content = html_content.replace('{discovered_paths_section}', discovered_paths_section)
        html_content = html_content.replace('{cicd_lateral_section}', cicd_lateral_section)
        
        return html_content
    
    def _get_html_template(self) -> str:
        """Get the HTML template with proper CSS escaping"""
        return r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Discovery Scanner - Executive Report</title>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/responsive/2.2.9/css/responsive.dataTables.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #2d3748;
            line-height: 1.6;
        }
        
        .main-container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 20px;
        }
        
        .header { 
            background: rgba(255, 255, 255, 0.95); 
            backdrop-filter: blur(10px);
            border-radius: 20px; 
            padding: 30px; 
            margin-bottom: 30px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .header h1 { 
            font-size: 2.5rem; 
            font-weight: 700; 
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .live-indicator { 
            color: #48bb78; 
            animation: pulse 2s infinite;
            font-size: 1.5rem;
        }
        
        @keyframes pulse { 
            0% { opacity: 1; transform: scale(1); } 
            50% { opacity: 0.5; transform: scale(1.1); } 
            100% { opacity: 1; transform: scale(1); } 
        }
        
        .header-subtitle {
            color: #718096;
            font-size: 1.1rem;
            font-weight: 400;
        }
        
        .executive-summary {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .executive-summary h2 {
            font-size: 1.8rem;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #f7fafc, #edf2f7);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid #e2e8f0;
            transition: all 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0,0,0,0.1);
        }
        
        .summary-card.critical {
            background: linear-gradient(135deg, #fed7d7, #feb2b2);
            border-color: #fc8181;
        }
        
        .summary-card.warning {
            background: linear-gradient(135deg, #fef5e7, #fed7aa);
            border-color: #f6ad55;
        }
        
        .summary-card.success {
            background: linear-gradient(135deg, #f0fff4, #c6f6d5);
            border-color: #68d391;
        }
        
        .summary-card.info {
            background: linear-gradient(135deg, #ebf8ff, #bee3f8);
            border-color: #63b3ed;
        }
        
        .summary-number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .summary-card.critical .summary-number { color: #c53030; }
        .summary-card.warning .summary-number { color: #dd6b20; }
        .summary-card.success .summary-number { color: #2f855a; }
        .summary-card.info .summary-number { color: #2b6cb0; }
        
        .summary-label {
            font-size: 0.9rem;
            font-weight: 500;
            color: #4a5568;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .vulnerability-analysis {
            background: #f7fafc;
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
        }
        
        .vulnerability-analysis h3 {
            font-size: 1.5rem;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .vuln-category {
            background: #f7fafc;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #e53e3e;
        }
        
        .vuln-category.warning {
            border-left-color: #dd6b20;
        }
        
        .vuln-category.info {
            border-left-color: #3182ce;
        }
        
        .vuln-title {
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 10px;
            color: #2d3748;
        }
        
        .vuln-description {
            color: #4a5568;
            margin-bottom: 10px;
            line-height: 1.6;
        }
        
        .vuln-impact {
            background: #fff5f5;
            border-radius: 8px;
            padding: 12px;
            font-size: 0.9rem;
            color: #c53030;
        }
        
        .vuln-impact.warning {
            background: #fffaf0;
            color: #dd6b20;
        }
        
        .vuln-impact.info {
            background: #ebf8ff;
            color: #2b6cb0;
        }
        
        .search-controls {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .search-controls h4 {
            font-size: 1.3rem;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .search-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .search-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #4a5568;
        }
        
        .search-group input,
        .search-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 14px;
            transition: all 0.3s ease;
            background: white;
        }
        
        .search-group input:focus,
        .search-group select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .filter-buttons {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 10px 20px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.3s ease;
            font-size: 14px;
        }
        
        .filter-btn.active {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }
        
        .filter-btn:not(.active) {
            background: #f7fafc;
            color: #4a5568;
            border: 2px solid #e2e8f0;
        }
        
        .filter-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        
        .clear-filters {
            background: linear-gradient(135deg, #fc8181, #f56565);
            color: white;
        }
        
        .data-table-section {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .data-table-section h3 {
            font-size: 1.5rem;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .service-type {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .type-web { background: #c6f6d5; color: #2f855a; }
        .type-router { background: #bee3f8; color: #2b6cb0; }
        .type-login { background: #fed7d7; color: #c53030; }
        .type-ci_cd_lateral { background: #fc8181; color: white; }
        .type-database { background: #fef5e7; color: #dd6b20; }
        .type-monitoring { background: #e6fffa; color: #2c7a7b; }
        
        /* Path Badges */
        .path-badge-success { background: #68d391; color: white; padding: 4px 8px; border-radius: 12px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-success:hover { background: #48bb78; color: white; text-decoration: none; }
        .path-badge-redirect { background: #f6ad55; color: white; padding: 4px 8px; border-radius: 12px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-redirect:hover { background: #ed8936; color: white; text-decoration: none; }
        .path-badge-auth { background: #63b3ed; color: white; padding: 4px 8px; border-radius: 12px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-auth:hover { background: #4299e1; color: white; text-decoration: none; }
        .path-badge-forbidden { background: #fc8181; color: white; padding: 4px 8px; border-radius: 12px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-forbidden:hover { background: #f56565; color: white; text-decoration: none; }
        .path-badge-other { background: #a0aec0; color: white; padding: 4px 8px; border-radius: 12px; font-size: 11px; margin: 2px; display: inline-block; text-decoration: none; }
        .path-badge-other:hover { background: #718096; color: white; text-decoration: none; }
        
        .screenshot {
            max-width: 120px;
            max-height: 90px;
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.3s ease;
            border: 2px solid #e2e8f0;
        }
        
        .screenshot:hover {
            transform: scale(3);
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            z-index: 1000;
            position: relative;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.9);
            backdrop-filter: blur(5px);
        }
        
        .modal-content {
            margin: auto;
            display: block;
            max-width: 95%;
            max-height: 95%;
            margin-top: 2%;
            border-radius: 15px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.5);
            transition: transform 0.3s ease;
        }
        
        .close {
            position: absolute;
            top: 20px;
            right: 40px;
            color: #f1f1f1;
            font-size: 50px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .close:hover {
            color: #fc8181;
            transform: scale(1.1);
        }
        
        @media (max-width: 768px) {
            .main-container { padding: 10px; }
            .header h1 { font-size: 2rem; }
            .summary-grid { grid-template-columns: 1fr; }
            .search-row { grid-template-columns: 1fr; }
            .filter-buttons { justify-content: center; }
        }
        
        .dataTables_wrapper .dataTables_length,
        .dataTables_wrapper .dataTables_filter,
        .dataTables_wrapper .dataTables_info,
        .dataTables_wrapper .dataTables_processing,
        .dataTables_wrapper .dataTables_paginate {
            color: #4a5568;
            font-weight: 500;
        }
        
        .dataTables_wrapper .dataTables_length select,
        .dataTables_wrapper .dataTables_filter input {
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            padding: 8px 12px;
            font-size: 14px;
        }
        
        .dataTables_wrapper .dataTables_length select:focus,
        .dataTables_wrapper .dataTables_filter input:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .dataTables_wrapper .dataTables_paginate .paginate_button {
            border: 2px solid #e2e8f0;
            padding: 8px 16px;
            margin: 0 4px;
            cursor: pointer;
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .dataTables_wrapper .dataTables_paginate .paginate_button:hover {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border-color: #667eea;
        }
        
        .dataTables_wrapper .dataTables_paginate .paginate_button.current {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border-color: #667eea;
        }
        
        table.dataTable {
            border-collapse: collapse;
            width: 100%;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }
        
        table.dataTable thead th {
            background: linear-gradient(135deg, #f7fafc, #edf2f7);
            border: none;
            padding: 15px 12px;
            font-weight: 600;
            color: #2d3748;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
        }
        
        table.dataTable tbody td {
            border: none;
            border-bottom: 1px solid #e2e8f0;
            padding: 12px;
            vertical-align: middle;
        }
        
        table.dataTable tbody tr:nth-child(even) {
            background: #f7fafc;
        }
        
        table.dataTable tbody tr:hover {
            background: #edf2f7;
            transform: scale(1.01);
            transition: all 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="main-container">
        <div class="header">
            <h1>🚀 Web Discovery Scanner <span class="live-indicator">●</span></h1>
            <p class="header-subtitle">Executive Security Assessment Report</p>
        </div>
        
        <div class="executive-summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card {critical_class}">
                    <div class="summary-number">{vulnerable_count}</div>
                    <div class="summary-label">Vulnerable Services</div>
                </div>
                <div class="summary-card {warning_class}">
                    <div class="summary-number">{expired_certs_count}</div>
                    <div class="summary-label">Expired Certificates</div>
                </div>
                <div class="summary-card {success_class}">
                    <div class="summary-number">{total_services}</div>
                    <div class="summary-label">Total Services Found</div>
                </div>
                <div class="summary-card {info_class}">
                    <div class="summary-number">{lateral_count}</div>
                    <div class="summary-label">Lateral Movement Targets</div>
                </div>
            </div>
            
            <div class="vulnerability-analysis">
                <h3>🔍 Vulnerability Analysis</h3>
                {vulnerability_explanations}
            </div>
        </div>
        
        <div class="search-controls">
            <h4>🔍 Search & Filter Controls</h4>
            <div class="search-row">
                <div class="search-group">
                    <label for="globalSearch">Global Search:</label>
                    <input type="text" id="globalSearch" placeholder="Search across all fields...">
                </div>
                <div class="search-group">
                    <label for="serviceTypeFilter">Service Type:</label>
                    <select id="serviceTypeFilter">
                        <option value="">All Types</option>
                        <option value="web">Web Service</option>
                        <option value="router">Router</option>
                        <option value="login">Login</option>
                        <option value="ci_cd_lateral">CI/CD & Lateral</option>
                    </select>
                </div>
                <div class="search-group">
                    <label for="protocolFilter">Protocol:</label>
                    <select id="protocolFilter">
                        <option value="">All Protocols</option>
                        <option value="http">HTTP</option>
                        <option value="https">HTTPS</option>
                    </select>
                </div>
                <div class="search-group">
                    <label for="vulnerabilityFilter">Vulnerabilities:</label>
                    <select id="vulnerabilityFilter">
                        <option value="">All Services</option>
                        <option value="has_vulns">Has Vulnerabilities</option>
                        <option value="no_vulns">No Vulnerabilities</option>
                    </select>
                </div>
            </div>
            <div class="filter-buttons">
                <button class="filter-btn active" data-filter="all">All Services</button>
                <button class="filter-btn" data-filter="vulnerable">Vulnerable</button>
                <button class="filter-btn" data-filter="https">HTTPS Only</button>
                <button class="filter-btn" data-filter="lateral">Lateral Movement</button>
                <button class="filter-btn clear-filters">Clear Filters</button>
            </div>
        </div>
        
        <div class="data-table-section">
            <h3>🌐 Discovered Services</h3>
            <table id="resultsTable" class="display responsive nowrap" style="width:100%">
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Type</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Screenshot</th>
                        <th>Vulnerabilities</th>
                        <th>Certificate</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
        
        <div class="data-table-section">
            <h3>🔍 Discovered Paths & Files</h3>
            <div id="pathsSection">
                {discovered_paths_section}
            </div>
        </div>
        
        <div class="data-table-section">
            <h3>🎯 CI/CD & Lateral Movement Assets</h3>
            <div id="cicdSection">
                {cicd_lateral_section}
            </div>
        </div>
        
        <div id="screenshotModal" class="modal">
            <span class="close">&times;</span>
            <img class="modal-content" id="modalImage">
        </div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/responsive/2.2.9/js/dataTables.responsive.min.js"></script>
    <script>
        $(document).ready(function() {
            var table = $('#resultsTable').DataTable({
                responsive: true,
                pageLength: 10,
                order: [[0, 'asc']],
                scrollX: true,
                autoWidth: false,
                scrollCollapse: true,
                columnDefs: [
                    { targets: [4, 5, 6], orderable: false },
                    { targets: [4], width: '100px' },
                    { targets: [5], width: '150px' },
                    { targets: [6], width: '200px' }
                ]
            });
            
            // Global search functionality
            $('#globalSearch').on('keyup', function() {
                table.search(this.value).draw();
            });
            
            // Service type filter
            $('#serviceTypeFilter').on('change', function() {
                var filterValue = $(this).val();
                if (filterValue) {
                    table.column(1).search(filterValue).draw();
                } else {
                    table.column(1).search('').draw();
                }
            });
            
            // Protocol filter
            $('#protocolFilter').on('change', function() {
                var filterValue = $(this).val();
                if (filterValue) {
                    table.column(0).search(filterValue).draw();
                } else {
                    table.column(0).search('').draw();
                }
            });
            
            // Vulnerability filter
            $('#vulnerabilityFilter').on('change', function() {
                var filterValue = $(this).val();
                if (filterValue === 'has_vulns') {
                    table.column(5).search('found').draw();
                } else if (filterValue === 'no_vulns') {
                    table.column(5).search('None').draw();
                } else {
                    table.column(5).search('').draw();
                }
            });
            
            // Filter buttons
            $('.filter-btn').on('click', function() {
                $('.filter-btn').removeClass('active');
                $(this).addClass('active');
                
                var filter = $(this).data('filter');
                if (filter === 'vulnerable') {
                    table.column(5).search('found').draw();
                } else if (filter === 'https') {
                    table.column(0).search('https').draw();
                } else if (filter === 'lateral') {
                    table.column(1).search('ci_cd_lateral').draw();
                } else {
                    table.search('').columns().search('').draw();
                }
            });
            
            // Clear filters
            $('.clear-filters').on('click', function() {
                $('#globalSearch').val('');
                $('#serviceTypeFilter').val('');
                $('#protocolFilter').val('');
                $('#vulnerabilityFilter').val('');
                $('.filter-btn').removeClass('active');
                $('.filter-btn[data-filter="all"]').addClass('active');
                table.search('').columns().search('').draw();
            });
        });
        
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
        
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
        """
    
    def _generate_vulnerability_explanations(self) -> str:
        """Generate detailed vulnerability explanations for the executive summary"""
        explanations = ""
        
        # Collect all unique vulnerabilities
        all_vulns = set()
        for service in self.results:
            if service.vulnerabilities:
                for vuln in service.vulnerabilities:
                    all_vulns.add(vuln)
        
        if not all_vulns:
            explanations = """
            <div class="vuln-category success">
                <div class="vuln-title">✅ No Critical Vulnerabilities Detected</div>
                <div class="vuln-description">The scan did not identify any critical security vulnerabilities in the discovered services.</div>
                <div class="vuln-impact info">This is a positive security indicator, but regular monitoring is still recommended.</div>
            </div>
            """
            return explanations
        
        # Categorize vulnerabilities
        vuln_categories = {
            'server_info': [],
            'default_creds': [],
            'expired_certs': [],
            'missing_headers': [],
            'other': []
        }
        
        for vuln in all_vulns:
            if 'server info disclosure' in vuln.lower():
                vuln_categories['server_info'].append(vuln)
            elif 'default_creds' in vuln.lower():
                vuln_categories['default_creds'].append(vuln)
            elif 'expired' in vuln.lower() or 'certificate' in vuln.lower():
                vuln_categories['expired_certs'].append(vuln)
            elif 'missing' in vuln.lower() and 'header' in vuln.lower():
                vuln_categories['missing_headers'].append(vuln)
            else:
                vuln_categories['other'].append(vuln)
        
        # Generate explanations for each category
        if vuln_categories['server_info']:
            explanations += """
            <div class="vuln-category warning">
                <div class="vuln-title">⚠️ Server Information Disclosure</div>
                <div class="vuln-description">Web servers are revealing detailed version information that could aid attackers in identifying potential exploits.</div>
                <div class="vuln-impact warning">
                    <strong>Impact:</strong> Attackers can use this information to target specific vulnerabilities for the disclosed server versions.
                    <br><strong>Recommendation:</strong> Configure servers to hide version information and use generic server banners.
                </div>
            </div>
            """
        
        if vuln_categories['default_creds']:
            explanations += """
            <div class="vuln-category critical">
                <div class="vuln-title">🚨 Default Credentials Active</div>
                <div class="vuln-description">Services are accessible using default or weak credentials, providing unauthorized access to sensitive systems.</div>
                <div class="vuln-impact">
                    <strong>Impact:</strong> Immediate unauthorized access to systems, potential data breach, and lateral movement capabilities.
                    <br><strong>Recommendation:</strong> Immediately change all default passwords and implement strong authentication policies.
                </div>
            </div>
            """
        
        if vuln_categories['expired_certs']:
            explanations += """
            <div class="vuln-category warning">
                <div class="vuln-title">⚠️ Expired SSL Certificates</div>
                <div class="vuln-description">SSL/TLS certificates have expired, potentially causing browser warnings and reducing user trust.</div>
                <div class="vuln-impact warning">
                    <strong>Impact:</strong> Browser security warnings, potential man-in-the-middle attacks, reduced user confidence.
                    <br><strong>Recommendation:</strong> Renew certificates immediately and implement automated certificate monitoring.
                </div>
            </div>
            """
        
        if vuln_categories['missing_headers']:
            explanations += """
            <div class="vuln-category info">
                <div class="vuln-title">ℹ️ Missing Security Headers</div>
                <div class="vuln-description">Web applications are missing recommended security headers that help protect against common attacks.</div>
                <div class="vuln-impact info">
                    <strong>Impact:</strong> Increased risk of XSS, clickjacking, and other client-side attacks.
                    <br><strong>Recommendation:</strong> Implement security headers like X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy.
                </div>
            </div>
            """
        
        if vuln_categories['other']:
            explanations += """
            <div class="vuln-category info">
                <div class="vuln-title">ℹ️ Other Security Findings</div>
                <div class="vuln-description">Additional security observations that should be reviewed and addressed.</div>
                <div class="vuln-impact info">
                    <strong>Findings:</strong> Review each finding individually and implement appropriate security measures.
                </div>
            </div>
            """
        
        return explanations
    
    def _generate_table_rows(self) -> str:
        """Generate table rows for the services data table"""
        table_rows = ""
        
        for i, service in enumerate(self.results):
            service_url = f"{service.protocol}://{service.ip}:{service.port}"
            
            # Service type badge
            type_class = f"type-{service.service_type}"
            type_badge = f'<span class="service-type {type_class}">{service.service_type.upper()}</span>'
            
            # Screenshot cell
            screenshot_cell = ""
            if service.screenshot_file:
                screenshot_filename = Path(service.screenshot_file).name
                relative_path = f"screenshots/{screenshot_filename}"
                if Path(service.screenshot_file).exists():
                    screenshot_cell = f'<img src="{relative_path}" class="screenshot" onclick="openModal(\'{relative_path}\')" alt="Screenshot">'
                else:
                    screenshot_cell = f'<em>Not found</em>'
            else:
                screenshot_cell = '<em>No screenshot</em>'
            
            # Vulnerabilities cell
            vuln_cell = ""
            if service.vulnerabilities:
                vuln_count = len(service.vulnerabilities)
                vuln_cell = f'<span style="color: #e53e3e; font-weight: bold;">{vuln_count} found</span>'
                for vuln in service.vulnerabilities[:2]:  # Show first 2
                    vuln_cell += f'<br><small style="color: #666;">• {vuln[:50]}...</small>'
                if len(service.vulnerabilities) > 2:
                    vuln_cell += f'<br><small style="color: #666;">... and {len(service.vulnerabilities) - 2} more</small>'
            else:
                vuln_cell = '<span style="color: #38a169;">None</span>'
            
            # Certificate cell with colored badges
            cert_cell = ""
            if service.cert_expiry:
                if service.cert_status == "Expired":
                    status_badge = '<span style="background: #fc8181; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">EXPIRED</span>'
                elif service.cert_status == "Expiring Soon":
                    status_badge = '<span style="background: #f6ad55; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">EXPIRING</span>'
                else:
                    status_badge = '<span style="background: #68d391; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">VALID</span>'
                
                cert_cell = f'<div style="font-size: 12px;">'
                cert_cell += f'<strong>Expires:</strong> {service.cert_expiry}<br>'
                cert_cell += status_badge
                if service.cert_sans:
                    cert_cell += f'<br><small>SANs: {len(service.cert_sans)} domains</small>'
                cert_cell += '</div>'
            else:
                cert_cell = '<em>No certificate</em>'
            
            # Service cell with domain name if available
            service_cell = f'<a href="{service_url}" target="_blank" style="font-weight: 600;">{service.ip}:{service.port}</a>'
            if service.domain_name:
                service_cell += f'<br><small style="color: #666;">🌐 {service.domain_name}</small>'
            
            # Status cell with color coding
            status_color = "#38a169" if service.status_code == 200 else "#e53e3e" if service.status_code >= 400 else "#d69e2e"
            status_cell = f'<span style="color: {status_color}; font-weight: bold;">{service.status_code}</span>'
            
            table_rows += f"""
                <tr>
                    <td>{service_cell}</td>
                    <td>{type_badge}</td>
                    <td>{service.title or 'No title'}</td>
                    <td>{status_cell}</td>
                    <td>{screenshot_cell}</td>
                    <td>{vuln_cell}</td>
                    <td>{cert_cell}</td>
                </tr>
            """
        
        return table_rows
    
    def _generate_discovered_paths_section(self) -> str:
        """Generate discovered paths section with status badges"""
        paths_html = ""
        
        # Collect all services with discovered paths
        services_with_paths = []
        for service in self.results:
            if service.discovered_paths:
                services_with_paths.append(service)
        
        if not services_with_paths:
            return '<p style="text-align: center; color: #718096; font-style: italic;">No additional paths discovered during this scan.</p>'
        
        for service in services_with_paths:
            service_url = f"{service.protocol}://{service.ip}:{service.port}"
            paths_html += f'<div style="margin-bottom: 30px; background: #f7fafc; border-radius: 12px; padding: 20px;">'
            paths_html += f'<h4 style="margin-bottom: 15px; color: #2d3748;">🌐 {service.ip}:{service.port} ({service.protocol.upper()})</h4>'
            
            # Count status codes
            status_counts = {'200': 0, '301': 0, '302': 0, '401': 0, '403': 0, 'other': 0}
            paths_list = ""
            
            for path in service.discovered_paths:
                # Extract status code from path string (format: "/path (status)")
                import re
                status_match = re.search(r'\((\d+)\)$', path)
                status_code = status_match.group(1) if status_match else "200"
                
                # Count status codes
                if status_code == "200":
                    status_counts['200'] += 1
                    badge_class = "path-badge-success"
                elif status_code == "301":
                    status_counts['301'] += 1
                    badge_class = "path-badge-redirect"
                elif status_code == "302":
                    status_counts['302'] += 1
                    badge_class = "path-badge-redirect"
                elif status_code == "401":
                    status_counts['401'] += 1
                    badge_class = "path-badge-auth"
                elif status_code == "403":
                    status_counts['403'] += 1
                    badge_class = "path-badge-forbidden"
                else:
                    status_counts['other'] += 1
                    badge_class = "path-badge-other"
                
                # Clean path name (remove status code)
                clean_path = re.sub(r'\s*\(\d+\)$', '', path)
                full_url = f"{service_url}{clean_path}"
                
                paths_list += f'<a href="{full_url}" target="_blank" class="{badge_class}">{clean_path} ({status_code})</a> '
            
            # Create status summary
            status_summary = []
            if status_counts['200'] > 0:
                status_summary.append(f'<span style="background: #68d391; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin-right: 8px;">✅ {status_counts["200"]} OK</span>')
            if status_counts['301'] + status_counts['302'] > 0:
                status_summary.append(f'<span style="background: #f6ad55; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin-right: 8px;">🔄 {status_counts["301"] + status_counts["302"]} Redirect</span>')
            if status_counts['401'] > 0:
                status_summary.append(f'<span style="background: #63b3ed; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin-right: 8px;">🔐 {status_counts["401"]} Auth</span>')
            if status_counts['403'] > 0:
                status_summary.append(f'<span style="background: #fc8181; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin-right: 8px;">🚫 {status_counts["403"]} Forbidden</span>')
            if status_counts['other'] > 0:
                status_summary.append(f'<span style="background: #a0aec0; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; margin-right: 8px;">❓ {status_counts["other"]} Other</span>')
            
            paths_html += f'<div style="margin-bottom: 15px;">{" ".join(status_summary)}</div>'
            paths_html += f'<div style="background: white; border-radius: 8px; padding: 15px; border: 1px solid #e2e8f0;">{paths_list}</div>'
            paths_html += '</div>'
        
        return paths_html
    
    def _generate_cicd_lateral_section(self) -> str:
        """Generate CI/CD and lateral movement assets section"""
        cicd_html = ""
        
        # Collect all CI/CD and lateral movement targets
        cicd_targets = {}
        lateral_targets = {}
        
        for service in self.results:
            if service.specific_target:
                if service.specific_target not in cicd_targets:
                    cicd_targets[service.specific_target] = []
                cicd_targets[service.specific_target].append(service)
            
            # Check for lateral movement indicators
            if any(keyword in service.title.lower() for keyword in ['jenkins', 'gitlab', 'github', 'bitbucket', 'teamcity', 'bamboo', 'azure devops', 'jira', 'confluence', 'sonarqube', 'nexus', 'artifactory']):
                if 'lateral_movement' not in lateral_targets:
                    lateral_targets['lateral_movement'] = []
                lateral_targets['lateral_movement'].append(service)
            
            # Check for database services
            if any(keyword in service.title.lower() for keyword in ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'kibana', 'grafana', 'prometheus']):
                if 'databases' not in lateral_targets:
                    lateral_targets['databases'] = []
                lateral_targets['databases'].append(service)
            
            # Check for monitoring services
            if any(keyword in service.title.lower() for keyword in ['zabbix', 'nagios', 'prtg', 'solarwinds', 'datadog', 'newrelic', 'splunk']):
                if 'monitoring' not in lateral_targets:
                    lateral_targets['monitoring'] = []
                lateral_targets['monitoring'].append(service)
        
        # Generate CI/CD section
        if cicd_targets:
            cicd_html += '<div style="margin-bottom: 30px; background: #fff5f5; border-radius: 12px; padding: 20px; border-left: 4px solid #fc8181;">'
            cicd_html += '<h3 style="margin-bottom: 20px; color: #c53030;">🚨 CI/CD & Development Assets</h3>'
            
            for target_type, services in cicd_targets.items():
                cicd_html += f'<div style="margin-bottom: 20px;">'
                cicd_html += f'<h4 style="margin-bottom: 10px; color: #2d3748;">🎯 {target_type.replace("_", " ").title()} ({len(services)} found)</h4>'
                
                for service in services:
                    service_url = f"{service.protocol}://{service.ip}:{service.port}"
                    cicd_html += f'<div style="background: white; border-radius: 8px; padding: 15px; margin-bottom: 10px; border: 1px solid #fed7d7;">'
                    cicd_html += f'<div style="display: flex; justify-content: space-between; align-items: center;">'
                    cicd_html += f'<div>'
                    cicd_html += f'<a href="{service_url}" target="_blank" style="font-weight: 600; color: #c53030;">{service.ip}:{service.port}</a>'
                    if service.domain_name:
                        cicd_html += f'<br><small style="color: #666;">🌐 {service.domain_name}</small>'
                    cicd_html += f'<br><span style="color: #4a5568;">{service.title}</span>'
                    cicd_html += f'</div>'
                    
                    # Add screenshot if available
                    if service.screenshot_file:
                        screenshot_filename = Path(service.screenshot_file).name
                        relative_path = f"screenshots/{screenshot_filename}"
                        cicd_html += f'<img src="{relative_path}" class="screenshot" onclick="openModal(\'{relative_path}\')" alt="Screenshot" style="max-width: 80px; max-height: 60px;">'
                    
                    cicd_html += f'</div>'
                    
                    # Add vulnerabilities if any
                    if service.vulnerabilities:
                        cicd_html += f'<div style="margin-top: 10px;">'
                        cicd_html += f'<span style="color: #e53e3e; font-weight: bold;">⚠️ Vulnerabilities:</span>'
                        for vuln in service.vulnerabilities:
                            cicd_html += f'<br><small style="color: #666;">• {vuln}</small>'
                        cicd_html += f'</div>'
                    
                    cicd_html += f'</div>'
                
                cicd_html += f'</div>'
            
            cicd_html += '</div>'
        
        # Generate lateral movement section
        if lateral_targets:
            cicd_html += '<div style="margin-bottom: 30px; background: #f0fff4; border-radius: 12px; padding: 20px; border-left: 4px solid #68d391;">'
            cicd_html += '<h3 style="margin-bottom: 20px; color: #2f855a;">🎯 Lateral Movement Targets</h3>'
            
            for target_type, services in lateral_targets.items():
                cicd_html += f'<div style="margin-bottom: 20px;">'
                cicd_html += f'<h4 style="margin-bottom: 10px; color: #2d3748;">🔗 {target_type.replace("_", " ").title()} ({len(services)} found)</h4>'
                
                for service in services:
                    service_url = f"{service.protocol}://{service.ip}:{service.port}"
                    cicd_html += f'<div style="background: white; border-radius: 8px; padding: 15px; margin-bottom: 10px; border: 1px solid #c6f6d5;">'
                    cicd_html += f'<div style="display: flex; justify-content: space-between; align-items: center;">'
                    cicd_html += f'<div>'
                    cicd_html += f'<a href="{service_url}" target="_blank" style="font-weight: 600; color: #2f855a;">{service.ip}:{service.port}</a>'
                    if service.domain_name:
                        cicd_html += f'<br><small style="color: #666;">🌐 {service.domain_name}</small>'
                    cicd_html += f'<br><span style="color: #4a5568;">{service.title}</span>'
                    cicd_html += f'</div>'
                    
                    # Add screenshot if available
                    if service.screenshot_file:
                        screenshot_filename = Path(service.screenshot_file).name
                        relative_path = f"screenshots/{screenshot_filename}"
                        cicd_html += f'<img src="{relative_path}" class="screenshot" onclick="openModal(\'{relative_path}\')" alt="Screenshot" style="max-width: 80px; max-height: 60px;">'
                    
                    cicd_html += f'</div>'
                    
                    # Add vulnerabilities if any
                    if service.vulnerabilities:
                        cicd_html += f'<div style="margin-top: 10px;">'
                        cicd_html += f'<span style="color: #e53e3e; font-weight: bold;">⚠️ Vulnerabilities:</span>'
                        for vuln in service.vulnerabilities:
                            cicd_html += f'<br><small style="color: #666;">• {vuln}</small>'
                        cicd_html += f'</div>'
                    
                    cicd_html += f'</div>'
                
                cicd_html += f'</div>'
            
            cicd_html += '</div>'
        
        # If no CI/CD or lateral movement targets found
        if not cicd_targets and not lateral_targets:
            cicd_html = '<div style="margin-bottom: 30px; background: #f7fafc; border-radius: 12px; padding: 20px; text-align: center;">'
            cicd_html += '<h3 style="margin-bottom: 10px; color: #718096;">🎯 CI/CD & Lateral Movement Assets</h3>'
            cicd_html += '<p style="color: #718096; font-style: italic;">No CI/CD or lateral movement targets detected during this scan.</p>'
            cicd_html += '</div>'
        
        return cicd_html
    
    def save_results(self):
        # Save CSV results
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
        
        # Save scan summary
        summary_file = self.output_dir / "scan_summary.txt"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("WEB DISCOVERY SCANNER - SCAN SUMMARY\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Scope: {self.scan_scope}\n")
            f.write(f"Scan Directory: {self.output_dir}\n\n")
            
            f.write(f"Total Services Found: {len(self.results)}\n")
            
            # Count different types of services
            service_types = {}
            https_services = 0
            subdomain_services = 0
            vulnerable_services = 0
            
            for service in self.results:
                service_types[service.service_type] = service_types.get(service.service_type, 0) + 1
                if service.protocol == 'https':
                    https_services += 1
                if service.is_subdomain:
                    subdomain_services += 1
                if service.vulnerabilities:
                    vulnerable_services += 1
            
            f.write(f"HTTPS Services: {https_services}\n")
            f.write(f"Subdomain Services: {subdomain_services}\n")
            f.write(f"Vulnerable Services: {vulnerable_services}\n\n")
            
            f.write("Service Types Found:\n")
            for service_type, count in service_types.items():
                f.write(f"  - {service_type.title()}: {count}\n")
            
            f.write(f"\nFiles Generated:\n")
            f.write(f"  - HTML Report: report.html\n")
            f.write(f"  - CSV Results: found_web.csv\n")
            f.write(f"  - Screenshots: screenshots/ directory\n")
            f.write(f"  - This Summary: scan_summary.txt\n")
            
            f.write(f"\nScan completed successfully!\n")
            f.write("=" * 60 + "\n")
        
        logger.info(f"💾 Results saved to {self.output_dir}")
        logger.info(f"📋 Scan summary saved to {summary_file}")
    
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
        
        # First pass: scan main targets with proper threading
        self.progress_tracker.update_status("Main targets", 0, "Starting main target scan...")
        
        # Create all target:port combinations first
        all_combinations = []
        for target in targets:
            # Check kill switch before starting each target
            if self.progress_tracker.should_kill():
                logger.info(f"🛑 Kill switch activated - stopping scan")
                break
                
            ports = self.scan_ports(target)
            for port in ports:
                # Check kill switch before each port
                if self.progress_tracker.should_kill():
                    logger.info(f"🛑 Kill switch activated - stopping scan")
                    break
                    
                combination = f"{target}:{port}"
                if combination in scanned_combinations:
                    self.progress_tracker.increment()
                    continue
                
                scanned_combinations.add(combination)
                all_combinations.append((target, port))
        
        # Process combinations in batches for better control
        max_concurrent = self.config.get('threads', 30)
        batch_size = max_concurrent
        
        for i in range(0, len(all_combinations), batch_size):
            batch = all_combinations[i:i + batch_size]
            
            # Check kill switch before each batch
            if self.progress_tracker.should_kill():
                logger.info(f"🛑 Kill switch activated - stopping scan")
                break
            
            # Create tasks for this batch
            tasks = []
            for target, port in batch:
                task = self.process_target_port(target, port, discovered_subdomains)
                tasks.append(task)
            
            # Execute batch concurrently
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results immediately
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Task failed: {result}")
                    elif result:
                        self.results.append(result)
                        logger.info(f"🌐 Found web service: {result.ip}:{result.port} ({result.protocol}) - {result.title} [{result.service_type}]")
                        
                        # Update HTML report after every discovery for live updates
                        self.generate_live_html_report()
        
        # Check kill switch before subdomain scan
        if self.progress_tracker.should_kill():
            logger.info(f"🛑 Kill switch activated - stopping before subdomain scan")
            return
        
        # Second pass: scan discovered subdomains (avoiding duplicates) with threading
        if self.config.get('recursive_scan', True) and discovered_subdomains and not self.progress_tracker.should_kill():
            subdomain_list = list(discovered_subdomains)
            self.progress_tracker.update_status("Subdomains", 0, f"Starting subdomain scan of {len(subdomain_list)} subdomains...")
            
            # Create all subdomain:port combinations first
            subdomain_combinations = []
            for subdomain in subdomain_list:
                # Check kill switch before each subdomain
                if self.progress_tracker.should_kill():
                    logger.info(f"🛑 Kill switch activated - stopping subdomain scan")
                    break
                    
                ports = self.scan_ports(subdomain)
                for port in ports:
                    # Check kill switch before each port
                    if self.progress_tracker.should_kill():
                        logger.info(f"🛑 Kill switch activated - stopping subdomain scan")
                        break
                        
                    combination = f"{subdomain}:{port}"
                    if combination in scanned_combinations:
                        self.progress_tracker.increment()
                        continue
                    
                    scanned_combinations.add(combination)
                    subdomain_combinations.append((subdomain, port))
            
            # Process subdomain combinations in batches
            for i in range(0, len(subdomain_combinations), batch_size):
                batch = subdomain_combinations[i:i + batch_size]
                
                # Check kill switch before each batch
                if self.progress_tracker.should_kill():
                    logger.info(f"🛑 Kill switch activated - stopping subdomain scan")
                    break
                
                # Create tasks for this batch
                subdomain_tasks = []
                for subdomain, port in batch:
                    task = self.process_subdomain_port(subdomain, port)
                    subdomain_tasks.append(task)
                
                # Execute batch concurrently
                if subdomain_tasks:
                    subdomain_results = await asyncio.gather(*subdomain_tasks, return_exceptions=True)
                    
                    # Process subdomain results immediately
                    for result in subdomain_results:
                        if isinstance(result, Exception):
                            logger.error(f"Subdomain task failed: {result}")
                        elif result:
                            # Mark as subdomain service
                            result.is_subdomain = True
                            result.original_target = result.ip
                            self.results.append(result)
                            logger.info(f"🔗 Found subdomain service: {result.ip}:{result.port} ({result.protocol}) - {result.title} [{result.service_type}]")
                            
                            # Update HTML report after every discovery for live updates
                            self.generate_live_html_report()
        
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
        print(f"{Fore.YELLOW}📋 Scan Summary: {self.output_dir}/scan_summary.txt{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}📸 Screenshots: {self.output_dir}/screenshots/{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}📁 Organized output directory: {self.output_dir}{Style.RESET_ALL}")
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
    
    async def process_target_port(self, target: str, port: int, discovered_subdomains: set):
        """Process a single target:port combination"""
        try:
            self.progress_tracker.update_status(target, port, "Checking service...")
            
            # Check if user wants to skip
            if self.progress_tracker.should_skip():
                logger.info(f"⏭️ Skipped {target}:{port}")
                self.progress_tracker.increment()
                return None
            
            result = await self.check_web_service(target, port)
            if result:
                # Collect subdomains for recursive scanning (avoid duplicates)
                if self.config.get('recursive_scan', True):
                    for subdomain in result.subdomains:
                        if subdomain not in discovered_subdomains and subdomain != target:
                            discovered_subdomains.add(subdomain)
                
                self.progress_tracker.increment()
                return result
            else:
                self.progress_tracker.increment()
                return None
                
        except Exception as e:
            logger.error(f"Error processing {target}:{port} - {e}")
            self.progress_tracker.increment()
            return None
    
    async def process_subdomain_port(self, subdomain: str, port: int):
        """Process a single subdomain:port combination"""
        try:
            self.progress_tracker.update_status(subdomain, port, "Checking subdomain service...")
            
            # Check if user wants to skip
            if self.progress_tracker.should_skip():
                logger.info(f"⏭️ Skipped subdomain {subdomain}:{port}")
                self.progress_tracker.increment()
                return None
            
            result = await self.check_web_service(subdomain, port)
            if result:
                self.progress_tracker.increment()
                return result
            else:
                self.progress_tracker.increment()
                return None
                
        except Exception as e:
            logger.error(f"Error processing subdomain {subdomain}:{port} - {e}")
            self.progress_tracker.increment()
            return None


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
    
    # Add scan scope to config for organized output
    if args.input:
        # Extract scope from input (e.g., "10.130.234.0/24" -> "10.130.234.0_24")
        scope = args.input.replace('/', '_').replace(':', '_').replace('.', '_')
        config['scan_scope'] = scope
    elif args.input_file:
        # Use filename as scope
        scope = Path(args.input_file).stem
        config['scan_scope'] = scope
    else:
        config['scan_scope'] = 'unknown'
    
    scanner = WebDiscoveryScanner(config)
    targets = scanner.parse_input(input_source, input_type)
    
    if not targets:
        logger.error("No valid targets found")
        sys.exit(1)
    
    asyncio.run(scanner.run_scan(targets))

if __name__ == "__main__":
    main() 