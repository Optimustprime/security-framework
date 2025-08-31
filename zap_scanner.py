import requests
import time
import logging
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

class ZAPScanner:
    """
    A class to manage OWASP ZAP security scanning operations.

    This class provides an interface to interact with a ZAP instance running in a Docker container,
    allowing for automated security scanning of web applications through both passive and active scans.

    Attributes:
        target_url (str): The URL of the web application to be scanned
        api_key (str): The API key for authenticating with ZAP
        zap_host (str): The hostname where ZAP is running
        zap_port (str): The port number where ZAP is listening
        zap_base_url (str): The complete base URL for the ZAP API
        session (requests.Session): HTTP session with retry configuration
    """

    def __init__(self, target_url, api_key=None, scan_mode='light'):
        """
        Initialize the ZAP scanner with target URL and configuration.

        Args:
            target_url (str): The URL of the web application to scan
            api_key (str, optional): The API key for ZAP authentication. Defaults to None.
            scan_mode (str, optional): Scan intensity mode ('light', 'medium', 'full'). Defaults to 'light'.
        """
        self.target_url = target_url
        # Use the fixed API key from docker-compose or environment
        self.api_key = api_key or "zap-api-key-12345"
        # Get ZAP host and port from environment variables
        self.zap_host = os.environ.get('ZAP_HOST', 'localhost')
        self.zap_port = os.environ.get('ZAP_PORT', '8080')
        self.zap_base_url = f'http://{self.zap_host}:{self.zap_port}'
        self.scan_mode = scan_mode

        # Initialize stop flag
        self.should_stop = False
        self.spider_id = None
        self.active_scan_id = None

        # Create a session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def start_zap_container(self):
        """Check if ZAP is ready, disable browser-dependent scanners, and configure scan mode."""
        try:
            logger.info(f"Checking ZAP readiness at {self.zap_base_url}")
            self._wait_for_zap_ready()
            
            # Disable browser-dependent scanners after ZAP is ready
            self._disable_browser_scanners()
            
            # Configure scan mode
            self._configure_scan_mode()

            logger.info(f"ZAP is ready for {self.scan_mode} scanning (browser scanners disabled)")
        except Exception as e:
            logger.error(f"ZAP is not available: {e}")
            raise Exception("ZAP service is not available. Please ensure docker-compose is running.")

    def _wait_for_zap_ready(self, max_wait=60):
        """
        Wait for the ZAP service to become available and ready for API calls.

        Args:
            max_wait (int, optional): Maximum time to wait in seconds. Defaults to 60.

        Raises:
            Exception: If ZAP service doesn't respond within the max_wait time.
        """
        wait_time = 0
        logger.info(f"Waiting for ZAP to be ready at {self.zap_base_url} (max {max_wait}s)...")

        while wait_time < max_wait:
            try:
                logger.info(f"Attempting to connect to ZAP (attempt {wait_time//5 + 1})")
                response = self.session.get(
                    f'{self.zap_base_url}/JSON/core/view/version/',
                    params={'apikey': self.api_key},
                    timeout=10
                )
                if response.status_code == 200:
                    version_info = response.json()
                    logger.info(f"ZAP is ready! Version: {version_info.get('version', 'Unknown')}")
                    return
                else:
                    logger.warning(f"ZAP responded with status {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.info(f"ZAP not ready yet: {e}")

            time.sleep(5)
            wait_time += 5
            logger.info(f"Waiting for ZAP to be ready... ({wait_time}s/{max_wait}s)")

        logger.error(f"ZAP service failed to respond within {max_wait} seconds.")
        raise Exception(f"ZAP service failed to respond within the expected time of {max_wait} seconds.")

    def _disable_browser_scanners(self):
        """
        Explicitly disable all browser-dependent scanners via ZAP API.
        
        This method ensures that scanners requiring browser automation are disabled
        to prevent startup failures in containerized environments without GUI support.
        """
        try:
            logger.info("Disabling browser-dependent scanners...")
            
            # List of browser-dependent scanners to disable
            browser_scanners = [
                'domxss',
                'ajaxSpider', 
                'selenium',
                'spiderAjax'
            ]
            
            for scanner in browser_scanners:
                try:
                    # Disable via API configuration
                    disable_url = f'{self.zap_base_url}/JSON/core/action/setOptionDefaultUserAgent/'
                    response = self.session.get(disable_url, params={
                        'String': 'ZAP-Headless-Scanner',
                        'apikey': self.api_key
                    })
                    
                    # Additional specific disables for each scanner type
                    if scanner == 'domxss':
                        config_url = f'{self.zap_base_url}/JSON/core/action/setOptionSingleCookieRequestHeader/'
                        self.session.get(config_url, params={
                            'Boolean': 'false',
                            'apikey': self.api_key
                        })
                    
                    logger.info(f"Successfully configured scanner: {scanner}")
                    
                except Exception as e:
                    logger.warning(f"Could not disable {scanner}: {e}")
            
            # Set headless mode explicitly
            try:
                headless_url = f'{self.zap_base_url}/JSON/core/action/setOptionDefaultUserAgent/'
                self.session.get(headless_url, params={
                    'String': 'ZAP-Headless-Mode/1.0',
                    'apikey': self.api_key
                })
                logger.info("Set ZAP to headless mode")
            except Exception as e:
                logger.warning(f"Could not set headless mode: {e}")
                
            logger.info("Browser-dependent scanners disabled successfully")
            
        except Exception as e:
            logger.warning(f"Error disabling browser scanners: {e}")
            # Don't fail the scan if we can't disable scanners - they should be disabled by config

    def _configure_scan_mode(self):
        """
        Configure ZAP scanning parameters based on the selected scan mode.

        Light mode: Ultra-fast, minimal scope scanning (2-5 minutes)
        Medium mode: Balanced scanning with moderate coverage
        Full mode: Comprehensive scanning (default ZAP behavior)
        """
        try:
            logger.info(f"Configuring ZAP for {self.scan_mode} scan mode...")

            if self.scan_mode == 'light':
                # Ultra-fast light scan configuration
                config_params = {
                    # Spider configuration for ultra-fast scanning
                    'spider.maxDepth': '1',  # Only scan 1 level deep
                    'spider.maxChildren': '3',  # Maximum 3 links per page
                    'spider.maxDuration': '45',  # 45 seconds max spider time
                    'spider.threadCount': '1',
                    'spider.parseComments': 'false',
                    'spider.parseRobotsTxt': 'false',
                    'spider.parseSitemapXml': 'false',
                    'spider.handleODataParametersVisited': 'false',

                    # Active scan configuration for ultra-fast scanning
                    'scanner.strength': 'LOW',
                    'scanner.threadPerHost': '1',
                    'scanner.delayInMs': '100',  # Minimal delay
                    'scanner.maxResultsToList': '5',
                    'scanner.maxRuleDurationInMins': '0.5',  # 30 seconds per rule max
                    'scanner.maxScanDurationInMins': '2',  # 2 minutes total active scan
                    'ascan.maxAlertsPerRule': '2',  # Stop after 2 alerts per rule

                    # Disable time-consuming features
                    'scanner.attackOnStart': 'false',
                    'scanner.hostPerScan': '1',
                }

            elif self.scan_mode == 'medium':
                # Medium scan configuration - balanced approach
                config_params = {
                    'spider.maxDepth': '2',
                    'spider.maxChildren': '10',
                    'spider.maxDuration': '180',  # 3 minutes max
                    'spider.threadCount': '2',

                    'scanner.strength': 'MEDIUM',
                    'scanner.threadPerHost': '2',
                    'scanner.delayInMs': '300',
                    'scanner.maxResultsToList': '25',
                    'scanner.maxRuleDurationInMins': '2',
                    'scanner.maxScanDurationInMins': '8',
                }

            else:  # full mode
                # Full scan configuration - comprehensive scanning
                config_params = {
                    'spider.maxDepth': '3',
                    'spider.maxChildren': '30',
                    'spider.maxDuration': '600',  # 10 minutes max
                    'spider.threadCount': '3',

                    'scanner.strength': 'HIGH',
                    'scanner.threadPerHost': '3',
                    'scanner.delayInMs': '200',
                    'scanner.maxResultsToList': '100',
                    'scanner.maxRuleDurationInMins': '5',
                    'scanner.maxScanDurationInMins': '20',
                }

            # Apply configuration via proper ZAP API calls
            for param, value in config_params.items():
                try:
                    # Use the appropriate API endpoint for different parameter types
                    if param.startswith('spider.'):
                        config_url = f'{self.zap_base_url}/JSON/spider/action/setOptionMaxDepth/' if 'maxDepth' in param else \
                                   f'{self.zap_base_url}/JSON/spider/action/setOptionMaxChildren/' if 'maxChildren' in param else \
                                   f'{self.zap_base_url}/JSON/spider/action/setOptionMaxDuration/' if 'maxDuration' in param else \
                                   f'{self.zap_base_url}/JSON/spider/action/setOptionThreadCount/' if 'threadCount' in param else \
                                   f'{self.zap_base_url}/JSON/core/action/setOptionDefaultUserAgent/'

                        if 'maxDepth' in param:
                            self.session.get(f'{self.zap_base_url}/JSON/spider/action/setOptionMaxDepth/',
                                           params={'Integer': value, 'apikey': self.api_key})
                        elif 'maxChildren' in param:
                            self.session.get(f'{self.zap_base_url}/JSON/spider/action/setOptionMaxChildren/',
                                           params={'Integer': value, 'apikey': self.api_key})
                        elif 'maxDuration' in param:
                            self.session.get(f'{self.zap_base_url}/JSON/spider/action/setOptionMaxDuration/',
                                           params={'Integer': value, 'apikey': self.api_key})
                        elif 'threadCount' in param:
                            self.session.get(f'{self.zap_base_url}/JSON/spider/action/setOptionThreadCount/',
                                           params={'Integer': value, 'apikey': self.api_key})

                    logger.debug(f"Set {param} = {value}")
                except Exception as e:
                    logger.warning(f"Could not set {param}: {e}")

            logger.info(f"ZAP configured for {self.scan_mode} scan mode")

        except Exception as e:
            logger.warning(f"Error configuring scan mode: {e}")
            # Don't fail the scan if configuration fails

    def run_passive_scan(self):
        """
        Execute a passive scan using ZAP's spider functionality.

        This method initiates a spider scan of the target URL, which crawls the web application
        and passively collects security-relevant information without actively testing for vulnerabilities.

        Raises:
            Exception: If the spider scan fails to start or complete.
        """
        try:
            logger.info("Starting passive scan (spider)...")

            # Start spider scan
            spider_url = f'{self.zap_base_url}/JSON/spider/action/scan/'
            response = self.session.get(spider_url, params={
                'url': self.target_url,
                'apikey': self.api_key
            })

            if response.status_code != 200:
                raise Exception(f"Failed to start spider: {response.text}")

            self.spider_id = response.json()['scan']
            logger.info(f"Spider started with ID: {self.spider_id}")

            # Poll for spider completion with stop check
            while True:
                # Check if scan should be stopped
                if hasattr(self, 'should_stop') and self.should_stop:
                    logger.info("Stopping spider scan due to user request")
                    # Stop the spider
                    stop_url = f'{self.zap_base_url}/JSON/spider/action/stop/'
                    self.session.get(stop_url, params={
                        'scanId': self.spider_id,
                        'apikey': self.api_key
                    })
                    raise Exception("Scan stopped by user")

                status_url = f'{self.zap_base_url}/JSON/spider/view/status/'
                response = self.session.get(status_url, params={
                    'scanId': self.spider_id,
                    'apikey': self.api_key
                })

                if response.status_code == 200:
                    status = int(response.json()['status'])
                    logger.info(f"Spider progress: {status}%")
                    if status >= 100:
                        break

                time.sleep(5)

            logger.info("Passive scan complete.")

        except Exception as e:
            logger.error(f"Error during passive scan: {e}")
            raise

    def run_active_scan(self):
        """
        Execute an active scan against the target URL.

        This method performs active security testing by sending potentially malicious requests
        to the target application to identify security vulnerabilities. It monitors the scan
        progress and provides detailed logging of the scanning process.

        Raises:
            Exception: If the active scan fails to start or complete.
        """
        try:
            logger.info("Starting active scan...")

            # Start active scan
            ascan_url = f'{self.zap_base_url}/JSON/ascan/action/scan/'
            response = self.session.get(ascan_url, params={
                'url': self.target_url,
                'apikey': self.api_key
            })

            if response.status_code != 200:
                raise Exception(f"Failed to start active scan: {response.text}")

            self.active_scan_id = response.json()['scan']
            logger.info(f"Active scan started with ID: {self.active_scan_id}")

            # Poll for active scan completion with enhanced status reporting and stop check
            last_status = -1
            last_rule = None
            while True:
                # Check if scan should be stopped
                if hasattr(self, 'should_stop') and self.should_stop:
                    logger.info("Stopping active scan due to user request")
                    # Stop the active scan
                    stop_url = f'{self.zap_base_url}/JSON/ascan/action/stop/'
                    self.session.get(stop_url, params={
                        'scanId': self.active_scan_id,
                        'apikey': self.api_key
                    })
                    raise Exception("Scan stopped by user")

                status_url = f'{self.zap_base_url}/JSON/ascan/view/status/'
                response = self.session.get(status_url, params={
                    'scanId': self.active_scan_id,
                    'apikey': self.api_key
                })

                if response.status_code == 200:
                    status = int(response.json()['status'])

                    # Get current scanning rule and phase
                    current_rule = None
                    try:
                        rules_url = f'{self.zap_base_url}/JSON/ascan/view/scanProgress/'
                        rules_response = self.session.get(rules_url, params={
                            'scanId': self.active_scan_id,
                            'apikey': self.api_key
                        })
                        if rules_response.status_code == 200:
                            progress_data = rules_response.json()
                            if 'scanProgress' in progress_data and progress_data['scanProgress']:
                                host_progress = progress_data['scanProgress'][-1]['HostProcess']
                                if host_progress:
                                    plugin_data = host_progress[-1]['plugin']
                                    current_rule = plugin_data['name']
                                    if current_rule != last_rule:
                                        status_msg = f"Currently scanning with rule: {current_rule}"
                                        logger.info(status_msg)
                                        last_rule = current_rule
                    except Exception as e:
                        logger.debug(f"Could not get detailed scan progress: {e}")

                    # Only log if progress has changed or we have a new rule
                    if status != last_status:
                        progress_msg = f"Active scan progress: {status}%"
                        if current_rule:
                            progress_msg += f" (Current rule: {current_rule})"
                        logger.info(progress_msg)
                        last_status = status

                    if status >= 100:
                        logger.info("Active scan phase complete")
                        break

                time.sleep(2)  # Reduced polling interval for more responsive updates

            logger.info("Active scan complete.")

        except Exception as e:
            logger.error(f"Error during active scan: {e}")
            raise

    def get_results(self):
        """
        Retrieve the security scan results from ZAP.

        Returns:
            list: A list of dictionaries containing alert details. Each dictionary represents
                  a security finding with information about the vulnerability type, risk level,
                  and affected URL.

        Raises:
            Exception: If unable to retrieve results from the ZAP API.
        """
        try:
            logger.info("Retrieving scan results...")

            alerts_url = f'{self.zap_base_url}/JSON/core/view/alerts/'
            response = self.session.get(alerts_url, params={
                'baseurl': self.target_url,
                'apikey': self.api_key
            })

            if response.status_code == 200:
                results = response.json()['alerts']
                logger.info(f"Retrieved {len(results)} alerts from scan.")
                return results
            else:
                raise Exception(f"Failed to get results: {response.text}")

        except Exception as e:
            logger.error(f"Error retrieving results: {e}")
            return []

    def stop_zap_container(self):
        """
        Clean up the ZAP session after scanning.

        This method creates a new session in ZAP to clear any existing session data,
        ensuring a clean state for subsequent scans. The actual ZAP container is managed
        by docker-compose and is not stopped by this method.
        """
        try:
            logger.info("Cleaning up scan session...")
            # Clear ZAP session data for next scan
            clear_url = f'{self.zap_base_url}/JSON/core/action/newSession/'
            response = self.session.get(clear_url, params={
                'name': f'session_{int(time.time())}',
                'apikey': self.api_key
            })
            if response.status_code == 200:
                logger.info("ZAP session cleared successfully")
            else:
                logger.warning(f"Failed to clear ZAP session: {response.status_code}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def stop_scan(self):
        """
        Stop the current scan by setting the should_stop flag and stopping active ZAP scans.
        """
        try:
            self.should_stop = True
            logger.info("Stop signal sent to scanner")

            # Stop any active spider scans
            if self.spider_id:
                try:
                    stop_url = f'{self.zap_base_url}/JSON/spider/action/stop/'
                    response = self.session.get(stop_url, params={
                        'scanId': self.spider_id,
                        'apikey': self.api_key
                    })
                    if response.status_code == 200:
                        logger.info(f"Spider scan {self.spider_id} stopped successfully")
                    else:
                        logger.warning(f"Failed to stop spider scan: {response.status_code}")
                except Exception as e:
                    logger.error(f"Error stopping spider scan: {e}")

            # Stop any active security scans
            if self.active_scan_id:
                try:
                    stop_url = f'{self.zap_base_url}/JSON/ascan/action/stop/'
                    response = self.session.get(stop_url, params={
                        'scanId': self.active_scan_id,
                        'apikey': self.api_key
                    })
                    if response.status_code == 200:
                        logger.info(f"Active scan {self.active_scan_id} stopped successfully")
                    else:
                        logger.warning(f"Failed to stop active scan: {response.status_code}")
                except Exception as e:
                    logger.error(f"Error stopping active scan: {e}")

            # Stop all scans as a fallback
            try:
                stop_all_url = f'{self.zap_base_url}/JSON/ascan/action/stopAllScans/'
                self.session.get(stop_all_url, params={'apikey': self.api_key})
                logger.info("Sent stop signal to all active scans")
            except Exception as e:
                logger.error(f"Error stopping all scans: {e}")

        except Exception as e:
            logger.error(f"Error in stop_scan: {e}")
            self.should_stop = True  # Ensure flag is set even if API calls fail

# Example Usage:
if __name__ == '__main__':
    TARGET = 'http://testphp.vulnweb.com'

    scanner = ZAPScanner(target_url=TARGET)
    try:
        scanner.start_zap_container()
        scanner.run_passive_scan()
        scanner.run_active_scan()
        results = scanner.get_results()
        print(f"Found {len(results)} vulnerabilities.")
    except Exception as e:
        print(f"Scan failed: {e}")
    finally:
        scanner.stop_zap_container()
