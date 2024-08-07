import r2pipe
import sys
import os
import hashlib
import requests
from datetime import datetime
import logging
import contextlib
import pyshark

class ThreatIntelligence:
    def __init__(self):
        self.api_key = "dc8e63c9afd662789c40128eb0f5bc1cc0c93bd7b55713b046bc8f0df844a2ba"
        if not self.api_key:
            raise ValueError("API key is missing.")

    def query_service(self, file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": self.api_key
        }
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print(f"File '{file_hash}' not found in Threat Intelligence Service.")
                logging.warning(f"File '{file_hash}' not found in Threat Intelligence Service.")
                return None
            else:
                print(f"Error querying Threat Intelligence Service: {response.status_code} {response.text}")
                logging.error(f"Error querying Threat Intelligence Service: {response.status_code} {response.text}")
                return None
        except requests.RequestException as e:
            print(f"An error occurred: {e}")
            logging.error(f"An error occurred: {e}")
            return None

class ReverzeX:
    def __init__(self):
        self.file_path = None
        self.r2 = None
        self.threat_intelligence = ThreatIntelligence()
        logging.basicConfig(filename='reverzex.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def start(self):
        green = '\033[92m'
        reset = '\033[0m'
        
        self.print_banner()
        print("ReverzeX - Malware Reverse Engineering Tool")

        self.print_help()

        sys.stdout.write(green)

        # Loop until a valid file is opened
        while True:
            self.file_path = input("Enter file path: ").strip()
            if self.open_file():
                break
            else:
                print(f"Error: The file '{self.file_path}' was not found. Please try again.")
        
        while True:
            try:
                command = input("ReverzeX> ").strip().split()
                if not command:
                    continue
                cmd = command[0]
                args = command[1:]
                if cmd == '1':
                    self.analyze_file()
                elif cmd == '2':
                    self.strings()
                elif cmd == '3':
                    self.functions()
                elif cmd == '4':
                    self.threat_score()
                elif cmd == '5':
                    self.active_summary()
                elif cmd == '6':
                    self.history()
                elif cmd == '7':
                    self.basic_properties()
                elif cmd == '8':
                    self.network_capture()
                elif cmd == '9':
                    self.threat_categories()
                elif cmd == 'h':
                    self.print_help()
                elif cmd == 'q':
                    print("Quitting ReverzeX...")
                    break
                else:
                    print(f"Unknown command: {cmd}")
            except (EOFError, KeyboardInterrupt):
                print("\nQuitting ReverzeX...")
                break
        
        sys.stdout.write(reset)

    def print_banner(self):
        green = '\033[92m'
        reset = '\033[0m'
        
        banner = f"""
{green}

______                           __   __
| ___ \                          \ \ / /
| |/ /____   _____ _ __ _______ \ V / 
|    // _ \ \ / / _ \ '|_  / _ \/   \ 
| |\ \  __/\ V /  __/ |   / /  __/ /^\ \\
\| \\| \/ \||  /\\/   \/
                                                                                
{reset}
        """
        print(banner)

    def print_help(self):
        help_text = """
Available commands:
    1 - Analyze                 - Analyze the opened file
    2 - Strings                 - List strings found in the file
    3 - Functions               - List functions found in the file
    4 - Threat Score            - Calculate and display threat score
    5 - Active Summary          - Display the last analysis stats
    6 - History                 - Display file history including creation time, last analysis, and first submission
    7 - Basic Properties        - Display basic properties of the file
    8 - Start Network Capture   - Start a network capture session 
    9 - Threat Categories       - Display threat categories
    h - Help                    - Display this help message
    q - Quit                    - Exit the tool
"""
        print(help_text)

    def open_file(self):
        if not self.file_path or not os.path.isfile(self.file_path):
            return False
        try:
            with open(self.file_path, 'rb') as file:
                file.read()
                self.r2 = r2pipe.open(self.file_path)
                print(f"Opened file: {self.file_path}")
                logging.info(f"Opened file: {self.file_path}")
                return True
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            logging.error(f"An error occurred: {str(e)}")
            return False

    @contextlib.contextmanager
    def suppress_output(self):
        with open(os.devnull, 'w') as devnull:
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = devnull
            sys.stderr = devnull
            try:
                yield
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

    def analyze_file(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return
        try:
            with self.suppress_output():
                self.r2.cmd('aaa')
            disassembly = self.r2.cmdj('pdj 100')

            print(f";-- eip:")
            print(f"┌ 378: entry0 (uint32_t arg_24h);")

            for instr in disassembly:
                addr = instr.get('offset', 'unknown')
                asm = instr.get('opcode', 'unknown')
                print(f"│           0x{addr:08x}      {asm:<15}")
                logging.info(f"Disassembled instruction at 0x{addr:08x}: {asm}")
        except Exception as e:
            print(f"An error occurred during analysis: {str(e)}")
            logging.error(f"An error occurred during analysis: {str(e)}")

    def file_info(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return
        try:
            info = self.r2.cmdj('ij')
            print(f"File info:\n{info}")
            logging.info(f"File info: {info}")
        except Exception as e:
            print(f"An error occurred while fetching file info: {str(e)}")
            logging.error(f"An error occurred while fetching file info: {str(e)}")

    def strings(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return
        try:
            strings = self.r2.cmd('iz')
            print(f"Strings found:\n{strings}")
            logging.info(f"Strings found: {strings}")
        except Exception as e:
            print(f"An error occurred while fetching strings: {str(e)}")
            logging.error(f"An error occurred while fetching strings: {str(e)}")

    def functions(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return
        try:
            functions = self.r2.cmd('afl')
            print(f"Functions found:\n{functions}")
            logging.info(f"Functions found: {functions}")
        except Exception as e:
            print(f"An error occurred while fetching functions: {str(e)}")
            logging.error(f"An error occurred while fetching functions: {str(e)}")

    def threat_score(self):
        if not self.file_path:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            vt_results = self.threat_intelligence.query_service(sha256_hash)
            if vt_results:
                vt_data = vt_results.get('data', {})
                vt_attributes = vt_data.get('attributes', {})
                last_analysis_stats = vt_attributes.get('last_analysis_stats', {})
                harmless = last_analysis_stats.get('harmless', 0)
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                undetected = last_analysis_stats.get('undetected', 0)
                total_scans = harmless + malicious + suspicious + undetected
                if total_scans > 0:
                    threat_score = (malicious + suspicious) / total_scans * 100
                else:
                    threat_score = None
            else:
                threat_score = None

            if threat_score is not None:
                if threat_score > 66:
                    risk_level = "High Risk"
                elif threat_score > 33:
                    risk_level = "Medium Risk"
                else:
                    risk_level = "Low Risk"
                print(f"Threat Intelligence Service Score: {threat_score:.2f}% - {risk_level}")
                logging.info(f"Threat Intelligence Service Score: {threat_score:.2f}% - {risk_level}")
            else:
                print("Unable to retrieve threat score from Threat Intelligence Service.")
                logging.error("Unable to retrieve threat score from Threat Intelligence Service.")
        except Exception as e:
            print(f"An error occurred during threat score calculation: {str(e)}")
            logging.error(f"An error occurred during threat score calculation: {str(e)}")

    def active_summary(self):
        if not self.file_path:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            vt_results = self.threat_intelligence.query_service(sha256_hash)
            if vt_results:
                vt_data = vt_results.get('data', {})
                vt_attributes = vt_data.get('attributes', {})
                last_analysis_stats = vt_attributes.get('last_analysis_stats', {})
                print("Active Summary:")
                print("Last Analysis Stats:")
                print(f"  Malicious: {last_analysis_stats.get('malicious', 'N/A')}")
                print(f"  Suspicious: {last_analysis_stats.get('suspicious', 'N/A')}")
                print(f"  Undetected: {last_analysis_stats.get('undetected', 'N/A')}")
                print(f"  Harmless: {last_analysis_stats.get('harmless', 'N/A')}")
                print(f"  Timeout: {last_analysis_stats.get('timeout', 'N/A')}")
                print(f"  Confirmed Timeout: {last_analysis_stats.get('confirmed-timeout', 'N/A')}")
                print(f"  Failure: {last_analysis_stats.get('failure', 'N/A')}")
                print(f"  Type Unsupported: {last_analysis_stats.get('type-unsupported', 'N/A')}")
            else:
                print("Unable to retrieve active summary from Threat Intelligence Service.")
                logging.error("Unable to retrieve active summary from Threat Intelligence Service.")
        except Exception as e:
            print(f"An error occurred while fetching the active summary: {str(e)}")
            logging.error(f"An error occurred while fetching the active summary: {str(e)}")

    def history(self):
        if not self.file_path:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            vt_results = self.threat_intelligence.query_service(sha256_hash)
            if vt_results:
                vt_data = vt_results.get('data', {})
                vt_attributes = vt_data.get('attributes', {})
                creation_date = datetime.utcfromtimestamp(vt_attributes.get('creation_date', 0)).strftime('%Y-%m-%d %H:%M:%S')
                last_analysis_date = datetime.utcfromtimestamp(vt_attributes.get('last_analysis_date', 0)).strftime('%Y-%m-%d %H:%M:%S')
                first_submission_date = datetime.utcfromtimestamp(vt_attributes.get('first_submission_date', 0)).strftime('%Y-%m-%d %H:%M:%S')
                print("History:")
                print(f"  Creation Time: {creation_date}")
                print(f"  Last Analysis: {last_analysis_date}")
                print(f"  First Submission: {first_submission_date}")
            else:
                print("Unable to retrieve history from Threat Intelligence Service.")
                logging.error("Unable to retrieve history from Threat Intelligence Service.")
        except Exception as e:
            print(f"An error occurred while fetching the history: {str(e)}")
            logging.error(f"An error occurred while fetching the history: {str(e)}")

    def basic_properties(self):
        if not self.file_path:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                sha256_hash = hashlib.sha256(file_data).hexdigest()
                md5_hash = hashlib.md5(file_data).hexdigest()
                file_size = os.path.getsize(self.file_path)

            vt_results = self.threat_intelligence.query_service(sha256_hash)
            if vt_results:
                vt_data = vt_results.get('data', {})
                vt_attributes = vt_data.get('attributes', {})
                md5 = vt_attributes.get('md5', 'N/A')
                sha1 = vt_attributes.get('sha1', 'N/A')
                sha256 = vt_attributes.get('sha256', 'N/A')
                size = vt_attributes.get('size', 'N/A')
                type_description = vt_attributes.get('type_description', 'N/A')
                magic = vt_attributes.get('magic', 'N/A')
                first_submission_date = datetime.utcfromtimestamp(vt_attributes.get('first_submission_date', 0)).strftime('%Y-%m-%d %H:%M:%S')

                print("Basic Properties:")
                print(f"  File Path: {self.file_path}")
                print(f"  SHA-256: {sha256_hash}")
                print(f"  MD5: {md5_hash}")
                print(f"  File Size: {file_size} bytes")
                print(f"  MD5: {md5}")
                print(f"  SHA-1: {sha1}")
                print(f"  SHA-256: {sha256}")
                print(f"  Size: {size} bytes")
                print(f"  Type Description: {type_description}")
                print(f"  Magic: {magic}")
                print(f"  First Submission Date: {first_submission_date}")

                logging.info("Basic Properties:")
                logging.info(f"  File Path: {self.file_path}")
                logging.info(f"  SHA-256: {sha256_hash}")
                logging.info(f"  MD5: {md5_hash}")
                logging.info(f"  File Size: {file_size} bytes")
                logging.info(f"  MD5: {md5}")
                logging.info(f"  SHA-1: {sha1}")
                logging.info(f"  SHA-256: {sha256}")
                logging.info(f"  Size: {size} bytes")
                logging.info(f"  Type Description: {type_description}")
                logging.info(f"  Magic: {magic}")
                logging.info(f"  First Submission Date: {first_submission_date}")
            else:
                print("Basic properties could not be determined from Threat Intelligence Service.")
                logging.warning("Basic properties could not be determined from Threat Intelligence Service.")
        except Exception as e:
            print(f"An error occurred while fetching basic properties: {str(e)}")
            logging.error(f"An error occurred while fetching basic properties: {str(e)}")

    def network_capture(self):
        capture_duration = 10

        print(f"Starting network capture for {capture_duration} seconds...")
        logging.info(f"Starting network capture for {capture_duration} seconds...")

        try:
            capture = pyshark.LiveCapture(interface='eth0')  # Change 'eth0' to your network interface
            capture.sniff(timeout=capture_duration)
            
            for packet in capture.sniff_continuously(packet_count=5):
                print(packet)
                logging.info(f"Captured packet: {packet}")
        
        except Exception as e:
            print(f"An error occurred while capturing network traffic: {str(e)}")
            logging.error(f"An error occurred while capturing network traffic: {str(e)}")

    def threat_categories(self):
        if not self.file_path:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            vt_results = self.threat_intelligence.query_service(sha256_hash)
            if vt_results:
                vt_data = vt_results.get('data', {})
                vt_attributes = vt_data.get('attributes', {})
                popular_threat_classification = vt_attributes.get('popular_threat_classification', {})
                popular_threat_categories = popular_threat_classification.get('popular_threat_category', [])

                if popular_threat_categories:
                    print(f"Threat Categories:")
                    for category in popular_threat_categories:
                        print(f"- {category.get('value', 'Unknown')}")
                        logging.info(f"Threat Category: {category.get('value', 'Unknown')}")
                else:
                    print("No threat categories available.")
                    logging.info("No threat categories available.")
            else:
                print("Unable to retrieve threat categories. No data available.")
                logging.info("Unable to retrieve threat categories. No data available.")
        except Exception as e:
            print(f"An error occurred while fetching threat categories: {str(e)}")
            logging.error(f"An error occurred while fetching threat categories: {str(e)}")



if __name__ == '__main__':
    try:
        reverzeX = ReverzeX()
        reverzeX.start()
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        logging.critical(f"An unexpected error occurred: {str(e)}")

