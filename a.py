import r2pipe
import sys
import os
import hashlib
import requests
from datetime import datetime
import logging
import contextlib

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

        # Prompt user for file name
        self.file_path = input("Enter file path: ").strip()
        self.open_file([self.file_path])

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
                    self.patterns()
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
| |_/ /_____   _____ _ __ _______ \ V / 
|    // _ \ \ / / _ \ '__|_  / _ \/   \ 
| |\ \  __/\ V /  __/ |   / /  __/ /^\ \\
\_| \_\___| \_/ \___|_|  /___\___\/   \/
                                                                                
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
    8 - Pattern                 - Search for patterns in the file
    h - Help                    - Display this help message
    q - Quit                    - Exit the tool
"""
        print(help_text)

    def open_file(self, args):
        if not self.file_path or not os.path.isfile(self.file_path):
            print(f"Error: The file '{self.file_path}' was not found.")
            return
        try:
            with open(self.file_path, 'rb') as file:
                file.read()
                self.r2 = r2pipe.open(self.file_path)
                print(f"Opened file: {self.file_path}")
                logging.info(f"Opened file: {self.file_path}")
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            logging.error(f"An error occurred: {str(e)}")

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

    def patterns(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            patterns_list = [
                {"description": "Virus-like code patterns", "pattern": "virus"},
                {"description": "Trojan-like behavior patterns", "pattern": "trojan"},
                {"description": "Backdoor patterns", "pattern": "backdoor"},
                {"description": "Suspicious API calls", "pattern": "CreateRemoteThread"},
                {"description": "Executable code sections", "pattern": ".text"},
                {"description": "Network communication patterns", "pattern": "connect"},
                {"description": "Encrypted strings", "pattern": "xor"},
                {"description": "Anti-debugging techniques", "pattern": "IsDebuggerPresent"}
            ]

            print("Available patterns:")
            for i, pattern in enumerate(patterns_list, start=1):
                print(f"{i}: {pattern['description']}")

            pattern_number = input("Enter the pattern number to search for: ").strip()

            if pattern_number.isdigit():
                pattern_number = int(pattern_number)
                if 1 <= pattern_number <= len(patterns_list):
                    pattern = patterns_list[pattern_number - 1]
                    print(f"Searching for pattern: {pattern['description']} (Pattern: {pattern['pattern']})")

                    search_command = f"/j {pattern['pattern']}"
                    pattern_search_result = self.r2.cmdj(search_command)
                    if pattern_search_result:  # Check if the result is not empty
                        print(f"Pattern search result: {pattern_search_result}")
                    else:
                        print(f"No matches found for the selected pattern: '{pattern['pattern']}'.")
                    logging.info(f"Pattern search command: {search_command} Result: {pattern_search_result}")
                else:
                    print("Invalid pattern number.")
            else:
                print("Please enter a valid number.")
        except Exception as e:
            print(f"An error occurred during pattern search: {str(e)}")
            logging.error(f"An error occurred during pattern search: {str(e)}")

if __name__ == "__main__":
    tool = ReverzeX()
    tool.start()
