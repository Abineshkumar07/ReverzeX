import r2pipe
import sys
import os
import contextlib
import hashlib
import requests
from datetime import datetime

class ThreatIntelligence:
    def __init__(self, api_keys):
        self.virustotal_api_key = api_keys["virustotal"]

    def query_virustotal(self, file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": self.virustotal_api_key
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error querying VirusTotal: {response.status_code} {response.text}")
            return None

class ReverzeX:
    def __init__(self, api_keys):
        self.file_path = None
        self.r2 = None
        self.threat_intelligence = ThreatIntelligence(api_keys)

    def start(self):
        green = '\033[92m'
        reset = '\033[0m'
        
        self.print_banner()
        print("ReverzeX - Malware Reverse Engineering Tool")
        
        sys.stdout.write(green)

        while True:
            try:
                command = input("ReverzeX> ").strip().split()
                if not command:
                    continue
                cmd = command[0]
                args = command[1:]
                if cmd == 'open':
                    self.open_file(args)
                elif cmd == 'analyze':
                    self.analyze_file()
                elif cmd == 'info':
                    self.file_info()
                elif cmd == 'strings':
                    self.strings()
                elif cmd == 'functions':
                    self.functions()
                elif cmd == 'threatscore':
                    self.threat_score()
                elif cmd == 'activesummary':
                    self.active_summary()
                elif cmd == 'history':
                    self.history()
                elif cmd == 'basicproperties':
                    self.basic_properties()
                elif cmd == 'help':
                    self.print_help()
                elif cmd == 'quit':
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
    open <file_path>        - Open a binary file
    analyze                 - Analyze the opened file
    info                    - Display information about the file
    strings                 - List strings found in the file
    functions               - List functions found in the file
    threatscore             - Calculate and display threat score
    activesummary           - Display the last analysis stats
    history                 - Display file history including creation time, last analysis, and first submission
    basicproperties         - Display basic properties of the file
    quit                    - Exit the tool
    help                    - Display this help message
"""
        print(help_text)

    def open_file(self, args):
        if len(args) != 1:
            print("Usage: open <file_path>")
            return
        self.file_path = args[0]
        try:
            with open(self.file_path, 'rb') as file:
                file.read()
                self.r2 = r2pipe.open(self.file_path)
                print(f"Opened file: {self.file_path}")
        except FileNotFoundError:
            print(f"Error: The file '{self.file_path}' was not found.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")

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
            assembly_code = self.r2.cmd('pd 100')
            print(f"Analysis result:\n{assembly_code}")
        except Exception as e:
            print(f"An error occurred during analysis: {str(e)}")

    def file_info(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return
        try:
            info = self.r2.cmdj('ij')
            print(f"File info:\n{info}")
        except Exception as e:
            print(f"An error occurred while fetching file info: {str(e)}")

    def strings(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return
        try:
            strings = self.r2.cmd('iz')
            print(f"Strings found:\n{strings}")
        except Exception as e:
            print(f"An error occurred while fetching strings: {str(e)}")

    def functions(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return
        try:
            functions = self.r2.cmd('afl')
            print(f"Functions found:\n{functions}")
        except Exception as e:
            print(f"An error occurred while fetching functions: {str(e)}")

    def threat_score(self):
        if not self.file_path:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            # Compute the file hash
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            # Query VirusTotal for threat score
            vt_results = self.threat_intelligence.query_virustotal(sha256_hash)
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
                    vt_threat_score = (malicious + suspicious) / total_scans * 100
                else:
                    vt_threat_score = None
            else:
                vt_threat_score = None

            if vt_threat_score is not None:
                if vt_threat_score > 66:
                    vt_risk_level = "High Risk"
                elif vt_threat_score > 33:
                    vt_risk_level = "Medium Risk"
                else:
                    vt_risk_level = "Low Risk"
                print(f"Threat Score: {vt_threat_score:.2f} out of 100 ({vt_risk_level})")
            else:
                print("Threat score could not be determined.")

        except Exception as e:
            print(f"An error occurred while fetching the threat score: {str(e)}")

    def active_summary(self):
        if not self.file_path:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            # Compute the file hash
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            # Query VirusTotal for active summary
            vt_results = self.threat_intelligence.query_virustotal(sha256_hash)
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

        except Exception as e:
            print(f"An error occurred while fetching the active summary: {str(e)}")

    def history(self):
        if not self.file_path:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            # Compute the file hash
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            # Query VirusTotal for history
            vt_results = self.threat_intelligence.query_virustotal(sha256_hash)
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

        except Exception as e:
            print(f"An error occurred while fetching the history: {str(e)}")

    def basic_properties(self):
        if not self.file_path:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return

        try:
            # Compute the file hash
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            # Query VirusTotal for basic properties
            vt_results = self.threat_intelligence.query_virustotal(sha256_hash)
            if vt_results:
                vt_data = vt_results.get('data', {})
                vt_attributes = vt_data.get('attributes', {})
                vt_properties = {
                    "md5": vt_attributes.get('md5', 'N/A'),
                    "sha1": vt_attributes.get('sha1', 'N/A'),
                    "sha256": vt_attributes.get('sha256', 'N/A'),
                    "size": vt_attributes.get('size', 'N/A'),
                    "type_description": vt_attributes.get('type_description', 'N/A'),
                    "magic": vt_attributes.get('magic', 'N/A'),
                    "first_submission_date": datetime.utcfromtimestamp(vt_attributes.get('first_submission_date', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                }
                print("Basic Properties:")
                for key, value in vt_properties.items():
                    print(f"  {key}: {value}")

        except Exception as e:
            print(f"An error occurred while fetching the basic properties: {str(e)}")

if __name__ == '__main__':
    api_keys = {
        "virustotal": "dc8e63c9afd662789c40128eb0f5bc1cc0c93bd7b55713b046bc8f0df844a2ba",
    }
    ReverzeX(api_keys).start()
