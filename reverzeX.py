import r2pipe
import os
import sys
import hashlib
import logging
import json
import contextlib
import pyshark
from datetime import datetime
from fpdf import FPDF
from threat_intelligence import ThreatIntelligence
from utils import print_banner, print_help


class ReverzeX:
    def __init__(self):
        self.file_path = None
        self.r2 = None
        self.threat_intelligence = ThreatIntelligence()
        self.analysis_data = {}

        # Ensure the logs directory exists
        log_dir = 'logs'
        os.makedirs(log_dir, exist_ok=True)

        # Set up logging
        log_file = os.path.join(log_dir, 'reverzex.log')
        logging.basicConfig(filename='logs/reverzex.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def start(self):
        green = '\033[92m'
        red = '\033[91m'
        blue = '\033[94m'
        reset = '\033[0m'
        
        print_banner()
        print(f"{red}ReverzeX - Malware Reverse Engineering Tool{reset}")
        print_help()

        sys.stdout.write(green)

        while True:
            self.file_path = input(f"{blue}Enter file path: {reset}").strip()
            if self.open_file():
                break
            else:
                print(f"Error: The file '{self.file_path}' was not found. Please try again.")
        
        while True:
            try:
                command = input(f"{blue}ReverzeX> {reset}").strip().split()
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
                    self.file_info()
                elif cmd == '5':
                    self.threat_score()
                elif cmd == '6':
                    self.active_summary()
                elif cmd == '7':
                    self.history()
                elif cmd == '8':
                    self.basic_properties()
                elif cmd == '9':
                    self.threat_categories()
                elif cmd == '10':
                    self.network_capture()
                elif cmd == '11':
                    self.auto_network_capture()
                elif cmd == '12':
                    self.generate_pdf_report()
                elif cmd == 'h':
                    print_help()
                elif cmd == 'q':
                    print("Quitting ReverzeX...")
                    break
                else:
                    print(f"Unknown command: {cmd}")
            except (EOFError, KeyboardInterrupt):
                print("\nQuitting ReverzeX...")
                break
        
        sys.stdout.write(reset)

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

            disassembly_str = []
            disassembly_str.append(f";-- eip:\n")
            disassembly_str.append(f"┌ 378: entry0 (uint32_t arg_24h);\n")

            for instr in disassembly:
                addr = instr.get('offset', 'unknown')
                asm = instr.get('opcode', 'unknown')
                disassembly_str.append(f"│           0x{addr:08x}      {asm:<15}\n")
                logging.info(f"Disassembled instruction at 0x{addr:08x}: {asm}")

            disassembly_report = ''.join(disassembly_str)
            self.analysis_data['disassembly'] = disassembly_report

            print(disassembly_report)
        except Exception as e:
            print(f"An error occurred during analysis: {str(e)}")
            logging.error(f"An error occurred during analysis: {str(e)}")

    def file_info(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return
        try:
            info = self.r2.cmdj('ij')
            info_str = json.dumps(info, indent=4)
            self.analysis_data['file_info'] = info_str

            print(f"File info:\n{info_str}")
            logging.info(f"File info: {info_str}")
        except Exception as e:
            print(f"An error occurred while fetching file info: {str(e)}")
            logging.error(f"An error occurred while fetching file info: {str(e)}")

    def strings(self):
        if not self.r2:
            print("No file is currently opened. Use 'open <file_path>' to open a file.")
            return
        try:
            strings = self.r2.cmd('iz')
            self.analysis_data['strings'] = strings

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
            self.analysis_data['functions'] = functions

            print(f"Functions found:\n{functions}")
            logging.info(f"Functions found: {functions}")
        except Exception as e:
            print(f"An error occurred while fetching functions: {str(e)}")
            logging.error(f"An error occurred while fetching functions: {str(e)}")

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

    def auto_network_capture(self):
        interface = input("Enter the network interface for capture (e.g., eth0): ").strip()

        print(f"Starting network capture on {interface}...")
        logging.info(f"Starting network capture on {interface}...")

        capture = pyshark.LiveCapture(interface=interface)

        print("Press Ctrl+C to stop the capture.")
        try:
            capture.sniff(timeout=50)  # Capture packets for 50 seconds
        except KeyboardInterrupt:
            print("Capture stopped.")
            logging.info("Network capture stopped by user.")

        for packet in capture.sniff_continuously(packet_count=5):  # Adjust the packet_count as needed
            try:
                protocol = packet.highest_layer
                source = packet.ip.src
                destination = packet.ip.dst
                print(f"Packet: {protocol} {source} -> {destination}")
                logging.info(f"Packet captured: {protocol} {source} -> {destination}")
            except AttributeError:
                continue
    def network_capture(self):
        capture_duration = 5

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

    def generate_pdf_report(self):
        if not self.analysis_data:
            print("No analysis data available to generate a report.")
            return

        def sanitize_text(text):
            return text.encode('latin-1', 'replace').decode('latin-1')

        try:
            pdf = FPDF()
            pdf.add_page()

            pdf.set_font("Arial", "B", 16)
            pdf.cell(40, 10, "ReverzeX Analysis Report")
            pdf.ln(20)

            for key, value in self.analysis_data.items():
                pdf.set_font("Arial", "B", 12)
                pdf.cell(40, 10, sanitize_text(f"{key}:"))
                pdf.ln(10)

                pdf.set_font("Arial", "", 12)
                if isinstance(value, dict):
                    value = json.dumps(value, indent=4)
                pdf.multi_cell(0, 10, sanitize_text(str(value)))
                pdf.ln(10)

            report_path = "ReverzeX_Analysis_Report.pdf"
            pdf.output(report_path)

            print(f"PDF report generated: {report_path}")
            logging.info(f"PDF report generated: {report_path}")
        except Exception as e:
            print(f"An error occurred while generating PDF report: {str(e)}")
            logging.error(f"An error occurred while generating PDF report: {str(e)}")
