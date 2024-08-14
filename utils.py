def print_banner():
    green = '\033[92m'
    reset = '\033[0m'
    
    banner = f"""
{green}

______                           __   __
| ___ \                          \ \ / /
| |_/ /_____   _____ _ __ _______ \ V / 
|    // _ \ \ / / _ \ '__|_  / _ \/   \ 
| |\ \  __/\ V /  __/ |   / /  __/ /^\ \
\_| \_\___| \_/ \___|_|  /___\___\/   \/

                                                                                
{reset}
    """
    print(banner)


def print_help():
    help_text = """
Available commands:
    1  - Analyze File              - Perform a comprehensive analysis of the opened file
    2  - Extract Strings           - Extract and list all the strings found in the file
    3  - List Functions            - List all the functions discovered in the file
    4  - File Metadata             - Retrieve detailed file metadata information
    5  - Calculate Threat Score    - Calculate and display the threat score based on threat intelligence data
    6  - Show Analysis Summary     - Display a summary of the latest analysis results
    7  - View File History         - Show file history, including creation time, last analysis, and first submission
    8  - Basic File Properties     - Display basic properties like hash values and file size
    9  - Automated Network Capture - Automatically start and monitor network capture
    10 - List Threat Categories    - List potential threat categories based on the analysis
    11 - Capture Network Traffic   - Start capturing network traffic for analysis
    12 - Generate PDF Report       - Generate a comprehensive PDF report of the analysis
    h  - Help                      - Display this help message
    q  - Quit                      - Exit the tool
"""
    print(help_text)
