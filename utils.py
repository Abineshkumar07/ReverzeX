def print_banner():
    red = '\033[91m'
    reset = '\033[0m'
    
    banner = f"""
{red}

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
    blue = '\033[94m'
    yellow = '\033[93m'
    reset = '\033[0m'
    
    help_text = f"""
{blue}Available commands:{reset}

    {yellow}1  - Analyze File              {reset}- Perform a comprehensive analysis of the opened file
    {yellow}2  - Extract Strings           {reset}- Extract and list all the strings found in the file
    {yellow}3  - List Functions            {reset}- List all the functions discovered in the file
    {yellow}4  - File Metadata             {reset}- Retrieve detailed file metadata information
    {yellow}5  - Calculate Threat Score    {reset}- Calculate and display the threat score based on threat intelligence data
    {yellow}6  - Show Analysis Summary     {reset}- Display a summary of the latest analysis results
    {yellow}7  - View File History         {reset}- Show file history, including creation time, last analysis, and first submission
    {yellow}8  - Basic File Properties     {reset}- Display basic properties like hash values and file size
    {yellow}9  - List Threat Categories    {reset}- List potential threat categories based on the analysis
    {yellow}10 - Automated Network Capture {reset}- Automatically start and monitor network capture
    {yellow}11 - Capture Network Traffic   {reset}- Start capturing network traffic for analysis
    {yellow}12 - Generate PDF Report       {reset}- Generate a comprehensive PDF report of the analysis
    {yellow}h  - Help                      {reset}- Display this help message
    {yellow}q  - Quit                      {reset}- Exit the tool

"""
    print(help_text)
