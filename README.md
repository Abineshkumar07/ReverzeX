
---

# ReverzeX CLI Tool


# ReverzeX - Malware Reverse Engineering Tool

ReverzeX is a powerful malware reverse engineering tool designed for analyzing potentially malicious files and extracting valuable information. It offers a suite of functionalities including file disassembly, threat intelligence integration, network traffic analysis, and comprehensive report generation. Whether you're a security researcher, a malware analyst, or someone interested in cybersecurity, ReverzeX provides the tools you need to dive deep into file analysis.

## Features

- **File Analysis**: Disassemble and analyze executable files to identify low-level instructions and functions.
- **Threat Intelligence Integration**: Query VirusTotal for file analysis, threat scoring, and detailed intelligence reports.
- **Network Capture**: Capture and analyze live network traffic to detect potentially malicious activities.
- **PDF Report Generation**: Generate detailed PDF reports summarizing the analysis, suitable for documentation and sharing.
- **User-Friendly CLI**: Access all functionalities via an intuitive command-line interface.
- **Logging**: Keep track of all activities and analysis results with extensive logging features.


## Installation

### Prerequisites

Before you begin, ensure you have the following installed:

- Python 3.6 or higher
  

### Steps to Install

1. **Clone the Repository**

   Start by cloning the repository to your local machine:

   ```bash
   git clone https://github.com/Abineshkumar07/ReverzeX.git
   cd ReverzeX
   ```

2. **Install Dependencies**

   Install the necessary Python libraries by running:

   ```bash
   pip install -r requirements.txt
   ```

   Alternatively, you can install dependencies individually:

   ```bash
   pip install r2pipe pyshark fpdf requests
   ```

3. **Update Configuration**

   You will need to update the `threat_intelligence.py` file with your VirusTotal API key. Instructions for this are provided in the [Configuration](#configuration) section below.

## Usage

### Running the Application

To start the ReverzeX tool, navigate to the directory where it is installed and run:

```bash
python main.py
```

Upon running, you will be presented with a menu of available commands to perform various tasks.

### Available Commands

   - **1**: Analyze File - Perform a comprehensive analysis of the opened file.
   - **2**: Extract Strings - Extract and list all the strings found in the file.
   - **3**: List Functions - List all the functions discovered in the file.
   - **4**: File Metadata - Retrieve detailed file metadata information.
   - **5**: Calculate Threat Score - Calculate and display the threat score based on threat intelligence data.
   - **6**: Show Analysis Summary - Display a summary of the latest analysis results.
   - **7**: View File History - Show file history, including creation time, last analysis, and first submission.
   - **8**: Basic File Properties - Display basic properties like hash values and file size.
   - **9**: List Threat Categories - List potential threat categories based on the analysis.
   - **10**: Automated Network Capture - Automatically start and monitor network capture.
   - **11**: Capture Network Traffic - Start capturing network traffic for analysis.
   - **12**: Generate PDF Report - Generate a comprehensive PDF report of the analysis.
   - **h**: Help - Display the help message.
   - **q**: Quit - Exit the tool.

Here is a detailed breakdown of the available commands:


Once the tool is running, you will be prompted to enter the file path of the malware file you wish to analyze:

```
Enter file path: sample_malware
```


1. **Analyze File**: Disassemble and analyze the opened file. This includes disassembling the binary and analyzing its contents to identify instructions, functions, and other key elements.

   ```bash
   Command: 1
   ```

2. **Extract Strings**: Extract and display all strings found in the file, which can often include indicators of malicious behavior such as URLs, file paths, and other potentially sensitive information.

   ```bash
   Command: 2
   ```

3. **List Functions**: List all functions identified within the file. This can be useful for understanding the capabilities and behavior of the executable.

   ```bash
   Command: 3
   ```

4. **File Metadata**: Retrieve and display detailed metadata information about the file, such as file type, size, hash values, and timestamps.

   ```bash
   Command: 4
   ```

5. **Calculate Threat Score**: Query VirusTotal to calculate and display a threat score based on the file's reputation and analysis results from multiple antivirus engines.

   ```bash
   Command: 5
   ```

6. **Show Analysis Summary**: Display a summary of the most recent analysis results, including key findings and threat indicators.

   ```bash
   Command: 6
   ```

7. **View File History**: Display the history of the file, including creation time, last analysis date, and first submission to VirusTotal.

   ```bash
   Command: 7
   ```

8. **Basic File Properties**: Show basic properties such as hash values (MD5, SHA-1, SHA-256) and file size, which can be useful for identifying and comparing files.

   ```bash
   Command: 8
   ```

9. **List Threat Categories**: List potential threat categories identified during analysis, such as ransomware, spyware, or trojans.

   ```bash
   Command: 9
   ```

10. **Automated Network Capture**: Start an automated process to capture and monitor network traffic, which can help identify malicious connections.

    ```bash
    Command: 10
    ```

11. **Capture Network Traffic**: Manually start capturing network traffic for analysis, allowing you to review packets and detect suspicious activity.

    ```bash
    Command: 11
    ```

12. **Generate PDF Report**: Create a detailed PDF report of the current analysis, which includes all findings, threat scores, and metadata.

    ```bash
    Command: 12
    ```

13. **Help**: Display the help menu, listing all available commands and a brief description of their functionality.

    ```bash
    Command: h
    ```

14. **Quit**: Exit the ReverzeX tool.

    ```bash
    Command: q
    ```



## Configuration

### Threat Intelligence API Key

To leverage the threat intelligence features of ReverzeX, you must configure the tool with your VirusTotal API key. Follow these steps:

1. Open the `threat_intelligence.py` file in a text editor:

   ```bash
   nano threat_intelligence.py
   ```

2. Locate the line where the API key is set:

   ```python
   self.api_key = "your_api_key_here"
   ```

3. Replace `"your_api_key_here"` with your actual VirusTotal API key.

4. Save the file and exit the editor.

### Network Capture Configuration

ReverzeX uses `pyshark` to capture and analyze network traffic. By default, it captures traffic on the primary network interface. If you need to capture traffic on a specific interface or apply filters, you can modify the capture settings in the `network_capture.py` file.

## Logging

ReverzeX logs all its activities and analysis results to a log file located in the `logs` directory. The log file is named `reverzex.log`.

### Accessing Logs

To view the logs:

```bash
cat logs/reverzex.log
```

Logs include timestamps, command execution details, error messages, and analysis results, providing a detailed record of your usage.

## Contributing

Contributions are welcome! If you’d like to contribute to ReverzeX, please follow these guidelines:

1. Fork the repository and create your branch from `main`.
2. Ensure your code follows the existing coding style and conventions.
3. Include tests for any new functionality.
4. Submit a pull request with a clear description of your changes and the rationale behind them.

For major changes, please open an issue first to discuss what you would like to change.

## Contact

For any questions, issues, or inquiries, please feel free to contact me at [sabineshkumar07@gmail.com](mailto:sabineshkumar07@gmail.com).

---


