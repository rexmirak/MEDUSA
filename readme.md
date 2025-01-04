# MEDUSA Retaliation System

## Overview
The MEDUSA Retaliation System is a comprehensive cybersecurity analysis tool designed to identify and assess potential security threats. It integrates network logs, AWS logs, and APT (Advanced Persistent Threat) databases to detect tactics, techniques, and procedures (TTPs) and associate them with known APT groups. The system generates detailed incident reports to assist threat analysts and incident response teams in understanding and mitigating security incidents.

## Features
- **APT Analysis**:
  - Matches detected TTPs to known APT groups using a preprocessed vector database.
  - Utilizes advanced text embeddings to calculate similarity metrics.

- **TTP Detection and Similarity Analysis**:
  - Detects and extracts TTPs from network and AWS logs.
  - Identifies kill chain phases and provides detailed descriptions.

- **Network Log Analysis**:
  - Processes and normalizes raw logs in various formats (JSON, raw text, dictionaries).
  - Extracts meaningful information to identify potential threats.

- **Automated Report Generation**:
  - Generates JSON reports summarizing detected TTPs, matching APT groups, and analysis details.
  - Includes timestamps and execution time for each analysis.

- **LLM Integration**:
  - Leverages a language model (LLaMA) to generate detailed explanations and perform incident analysis.

## Project Structure
```
.
├── apt_rag_system.py         # Handles APT database processing and similarity analysis
├── ttp_rag_system.py         # Manages TTP similarity analysis and embedding generation
├── network_ttp_analyzer.py   # Processes network logs and extracts TTPs
├── MEDUSA_RETALIATION.py     # Integrates all components for end-to-end analysis
├── data/
│   ├── apt_data.json         # APT data used for matching
│   ├── ttp_data.json         # TTP data for similarity analysis
│   ├── reports.json          # Generated reports
│   └── network_analyzer_history.json # LLM network analysis history
└── requirements.txt          # Python dependencies
```

## Installation
### Prerequisites
- Python 3.8+
- pip package manager

### Steps
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd <repository_name>
   ```
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up data files:
   - Ensure the `data/` directory contains `apt_data.json` and `ttp_data.json`.
   - Modify file paths if necessary in the scripts.

## Usage
### Running the System
1. Execute the main script:
   ```bash
   python MEDUSA_RETALIATION.py
   ```
2. The system will process logs and generate a report in `data/reports.json`.

### Input Logs
- The system accepts:
  - JSON logs (e.g., AWS CloudTrail logs).
  - Raw text logs (e.g., firewall logs).
  - Lists or dictionaries of log entries.

### Outputs
- A JSON report with the following:
  - **Logs**: Raw and normalized log data.
  - **TTPs**: Detected TTPs and their descriptions.
  - **APTs**: Matching APT groups with associated data.
  - **Analysis Time**: Total execution time.

## Example Workflow
1. **Input Logs**:
   ```json
   [
     {
       "timestamp": "2024-12-07T08:00:00Z",
       "source_ip": "192.168.1.50",
       "destination_ip": "203.0.113.100",
       "protocol": "HTTPS",
       "payload": "C2 beacon: GET /tasks/update"
     }
   ]
   ```
2. **Generated Report**:
   ```json
   {
     "report": "2024-12-07T10:00:00Z",
     "logs": [...],
     "description of logs": "Command and Control communication detected...",
     "network analysis": [...],
     "TTPs": [...],
     "APTs": [...],
     "Time taken for analysis": "3.42 seconds"
   }
   ```

## Configuration
### Global Settings
- Modify configurations in individual scripts:
  - `SIMILARITY_THRESHOLD`: Minimum similarity score for matching.
  - `OLLAMA_BASE_URL`: API URL for embedding and LLM queries.
  - `EMBEDDING_MODEL`: Model used for generating text embeddings.

## Contributing
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add a new feature"
   ```
4. Push the branch:
   ```bash
   git push origin feature-name
   ```
5. Create a pull request.

## License
This project is licensed under the `MIT License`.

## Acknowledgments
- **MITRE ATT&CK Framework** for the TTP classifications.
- **OpenAI's LLaMA model** for language processing.

## Contact
For questions or support, please contact [karim.abdel-aziz@guc.edu.eg].

