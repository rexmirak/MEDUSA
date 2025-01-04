import json
import requests
from typing import List, Dict, Any, Union
import os
from datetime import datetime

OLLAMA_BASE_URL = "http://localhost:11434/api"
LLM_MODEL = "llama3.2"

class LogNormalizer:
    @staticmethod
    def normalize_log_entry(entry: Any) -> Dict[str, str]:
        """Convert various log entry formats into a standardized dictionary"""
        if isinstance(entry, str):
            # Try to parse as JSON first
            try:
                parsed = json.loads(entry)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                # If not JSON, treat as raw log string
                return {
                    "timestamp": datetime.now().isoformat(),
                    "raw_log": entry.strip()
                }
        elif isinstance(entry, dict):
            return entry
        else:
            raise ValueError(f"Unsupported log entry format: {type(entry)}")
        
    @staticmethod
    def normalize_logs(logs: Any) -> List[Dict[str, str]]:
        """Convert various log formats into a standardized list of log entries"""
        normalized_logs = []
        
        # Handle string input
        if isinstance(logs, str):
            # Try to parse as JSON first
            try:
                parsed = json.loads(logs)
                if isinstance(parsed, list):
                    for entry in parsed:
                        normalized_logs.append(LogNormalizer.normalize_log_entry(entry))
                elif isinstance(parsed, dict):
                    normalized_logs.append(LogNormalizer.normalize_log_entry(parsed))
                else:
                    # Treat as raw log string
                    # Split by newlines and process each line
                    for line in logs.split('\n'):
                        if line.strip():
                            normalized_logs.append(LogNormalizer.normalize_log_entry(line))
            except json.JSONDecodeError:
                # If not JSON, treat as raw log string
                for line in logs.split('\n'):
                    if line.strip():
                        normalized_logs.append(LogNormalizer.normalize_log_entry(line))
        
        # Handle list input
        elif isinstance(logs, list):
            for entry in logs:
                normalized_logs.append(LogNormalizer.normalize_log_entry(entry))
        
        # Handle dict input
        elif isinstance(logs, dict):
            normalized_logs.append(LogNormalizer.normalize_log_entry(logs))
            
        else:
            raise ValueError(f"Unsupported logs format: {type(logs)}")
            
        return normalized_logs

class LLMClient:
    def __init__(self, model: str, history_file: str):
        self.model = model
        self.history_file = history_file
        self.history = self.load_history()
    
    def load_history(self) -> List[Dict[str, str]]:
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                try:
                    data = json.load(f)
                    return data.get("messages", [])
                except json.JSONDecodeError:
                    print(f"Error loading history file {self.history_file}. Starting with empty history.")
                    return []
        return []
    
    def save_history(self):
        os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
        with open(self.history_file, 'w') as f:
            json.dump({"messages": self.history}, f, indent=2)
    
    def format_message_for_context(self, msg: Dict) -> Dict:
        """Format a message for context inclusion"""
        return {
            "role": msg.get("role", "user"),
            "content": msg.get("content", "")
        }

    def query_llm(self, prompt: Union[str, Dict, List], context: List[Dict]) -> str:
        """Query LLM with context"""
        # Convert prompt to string if it's not already
        if isinstance(prompt, (dict, list)):
            prompt_str = json.dumps(prompt, indent=2)
        else:
            prompt_str = str(prompt)
            
        # Format each message in the context
        formatted_context = [self.format_message_for_context(msg) for msg in context]
        context_str = json.dumps(formatted_context, ensure_ascii=False)
        
        # Create the full prompt
        full_prompt = f"""Context: {context_str}\n\nInput: {prompt_str}\n\nAnalysis:"""
        
        try:
            # Stream the response from the server
            response = requests.post(
                f"{OLLAMA_BASE_URL}/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt
                },
                stream=True
            )
            response.raise_for_status()
            
            full_response = ""
            for line in response.iter_lines():
                if line:
                    try:
                        json_line = json.loads(line.decode('utf-8'))
                        full_response += json_line.get("response", "")
                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON line: {e}")
            
            # Add the interaction to history
            self.history.append({"role": "user", "content": prompt_str})
            self.history.append({"role": "assistant", "content": full_response})
            self.save_history()
            
            return full_response or "No response received"
            
        except requests.exceptions.RequestException as e:
            print(f"Error communicating with Ollama: {e}")
            return f"Error: Failed to get response from Ollama: {str(e)}"

class NetworkTTPAnalyzer:
    def __init__(self, model: str = LLM_MODEL):
        self.network_analyzer = LLMClient(
            model, 
            os.path.join("data", "network_analyzer_history.json")
        )
        self.ttp_extractor = LLMClient(
            model,
            os.path.join("data", "ttp_extractor_history.json")
        )
        self.log_normalizer = LogNormalizer()
        
        # Initialize system messages
        self._initialize_llms()
    
    def _initialize_llms(self):
        # Set system message for network analyzer if history is empty
        if not self.network_analyzer.history:
            self.network_analyzer.history.append({
                "role": "system",
                "content": """You are a network security analyst specialized in interpreting network logs. 
                Your task is to analyze network logs (firewall logs, AWS CloudTrail, etc.) and provide clear,
                detailed English descriptions of potential security events. Focus on:
                - Identifying suspicious patterns and behaviors
                - Describing the sequence of events
                - Maintaining technical accuracy while being clear and descriptive
                - Including relevant technical details (IPs, ports, services, etc.)
                Do not classify events into kill chain phases - focus only on describing what happened."""
            })
            self.network_analyzer.save_history()
        
        # Set system message for TTP extractor if history is empty
        if not self.ttp_extractor.history:
            self.ttp_extractor.history.append({
                "role": "system",
                "content": """You are a MITRE ATT&CK framework specialist. Your task is to analyze 
                security incident descriptions and identify relevant TTPs and their kill chain phases.
                For each distinct activity or behavior described, create a separate object containing:
                1. The relevant kill chain phase(s)
                2. A technical description of the specific TTP
                
                Output should be a JSON array of objects with "kill_chain_phases" and "description" keys.
                
                Available kill chain phases are:
                - Initial Access
                - Execution 
                - Persistence
                - Privilege Escalation
                - Defense Evasion
                - Credential Access
                - Discovery
                - Lateral Movement
                - Collection
                - Command and Control
                - Exfiltration
                - Impact
                
                IMPORTANT: ONLY CHOOSE ONE OR MORE FROM THIS LIST FOR THE kill chain phases, DON'T USE OTHER KEYWORDS FOR THE kill chain phases
                Ensure each description is specific and technical, not general. it has to be verbose and explains exactly what happened and/or when and/or how and/or the result and/or and commands or Tactics or Techniques or Procedures they used. 
                Response MUST be a valid JSON array that can be parsed."""
            })
            self.ttp_extractor.save_history()
    

    def analyze_logs(self, logs: Union[str, Dict, List]) -> List[Dict[str, Any]]:
        """
        Analyze logs in any format and extract TTPs
        
        Args:
            logs: Can be:
                - A string (raw logs or JSON-formatted string)
                - A dictionary (single log entry)
                - A list of dictionaries or strings (multiple log entries)
        
        Returns:
            List of dictionaries containing extracted TTPs with kill chain phases
        """
        try:
            # Step 1: Normalize the logs
            normalized_logs = self.log_normalizer.normalize_logs(logs)
            
            # Step 2: Convert normalized logs to English description
            english_description = self.network_analyzer.query_llm(
                normalized_logs, 
                self.network_analyzer.history
            )
            
            # Step 3: Extract TTPs from description
            ttp_response = self.ttp_extractor.query_llm(
                "generate a json list with \"kill chain phases\" and \"description\" keys of this report IMPORTNT KILL CHAIN PHASES VALUE IS A COMMA SEPERATED STRING OF VALUES.: "+english_description, 
                self.ttp_extractor.history
            )
            
            # Parse JSON response
            try:
                ttps = json.loads(ttp_response)
                return [ttps,english_description]
            except json.JSONDecodeError:
                # If response isn't valid JSON, try to extract JSON-like content
                import re
                json_match = re.search(r'\[.*\]', ttp_response, re.DOTALL)
                if json_match:
                    try:
                        return [json.loads(json_match.group()),english_description]
                    except json.JSONDecodeError:
                        raise ValueError("Could not parse TTP response as JSON")
                raise ValueError("No valid JSON found in TTP response")
                
        except Exception as e:
            print(f"Error in analyze_logs: {str(e)}")
            raise

def main():
    # Example usage with different input formats
    analyzer = NetworkTTPAnalyzer()
    
    # Example 1: JSON-formatted string
    json_logs = '''[
        {"timestamp": "2024-01-01T12:00:00Z", "event": "Failed login attempt"},
        {"timestamp": "2024-01-01T12:05:00Z", "event": "Password spray attack detected"}
    ]'''
    
    # Example 2: Raw log string
    raw_logs = """
    2024-01-01 12:00:00 Failed login attempt from 192.168.1.100
    2024-01-01 12:05:00 Password spray attack detected from multiple IPs
    """
    
    # Example 3: List of dictionaries
    dict_logs = [
        {"timestamp": "2024-01-01T12:00:00Z", "event": "Failed login attempt"},
        {"timestamp": "2024-01-01T12:05:00Z", "event": "Password spray attack detected"}
    ]
    
    # Example 4: Single dictionary
    single_log = {
        "timestamp": "2024-01-01T12:00:00Z",
        "event": "Failed login attempt"
    }
    
    example_logs = [
    {
        "timestamp": "2024-12-07T08:00:00.123Z",
        "source_ip": "192.168.1.50",
        "destination_ip": "203.0.113.100",
        "protocol": "HTTPS",
        "port": 443,
        "payload": "C2 beacon: GET /tasks/update"
    },
    {
        "timestamp": "2024-12-07T08:05:15.456Z",
        "source_ip": "192.168.1.51",
        "destination_ip": "192.168.1.10",
        "protocol": "SMB",
        "port": 445,
        "payload": "NTLM authentication attempt for lateral movement"
    },
    {
        "timestamp": "2024-12-07T08:10:30.789Z",
        "source_ip": "192.168.1.52",
        "destination_ip": "8.8.8.8",
        "protocol": "DNS",
        "port": 53,
        "payload": "DNS query: exfil.domain.com (suspected data exfiltration)"
    },
    {
        "timestamp": "2024-12-07T08:15:00.321Z",
        "source_ip": "192.168.1.53",
        "destination_ip": "203.0.113.50",
        "protocol": "LDAP",
        "port": 389,
        "payload": "Query: (&(objectClass=user)(servicePrincipalName=*))"
    },
    {
        "timestamp": "2024-12-07T08:20:45.654Z",
        "source_ip": "192.168.1.54",
        "destination_ip": "10.0.0.5",
        "protocol": "RDP",
        "port": 3389,
        "payload": "Brute-force login detected"
    },
    {
        "timestamp": "2024-12-07T08:25:30.987Z",
        "source_ip": "192.168.1.55",
        "destination_ip": "192.168.1.20",
        "protocol": "HTTP",
        "port": 80,
        "payload": "File upload detected: malicious.exe"
    },
    {
        "timestamp": "2024-12-07T08:30:00.567Z",
        "source_ip": "192.168.1.56",
        "destination_ip": "203.0.113.30",
        "protocol": "HTTPS",
        "port": 443,
        "payload": "POST request: /report-status (C2 communication)"
    },
    {
        "timestamp": "2024-12-07T08:35:12.890Z",
        "source_ip": "192.168.1.57",
        "destination_ip": "192.168.1.25",
        "protocol": "FTP",
        "port": 21,
        "payload": "File exfiltration: database_dump.sql"
    },
    {
        "timestamp": "2024-12-07T08:40:47.123Z",
        "source_ip": "192.168.1.58",
        "destination_ip": "192.168.1.30",
        "protocol": "SSH",
        "port": 22,
        "payload": "Failed login attempt (password guessing)"
    },
    {
        "timestamp": "2024-12-07T08:45:02.345Z",
        "source_ip": "192.168.1.59",
        "destination_ip": "192.168.1.35",
        "protocol": "SMB",
        "port": 445,
        "payload": "File access: \\\\server\\admin$\\sensitive_data.txt"
    },
    {
        "timestamp": "2024-12-07T08:50:25.678Z",
        "source_ip": "192.168.1.60",
        "destination_ip": "192.168.1.40",
        "protocol": "SNMP",
        "port": 161,
        "payload": "SNMP walk: public community string"
    },
    {
        "timestamp": "2024-12-07T08:55:10.234Z",
        "source_ip": "192.168.1.61",
        "destination_ip": "203.0.113.40",
        "protocol": "HTTPS",
        "port": 443,
        "payload": "Malware download: /resources/implant.bin"
    },
    {
        "timestamp": "2024-12-07T09:00:33.456Z",
        "source_ip": "192.168.1.62",
        "destination_ip": "10.0.0.15",
        "protocol": "Kerberos",
        "port": 88,
        "payload": "TGS-REQ for MSSQLSvc/dbserver.company.local"
    },
    {
        "timestamp": "2024-12-07T09:05:20.567Z",
        "source_ip": "192.168.1.63",
        "destination_ip": "10.0.0.20",
        "protocol": "MS-SQL",
        "port": 1433,
        "payload": "Login: NTLM Authentication for database access"
    },
    {
        "timestamp": "2024-12-07T09:10:48.789Z",
        "source_ip": "192.168.1.64",
        "destination_ip": "10.0.0.25",
        "protocol": "HTTP",
        "port": 80,
        "payload": "Query: SELECT * FROM master.sys.server_principals"
    }
]
    # try:
    #     # Test all input formats
    #     for logs in [json_logs, raw_logs, dict_logs, single_log]:
    #         print("\nAnalyzing logs:")
    #         print("-" * 50)
    #         print(f"Input type: {type(logs)}")
    #         ttps = analyzer.analyze_logs(logs)
    #         print("\nExtracted TTPs:")
    #         print(json.dumps(ttps, indent=2))
    #         print("-" * 50)

    # try:
    #     print("\nAnalyzing logs:")
    #     print("-" * 50)
    #     print(f"Input type: {type(example_logs)}")
    #     ttps = analyzer.analyze_logs(example_logs)
    #     print("\nExtracted TTPs:")
    #     print(json.dumps(ttps, indent=2))
    #     print("-" * 50)
            
    # except Exception as e:
    #     print(f"Error analyzing logs: {str(e)}")

if __name__ == "__main__":
    main()