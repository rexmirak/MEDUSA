import json
import requests
from typing import List, Dict, Any
import os

OLLAMA_BASE_URL = "http://localhost:11434/api"
LLM_MODEL = "llama3.2"

class LLMClient:
    def __init__(self, model: str, history_file: str):
        self.model = model
        self.history_file = history_file
        self.history = self.load_history()
    
    def load_history(self) -> List[Dict[str, str]]:
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                data = json.load(f)
                return data.get("messages", [])
        return []
    
    def save_history(self):
        with open(self.history_file, 'w') as f:
            json.dump({"messages": self.history}, f, indent=2)
    
    def format_message_for_context(self, msg: Dict) -> Dict:
        """Format a message for context inclusion"""
        return {
            "role": msg.get("role", "user"),
            "content": msg.get("content", "")
        }

    def query_llm(self, prompt: str, context: List[Dict]) -> str:
        """Query LLM with context"""
        # Format each message in the context
        formatted_context = [self.format_message_for_context(msg) for msg in context]
        
        # Create the full prompt with properly formatted JSON
        try:
            prompt_data = json.loads(prompt)  # If prompt is a JSON string
            context_str = json.dumps(formatted_context, ensure_ascii=False)
            full_prompt = f"""Context: {context_str}\n\nQuestion: {json.dumps(prompt_data)}\n\nAnswer:"""
        except json.JSONDecodeError:
            # If the prompt is not JSON, use it as plain text
            context_str = json.dumps(formatted_context, ensure_ascii=False)
            full_prompt = f"""Context: {context_str}\n\nQuestion: {prompt}\n\nAnswer:"""
        
        try:
            # Stream the response from the server
            response = requests.post(
                f"{OLLAMA_BASE_URL}/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt
                },
                stream=True  # Enable streaming
            )
            response.raise_for_status()  # Raises an error if the response code is bad
            
            # Initialize an empty string to hold the full response
            full_response = ""
            
            # Iterate over the streamed content and process it as JSON chunks
            for line in response.iter_lines():
                if line:
                    try:
                        json_line = json.loads(line.decode('utf-8'))  # Decode and parse each line as JSON
                        full_response += json_line.get("response", "")  # Append each response part
                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON line: {e}")
            
            # Add the interaction to history
            self.history.append({"role": "user", "content": prompt})
            self.history.append({"role": "assistant", "content": full_response})
            self.save_history()
            
            # Return the concatenated response
            return full_response or "No response received"
            
        except requests.exceptions.RequestException as e:
            print(f"Error communicating with Ollama: {e}")
            return "Error: Failed to get response from Ollama"

class NetworkTTPAnalyzer:
    def __init__(self):
        self.network_analyzer = LLMClient(
            LLM_MODEL, 
            "./data/network_analyzer_history.json"
        )
        self.ttp_extractor = LLMClient(
            LLM_MODEL,
            "./data/ttp_extractor_history.json"
        )
        
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
                
                Ensure each description is specific and technical, not general.
                Response must be a valid JSON array that can be parsed."""
            })
            self.ttp_extractor.save_history()

    def analyze_logs(self, logs: str) -> List[Dict[str, Any]]:
        # Step 1: Convert logs to English description
        english_description = self.network_analyzer.query_llm(logs, self.network_analyzer.history)
        
        # Step 2: Extract TTPs from description
        ttp_response = self.ttp_extractor.query_llm(english_description, self.ttp_extractor.history)
        
        # Parse JSON response
        try:
            ttps = json.loads(ttp_response)
            return ttps
        except json.JSONDecodeError:
            # If response isn't valid JSON, try to extract JSON-like content
            import re
            json_match = re.search(r'\[.*\]', ttp_response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            raise Exception("Could not parse TTP response as JSON")

def main():
    # Example usage
    analyzer = NetworkTTPAnalyzer()
    
    # Example log input
    sample_log = """
    2024-01-01T12:00:00Z AWS CloudTrail: UserIdentity: type=IAMUser userName=admin 
    eventName=CreateAccessKey sourceIPAddress=192.168.1.100
    2024-01-01T12:05:00Z AWS CloudTrail: UserIdentity: type=IAMUser userName=admin 
    eventName=PutRolePolicy sourceIPAddress=192.168.1.100 
    requestParameters:RoleName=lambda-admin PolicyName=full-access
    """

    try:
        ttps = analyzer.analyze_logs(json.dumps(example_logs, indent=2))
        print(json.dumps(ttps, indent=2))
    except Exception as e:
        print(f"Error analyzing logs: {str(e)}")

if __name__ == "__main__":
    main()