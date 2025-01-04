import json
import requests
from typing import List, Dict, Any, Union
import os
from datetime import datetime

OLLAMA_BASE_URL = "http://localhost:11434/api"
LLM_MODEL = "llama3.2"
SIMILARITY_THRESHOLD = 0.1

class LogNormalizer:
    @staticmethod
    def normalize_log_entry(entry: Any) -> Dict[str, str]:
        """Convert various log entry formats into a standardized dictionary"""
        if isinstance(entry, str):
            try:
                parsed = json.loads(entry)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
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
        if isinstance(logs, str):
            try:
                parsed = json.loads(logs)
                if isinstance(parsed, list):
                    for entry in parsed:
                        normalized_logs.append(LogNormalizer.normalize_log_entry(entry))
                elif isinstance(parsed, dict):
                    normalized_logs.append(LogNormalizer.normalize_log_entry(parsed))
                else:
                    for line in logs.split('\n'):
                        if line.strip():
                            normalized_logs.append(LogNormalizer.normalize_log_entry(line))
            except json.JSONDecodeError:
                for line in logs.split('\n'):
                    if line.strip():
                        normalized_logs.append(LogNormalizer.normalize_log_entry(line))
        elif isinstance(logs, list):
            for entry in logs:
                normalized_logs.append(LogNormalizer.normalize_log_entry(entry))
        elif isinstance(logs, dict):
            normalized_logs.append(LogNormalizer.normalize_log_entry(logs))
        else:
            raise ValueError(f"Unsupported logs format: {type(logs)}")
        return normalized_logs

class EmbeddingClient:
    def __init__(self, model: str = LLM_MODEL):
        self.model = model

    def get_embedding(self, text: str) -> List[float]:
        """Fetch embeddings from embedding service"""
        response = requests.post(
            f"{OLLAMA_BASE_URL}/embeddings",
            json={"model": self.model, "prompt": text}
        )
        if response.status_code != 200:
            raise Exception(f"Error getting embedding: {response.text}")
        return response.json().get("embedding", [])

class TTPMatcher:
    def __init__(self, similarity_threshold: float = SIMILARITY_THRESHOLD):
        self.similarity_threshold = similarity_threshold
        self.ttp_database = self.load_ttp_database()

    def load_ttp_database(self) -> List[Dict[str, Any]]:
        """Load TTP database from a JSON file"""
        with open("./data/ttp_data.json", "r") as file:
            return json.load(file)

    def match_ttps(self, extracted_ttps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match extracted TTPs to database entries"""
        matches = []
        for ttp in extracted_ttps:
            for db_ttp in self.ttp_database:
                similarity = self.calculate_similarity(ttp, db_ttp)
                if similarity >= self.similarity_threshold:
                    matches.append({
                        "id": db_ttp["id"],
                        "description": db_ttp["description"],
                        "similarity": similarity
                    })
        return matches

    @staticmethod
    def calculate_similarity(ttp: Dict[str, Any], db_ttp: Dict[str, Any]) -> float:
        """Placeholder for similarity calculation logic"""
        return 0.5  # Replace with real similarity logic

class NetworkTTPAnalyzer:
    def __init__(self):
        self.log_normalizer = LogNormalizer()
        self.embedding_client = EmbeddingClient()
        self.ttp_matcher = TTPMatcher()

    def analyze_logs(self, logs: Any) -> List[Dict[str, Any]]:
        """Analyze logs and extract TTPs"""
        try:
            # Normalize logs
            normalized_logs = self.log_normalizer.normalize_logs(logs)

            # Generate embeddings and descriptions
            descriptions = [self.generate_description(log) for log in normalized_logs]

            # Extract TTPs from descriptions
            extracted_ttps = [self.extract_ttps(desc) for desc in descriptions]

            # Match TTPs to database entries
            ttp_matches = self.ttp_matcher.match_ttps(extracted_ttps)

            return ttp_matches
        except Exception as e:
            print(f"Error in analyze_logs: {str(e)}")
            raise

    def generate_description(self, log: Dict[str, str]) -> str:
        """Generate human-readable description of log"""
        return json.dumps(log)  # Replace with LLM-based description logic

    def extract_ttps(self, description: str) -> Dict[str, Any]:
        """Extract TTPs from a description"""
        return {"description": description}  # Replace with real TTP extraction logic

if __name__ == "__main__":
    logs = """[
        {"timestamp": "2025-01-04T19:10:18.587099", "event": "Failed login attempt"},
        {"timestamp": "2025-01-04T19:15:22.345678", "event": "Suspicious DNS query"}
    ]"""

    analyzer = NetworkTTPAnalyzer()
    ttp_matches = analyzer.analyze_logs(logs)
    print(json.dumps(ttp_matches, indent=2))
