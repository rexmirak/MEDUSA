import json
import numpy as np
from typing import List, Dict, Set
import requests
from sklearn.metrics.pairwise import cosine_similarity

# Global configurations
SIMILARITY_THRESHOLD = 0.1
OLLAMA_BASE_URL = "http://localhost:11434/api"
EMBEDDING_MODEL = "nomic-embed-text"
LLM_MODEL = "llama2"

class APTRagSystem:
    def __init__(self, json_file_path: str):
        self.vector_db = []
        self.json_file_path = json_file_path
        self.apt_data = self.load_apt_data()
        self.process_apt_data()

    def load_apt_data(self) -> List[Dict]:
        """Load APT data from JSON file"""
        with open(self.json_file_path, 'r') as file:
            return json.load(file)

    def get_embedding(self, text: str) -> List[float]:
        """Get embeddings using nomic-embed-text"""
        response = requests.post(
            f"{OLLAMA_BASE_URL}/embeddings",
            json={"model": EMBEDDING_MODEL, "prompt": text}
        )
        if response.status_code != 200:
            raise Exception(f"Error getting embedding: {response.text}")
        return response.json()["embedding"]

    def process_apt_data(self):
        """Process APT data and create embeddings"""
        for apt in self.apt_data:
            # Create a comprehensive text representation of the APT
            apt_text = f"""
            Group: {apt['mitre_attack_name']} ({apt['etda_name']})
            Aliases: {', '.join(apt['mitre_attack_aliases'])}
            Country: {apt['country']}
            Motivation: {', '.join(apt['motivation'])}
            Victim Industries: {', '.join(apt['victim_industries'])}
            Victim Countries: {', '.join(apt['victim_countries'])}
            TTPs: {', '.join(apt['mitre_attack_ttps'])}
            """
            
            embedding = self.get_embedding(apt_text)
            
            self.vector_db.append({
                'id': apt['mitre_attack_id'],
                'embedding': embedding,
                'original_data': apt
            })

    def find_apt_by_ttps(self, ttp_list: List[str], return_full_profile: bool = True) -> List[Dict]:
        """Find APT groups based on TTPs"""
        # First, filter APTs that use any of the specified TTPs
        matching_apts = []
        
        for apt_entry in self.vector_db:
            apt_data = apt_entry['original_data']
            apt_ttps = set(apt_data['mitre_attack_ttps'])
            query_ttps = set(ttp_list)
            
            # Calculate percentage of matching TTPs
            matching_ttps = apt_ttps.intersection(query_ttps)
            if matching_ttps:
                match_percentage = len(matching_ttps) / len(query_ttps)
                if match_percentage >= SIMILARITY_THRESHOLD:
                    result = {
                        'id': apt_data['mitre_attack_id'],
                        'name': apt_data['mitre_attack_name'],
                        'match_score': f"{match_percentage:.2f}",
                        'matching_ttps': list(matching_ttps)
                    }
                    
                    if return_full_profile:
                        result['full_profile'] = {
                            'etda_name': apt_data['etda_name'],
                            'aliases': apt_data['mitre_attack_aliases'],
                            'country': apt_data['country'],
                            'motivation': apt_data['motivation'],
                            'victim_industries': apt_data['victim_industries'],
                            'victim_countries': apt_data['victim_countries'],
                            'first_seen': apt_data['etda_first_seen'],
                            'mitre_url': apt_data['mitre_url'],
                            'etda_url': apt_data['etda_url']
                        }
                    
                    matching_apts.append(result)
        
        # Sort by match score
        matching_apts.sort(key=lambda x: float(x['match_score']), reverse=True)
        return matching_apts

# Example usage
if __name__ == "__main__":
    # Initialize system
    rag = APTRagSystem("./data/apt_data.json")
    
    # Example query
    ttp_list = ['T1001', 'T1001.002', 'T1071.001']
    
    # Get matching APT groups
    matching_groups = rag.find_apt_by_ttps(ttp_list)
    print(json.dumps(matching_groups, indent=2))