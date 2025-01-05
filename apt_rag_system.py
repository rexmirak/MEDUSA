import json
import numpy as np
from typing import List, Dict, Set
import requests
from sklearn.metrics.pairwise import cosine_similarity

# Global configurations
SIMILARITY_THRESHOLD = 0.001
OLLAMA_BASE_URL = "http://localhost:11434/api"
EMBEDDING_MODEL = "nomic-embed-text"
LLM_MODEL = "llama2"

class APTRagSystem:
    def __init__(self, json_file_path: str):
        self.vector_db = []
        self.json_file_path = json_file_path
        self.apt_data = self.load_apt_data()
        # self.calculate_ttp_match()
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

    # def calculate_ttp_match(self,ttp_ids:List[str]):
    #     """
    #     Calculates the percentage of TTPs in a given list matching the TTPs in each object's profile.
        
    #     Args:
    #         objects (list): A list of dictionaries representing profiles with TTPs and other metadata.
    #         ttp_ids (list): A list of TTP IDs to compare against the profiles.

    #     Returns:
    #         list: A list of dictionaries with match score, matched TTPs, and full profile metadata.
    #     """
    #     objects= []
    #     with open("./data/apt_data.json", 'r') as file:
    #         objects=json.load(file)
    #     results = []

    #     for obj in objects:
    #         # Extract relevant fields
    #         mitre_ttps = obj.get("mitre_attack_ttps", [])
    #         matching_ttps = [ttp for ttp in ttp_ids if ttp in mitre_ttps]
    #         match_score = len(matching_ttps) / len(ttp_ids) if ttp_ids else 0
    #         if(match_score<SIMILARITY_THRESHOLD):
    #             continue
    #         # Prepare the structured result
    #         results.append({
    #             "id": obj.get("mitre_attack_id", ""),
    #             "name": obj.get("mitre_attack_name", ""),
    #             "match_score": round(match_score, 2),
    #             "matching_ttps": matching_ttps,
    #             "full_profile": {
    #                 "etda_name": obj.get("etda_name", ""),
    #                 "aliases": obj.get("etda_aliases", []),
    #                 "country": obj.get("country", ""),
    #                 "motivation": obj.get("motivation", []),
    #                 "victim_industries": obj.get("victim_industries", []),
    #                 "victim_countries": obj.get("victim_countries", []),
    #                 "first_seen": obj.get("etda_first_seen", ""),
    #                 "mitre_url": obj.get("mitre_url", ""),
    #                 "etda_url": obj.get("etda_url", "")
    #             }
    #         })

    #     return results

    def calculate_ttp_match(self, ttp_ids: List[Dict[str, str]]):
        """
        Calculates the percentage of TTPs in a given list matching the TTPs in each object's profile.
        
        Args:
            ttp_ids (list): A list of dictionaries representing TTPs with "id" and "similarity" keys.

        Returns:
            list: A list of dictionaries with match score, matched TTPs, and full profile metadata.
        """
        objects = []
        with open("./data/apt_data.json", 'r') as file:
            objects = json.load(file)
        
        results = []

        for obj in objects:
            # Extract relevant fields
            mitre_ttps = obj.get("mitre_attack_ttps", [])
            APT_TTP_MAX = len(mitre_ttps)

            # Filter and calculate matches
            matching_ttps = [ttp for ttp in ttp_ids if ttp['id'] in mitre_ttps]
            unmatched_ttps = [ttp for ttp in ttp_ids if ttp['id'] not in mitre_ttps]
            if (matching_ttps==[]):
                continue
            total_similarity_unmatched = sum(float(ttp['similarity']) for ttp in unmatched_ttps)
            total_similarity = sum(float(ttp['similarity']) for ttp in matching_ttps)
            match_score = (total_similarity / APT_TTP_MAX) - (total_similarity_unmatched / len(ttp_ids))
            
            if match_score < SIMILARITY_THRESHOLD:
                continue

            # Prepare the structured result
            results.append({
                "id": obj.get("mitre_attack_id", ""),
                "name": obj.get("mitre_attack_name", ""),
                "match_score": round(match_score, 2),
                "matching_ttps": [ttp['id'] for ttp in matching_ttps],
                "unmatching_ttps": [ttp['id'] for ttp in unmatched_ttps],
                "full_profile": {
                    "etda_name": obj.get("etda_name", ""),
                    "aliases": obj.get("etda_aliases", []),
                    "country": obj.get("country", ""),
                    "motivation": obj.get("motivation", []),
                    "victim_industries": obj.get("victim_industries", []),
                    "victim_countries": obj.get("victim_countries", []),
                    "first_seen": obj.get("etda_first_seen", ""),
                    "mitre_url": obj.get("mitre_url", ""),
                    "etda_url": obj.get("etda_url", "")
                }
            })

        # Sort by match score, ascending (lowest similarity first)
        results.sort(key=lambda x: x['match_score'],reverse=True)
        return results

# Example usage
if __name__ == "__main__":
    # # Initialize system
    # rag = APTRagSystem("./data/apt_data.json")
    
    # # Example query
    # ttp_list = ['T1001', 'T1001.002', 'T1071.001']
    
    # # Get matching APT groups
    # matching_groups = rag.calculate_ttp_match(ttp_list)
    # print(json.dumps(matching_groups, indent=2))

    ttp_list =[
            {
                "id": "T1098",
                "similarity": "0.75"
            },
            {
                "id": "T1484",
                "similarity": "0.75"
            },
            {
                "id": "T1528",
                "similarity": "0.74"
            },
            {
                "id": "T1531",
                "similarity": "0.74"
            },
            {
                "id": "T1556",
                "similarity": "0.74"
            },
            {
                "id": "T1578.001",
                "similarity": "0.74"
            },
            {
                "id": "T1078",
                "similarity": "0.73"
            },
            {
                "id": "T1606",
                "similarity": "0.73"
            },
            {
                "id": "T1098.001",
                "similarity": "0.72"
            },
            {
                "id": "T1134.003",
                "similarity": "0.72"
            },
            {
                "id": "T1539",
                "similarity": "0.72"
            },
            {
                "id": "T1550.004",
                "similarity": "0.72"
            },
            {
                "id": "T1056.003",
                "similarity": "0.71"
            },
            {
                "id": "T1078.001",
                "similarity": "0.71"
            },
            {
                "id": "T1078.002",
                "similarity": "0.71"
            },
            {
                "id": "T1110",
                "similarity": "0.71"
            },
            {
                "id": "T1134",
                "similarity": "0.71"
            },
            {
                "id": "T1212",
                "similarity": "0.71"
            },
            {
                "id": "T1546",
                "similarity": "0.71"
            },
            {
                "id": "T1550.001",
                "similarity": "0.71"
            },
            {
                "id": "T1556.001",
                "similarity": "0.71"
            },
            {
                "id": "T1562",
                "similarity": "0.71"
            },
            {
                "id": "T1563",
                "similarity": "0.71"
            },
            {
                "id": "T1565.003",
                "similarity": "0.71"
            },
            {
                "id": "T1615",
                "similarity": "0.71"
            },
            {
                "id": "T1098.003",
                "similarity": "0.70"
            },
            {
                "id": "T1136.003",
                "similarity": "0.70"
            },
            {
                "id": "T1190",
                "similarity": "0.70"
            },
            {
                "id": "T1199",
                "similarity": "0.70"
            },
            {
                "id": "T1204",
                "similarity": "0.70"
            },
            {
                "id": "T1204.003",
                "similarity": "0.70"
            },
            {
                "id": "T1210",
                "similarity": "0.70"
            },
            {
                "id": "T1525",
                "similarity": "0.70"
            },
            {
                "id": "T1548.004",
                "similarity": "0.70"
            },
            {
                "id": "T1557",
                "similarity": "0.70"
            },
            {
                "id": "T1565",
                "similarity": "0.70"
            },
            {
                "id": "T1565.001",
                "similarity": "0.70"
            },
            {
                "id": "T1565.002",
                "similarity": "0.70"
            },
            {
                "id": "T1569",
                "similarity": "0.70"
            },
            {
                "id": "T1574",
                "similarity": "0.70"
            },
            {
                "id": "T1574.010",
                "similarity": "0.70"
            },
            {
                "id": "T1578.002",
                "similarity": "0.70"
            },
            {
                "id": "T1580",
                "similarity": "0.70"
            },
            {
                "id": "T1586",
                "similarity": "0.70"
            },
            {
                "id": "T1586.002",
                "similarity": "0.70"
            },
            {
                "id": "T1606.001",
                "similarity": "0.70"
            },
            {
                "id": "T1068",
                "similarity": "0.69"
            },
            {
                "id": "T1078.004",
                "similarity": "0.69"
            },
            {
                "id": "T1110.004",
                "similarity": "0.69"
            },
            {
                "id": "T1222",
                "similarity": "0.69"
            },
            {
                "id": "T1486",
                "similarity": "0.69"
            },
            {
                "id": "T1491.001",
                "similarity": "0.69"
            },
            {
                "id": "T1546.003",
                "similarity": "0.69"
            },
            {
                "id": "T1546.014",
                "similarity": "0.69"
            },
            {
                "id": "T1548.002",
                "similarity": "0.69"
            },
            {
                "id": "T1553",
                "similarity": "0.69"
            },
            {
                "id": "T1574.005",
                "similarity": "0.69"
            },
            {
                "id": "T1578",
                "similarity": "0.69"
            },
            {
                "id": "T1584.001",
                "similarity": "0.69"
            },
            {
                "id": "T1584.004",
                "similarity": "0.69"
            },
            {
                "id": "T1588",
                "similarity": "0.69"
            },
            {
                "id": "T1608.004",
                "similarity": "0.69"
            },
            {
                "id": "T1003",
                "similarity": "0.68"
            },
            {
                "id": "T1025",
                "similarity": "0.68"
            },
            {
                "id": "T1039",
                "similarity": "0.68"
            },
            {
                "id": "T1053.001",
                "similarity": "0.68"
            },
            {
                "id": "T1078.003",
                "similarity": "0.68"
            },
            {
                "id": "T1134.002",
                "similarity": "0.68"
            },
            {
                "id": "T1136",
                "similarity": "0.68"
            },
            {
                "id": "T1137.005",
                "similarity": "0.68"
            },
            {
                "id": "T1195.001",
                "similarity": "0.68"
            },
            {
                "id": "T1195.002",
                "similarity": "0.68"
            },
            {
                "id": "T1204.002",
                "similarity": "0.68"
            },
            {
                "id": "T1222.002",
                "similarity": "0.68"
            },
            {
                "id": "T1489",
                "similarity": "0.68"
            },
            {
                "id": "T1505.001",
                "similarity": "0.68"
            },
            {
                "id": "T1505.004",
                "similarity": "0.68"
            },
            {
                "id": "T1543",
                "similarity": "0.68"
            },
            {
                "id": "T1546.009",
                "similarity": "0.68"
            },
            {
                "id": "T1546.015",
                "similarity": "0.68"
            },
            {
                "id": "T1547",
                "similarity": "0.68"
            },
            {
                "id": "T1547.014",
                "similarity": "0.68"
            },
            {
                "id": "T1550",
                "similarity": "0.68"
            },
            {
                "id": "T1552.005",
                "similarity": "0.68"
            },
            {
                "id": "T1556.003",
                "similarity": "0.68"
            },
            {
                "id": "T1557.002",
                "similarity": "0.68"
            },
            {
                "id": "T1562.001",
                "similarity": "0.68"
            },
            {
                "id": "T1563.001",
                "similarity": "0.68"
            },
            {
                "id": "T1563.002",
                "similarity": "0.68"
            },
            {
                "id": "T1584.002",
                "similarity": "0.68"
            },
            {
                "id": "T1586.001",
                "similarity": "0.68"
            },
            {
                "id": "T1588.001",
                "similarity": "0.68"
            },
            {
                "id": "T1608.001",
                "similarity": "0.68"
            },
            {
                "id": "T1021.001",
                "similarity": "0.67"
            },
            {
                "id": "T1055.004",
                "similarity": "0.67"
            },
            {
                "id": "T1056.002",
                "similarity": "0.67"
            },
            {
                "id": "T1098.004",
                "similarity": "0.67"
            },
            {
                "id": "T1110.001",
                "similarity": "0.67"
            },
            {
                "id": "T1134.001",
                "similarity": "0.67"
            },
            {
                "id": "T1185",
                "similarity": "0.67"
            },
            {
                "id": "T1195",
                "similarity": "0.67"
            },
            {
                "id": "T1195.003",
                "similarity": "0.67"
            },
            {
                "id": "T1201",
                "similarity": "0.67"
            },
            {
                "id": "T1207",
                "similarity": "0.67"
            },
            {
                "id": "T1484.002",
                "similarity": "0.67"
            },
            {
                "id": "T1538",
                "similarity": "0.67"
            },
            {
                "id": "T1543.003",
                "similarity": "0.67"
            },
            {
                "id": "T1546.010",
                "similarity": "0.67"
            },
            {
                "id": "T1546.013",
                "similarity": "0.67"
            },
            {
                "id": "T1548",
                "similarity": "0.67"
            },
            {
                "id": "T1548.001",
                "similarity": "0.67"
            },
            {
                "id": "T1555.005",
                "similarity": "0.67"
            },
            {
                "id": "T1560.001",
                "similarity": "0.67"
            },
            {
                "id": "T1561",
                "similarity": "0.67"
            },
            {
                "id": "T1561.001",
                "similarity": "0.67"
            },
            {
                "id": "T1562.004",
                "similarity": "0.67"
            },
            {
                "id": "T1562.008",
                "similarity": "0.67"
            },
            {
                "id": "T1566.001",
                "similarity": "0.67"
            },
            {
                "id": "T1584",
                "similarity": "0.67"
            },
            {
                "id": "T1587.004",
                "similarity": "0.67"
            },
            {
                "id": "T1588.005",
                "similarity": "0.67"
            },
            {
                "id": "T1588.006",
                "similarity": "0.67"
            },
            {
                "id": "T1589.001",
                "similarity": "0.67"
            },
            {
                "id": "T1601",
                "similarity": "0.67"
            },
            {
                "id": "T1602",
                "similarity": "0.67"
            },
            {
                "id": "T1606.002",
                "similarity": "0.67"
            },
            {
                "id": "T1608.005",
                "similarity": "0.67"
            },
            {
                "id": "T1003.003",
                "similarity": "0.66"
            },
            {
                "id": "T1003.006",
                "similarity": "0.66"
            },
            {
                "id": "T1021",
                "similarity": "0.66"
            },
            {
                "id": "T1027.005",
                "similarity": "0.66"
            },
            {
                "id": "T1036.003",
                "similarity": "0.66"
            },
            {
                "id": "T1055.003",
                "similarity": "0.66"
            },
            {
                "id": "T1055.011",
                "similarity": "0.66"
            },
            {
                "id": "T1055.012",
                "similarity": "0.66"
            },
            {
                "id": "T1056.001",
                "similarity": "0.66"
            },
            {
                "id": "T1056.004",
                "similarity": "0.66"
            },
            {
                "id": "T1059.008",
                "similarity": "0.66"
            },
            {
                "id": "T1072",
                "similarity": "0.66"
            },
            {
                "id": "T1091",
                "similarity": "0.66"
            },
            {
                "id": "T1098.002",
                "similarity": "0.66"
            },
            {
                "id": "T1111",
                "similarity": "0.66"
            },
            {
                "id": "T1114.003",
                "similarity": "0.66"
            },
            {
                "id": "T1133",
                "similarity": "0.66"
            },
            {
                "id": "T1134.004",
                "similarity": "0.66"
            },
            {
                "id": "T1134.005",
                "similarity": "0.66"
            },
            {
                "id": "T1136.002",
                "similarity": "0.66"
            },
            {
                "id": "T1176",
                "similarity": "0.66"
            },
            {
                "id": "T1200",
                "similarity": "0.66"
            },
            {
                "id": "T1203",
                "similarity": "0.66"
            },
            {
                "id": "T1211",
                "similarity": "0.66"
            },
            {
                "id": "T1213.003",
                "similarity": "0.66"
            },
            {
                "id": "T1218.005",
                "similarity": "0.66"
            },
            {
                "id": "T1485",
                "similarity": "0.66"
            },
            {
                "id": "T1491.002",
                "similarity": "0.66"
            },
            {
                "id": "T1499.002",
                "similarity": "0.66"
            },
            {
                "id": "T1499.003",
                "similarity": "0.66"
            },
            {
                "id": "T1499.004",
                "similarity": "0.66"
            },
            {
                "id": "T1505",
                "similarity": "0.66"
            },
            {
                "id": "T1530",
                "similarity": "0.66"
            },
            {
                "id": "T1534",
                "similarity": "0.66"
            },
            {
                "id": "T1537",
                "similarity": "0.66"
            },
            {
                "id": "T1546.001",
                "similarity": "0.66"
            },
            {
                "id": "T1552",
                "similarity": "0.66"
            },
            {
                "id": "T1553.004",
                "similarity": "0.66"
            },
            {
                "id": "T1554",
                "similarity": "0.66"
            },
            {
                "id": "T1557.001",
                "similarity": "0.66"
            },
            {
                "id": "T1561.002",
                "similarity": "0.66"
            },
            {
                "id": "T1562.010",
                "similarity": "0.66"
            },
            {
                "id": "T1566.003",
                "similarity": "0.66"
            },
            {
                "id": "T1574.004",
                "similarity": "0.66"
            },
            {
                "id": "T1574.009",
                "similarity": "0.66"
            },
            {
                "id": "T1578.004",
                "similarity": "0.66"
            },
            {
                "id": "T1584.006",
                "similarity": "0.66"
            },
            {
                "id": "T1588.002",
                "similarity": "0.66"
            },
            {
                "id": "T1588.003",
                "similarity": "0.66"
            },
            {
                "id": "T1588.004",
                "similarity": "0.66"
            },
            {
                "id": "T1592.002",
                "similarity": "0.66"
            },
            {
                "id": "T1595.002",
                "similarity": "0.66"
            },
            {
                "id": "T1608",
                "similarity": "0.66"
            },
            {
                "id": "T1003.002",
                "similarity": "0.65"
            },
            {
                "id": "T1021.004",
                "similarity": "0.65"
            },
            {
                "id": "T1053",
                "similarity": "0.65"
            },
            {
                "id": "T1055.014",
                "similarity": "0.65"
            },
            {
                "id": "T1069.003",
                "similarity": "0.65"
            },
            {
                "id": "T1070",
                "similarity": "0.65"
            },
            {
                "id": "T1110.002",
                "similarity": "0.65"
            },
            {
                "id": "T1123",
                "similarity": "0.65"
            },
            {
                "id": "T1140",
                "similarity": "0.65"
            },
            {
                "id": "T1204.001",
                "similarity": "0.65"
            },
            {
                "id": "T1213",
                "similarity": "0.65"
            },
            {
                "id": "T1218.003",
                "similarity": "0.65"
            },
            {
                "id": "T1218.007",
                "similarity": "0.65"
            },
            {
                "id": "T1218.010",
                "similarity": "0.65"
            },
            {
                "id": "T1222.001",
                "similarity": "0.65"
            },
            {
                "id": "T1491",
                "similarity": "0.65"
            },
            {
                "id": "T1497.002",
                "similarity": "0.65"
            },
            {
                "id": "T1529",
                "similarity": "0.65"
            },
            {
                "id": "T1542.002",
                "similarity": "0.65"
            },
            {
                "id": "T1542.003",
                "similarity": "0.65"
            },
            {
                "id": "T1542.005",
                "similarity": "0.65"
            },
            {
                "id": "T1543.001",
                "similarity": "0.65"
            },
            {
                "id": "T1546.006",
                "similarity": "0.65"
            },
            {
                "id": "T1546.011",
                "similarity": "0.65"
            },
            {
                "id": "T1547.007",
                "similarity": "0.65"
            },
            {
                "id": "T1547.009",
                "similarity": "0.65"
            },
            {
                "id": "T1547.012",
                "similarity": "0.65"
            },
            {
                "id": "T1550.003",
                "similarity": "0.65"
            },
            {
                "id": "T1555.002",
                "similarity": "0.65"
            },
            {
                "id": "T1555.003",
                "similarity": "0.65"
            },
            {
                "id": "T1558.002",
                "similarity": "0.65"
            },
            {
                "id": "T1558.003",
                "similarity": "0.65"
            },
            {
                "id": "T1560",
                "similarity": "0.65"
            },
            {
                "id": "T1560.002",
                "similarity": "0.65"
            },
            {
                "id": "T1562.007",
                "similarity": "0.65"
            },
            {
                "id": "T1564.002",
                "similarity": "0.65"
            },
            {
                "id": "T1564.006",
                "similarity": "0.65"
            },
            {
                "id": "T1566.002",
                "similarity": "0.65"
            },
            {
                "id": "T1568",
                "similarity": "0.65"
            },
            {
                "id": "T1569.002",
                "similarity": "0.65"
            },
            {
                "id": "T1574.001",
                "similarity": "0.65"
            },
            {
                "id": "T1583.002",
                "similarity": "0.65"
            },
            {
                "id": "T1583.004",
                "similarity": "0.65"
            },
            {
                "id": "T1583.005",
                "similarity": "0.65"
            },
            {
                "id": "T1584.003",
                "similarity": "0.65"
            },
            {
                "id": "T1584.005",
                "similarity": "0.65"
            },
            {
                "id": "T1594",
                "similarity": "0.65"
            },
            {
                "id": "T1602.001",
                "similarity": "0.65"
            },
            {
                "id": "T1021.005",
                "similarity": "0.64"
            },
            {
                "id": "T1027",
                "similarity": "0.64"
            },
            {
                "id": "T1033",
                "similarity": "0.64"
            },
            {
                "id": "T1037",
                "similarity": "0.64"
            },
            {
                "id": "T1037.004",
                "similarity": "0.64"
            },
            {
                "id": "T1040",
                "similarity": "0.64"
            },
            {
                "id": "T1041",
                "similarity": "0.64"
            },
            {
                "id": "T1047",
                "similarity": "0.64"
            },
            {
                "id": "T1052",
                "similarity": "0.64"
            },
            {
                "id": "T1052.001",
                "similarity": "0.64"
            },
            {
                "id": "T1055.008",
                "similarity": "0.64"
            },
            {
                "id": "T1056",
                "similarity": "0.64"
            },
            {
                "id": "T1059",
                "similarity": "0.64"
            },
            {
                "id": "T1069",
                "similarity": "0.64"
            },
            {
                "id": "T1080",
                "similarity": "0.64"
            },
            {
                "id": "T1082",
                "similarity": "0.64"
            },
            {
                "id": "T1110.003",
                "similarity": "0.64"
            },
            {
                "id": "T1113",
                "similarity": "0.64"
            },
            {
                "id": "T1119",
                "similarity": "0.64"
            },
            {
                "id": "T1125",
                "similarity": "0.64"
            },
            {
                "id": "T1127",
                "similarity": "0.64"
            },
            {
                "id": "T1197",
                "similarity": "0.64"
            },
            {
                "id": "T1216",
                "similarity": "0.64"
            },
            {
                "id": "T1218.008",
                "similarity": "0.64"
            },
            {
                "id": "T1218.012",
                "similarity": "0.64"
            },
            {
                "id": "T1218.013",
                "similarity": "0.64"
            },
            {
                "id": "T1218.014",
                "similarity": "0.64"
            },
            {
                "id": "T1496",
                "similarity": "0.64"
            },
            {
                "id": "T1498",
                "similarity": "0.64"
            },
            {
                "id": "T1518",
                "similarity": "0.64"
            },
            {
                "id": "T1526",
                "similarity": "0.64"
            },
            {
                "id": "T1542.004",
                "similarity": "0.64"
            },
            {
                "id": "T1543.002",
                "similarity": "0.64"
            },
            {
                "id": "T1546.002",
                "similarity": "0.64"
            },
            {
                "id": "T1546.007",
                "similarity": "0.64"
            },
            {
                "id": "T1546.012",
                "similarity": "0.64"
            },
            {
                "id": "T1547.005",
                "similarity": "0.64"
            },
            {
                "id": "T1547.006",
                "similarity": "0.64"
            },
            {
                "id": "T1547.008",
                "similarity": "0.64"
            },
            {
                "id": "T1550.002",
                "similarity": "0.64"
            },
            {
                "id": "T1552.006",
                "similarity": "0.64"
            },
            {
                "id": "T1553.002",
                "similarity": "0.64"
            },
            {
                "id": "T1556.004",
                "similarity": "0.64"
            },
            {
                "id": "T1560.003",
                "similarity": "0.64"
            },
            {
                "id": "T1562.006",
                "similarity": "0.64"
            },
            {
                "id": "T1564.007",
                "similarity": "0.64"
            },
            {
                "id": "T1564.008",
                "similarity": "0.64"
            },
            {
                "id": "T1574.008",
                "similarity": "0.64"
            },
            {
                "id": "T1578.003",
                "similarity": "0.64"
            },
            {
                "id": "T1583.001",
                "similarity": "0.64"
            },
            {
                "id": "T1583.003",
                "similarity": "0.64"
            },
            {
                "id": "T1585",
                "similarity": "0.64"
            },
            {
                "id": "T1587.001",
                "similarity": "0.64"
            },
            {
                "id": "T1592.004",
                "similarity": "0.64"
            },
            {
                "id": "T1596",
                "similarity": "0.64"
            },
            {
                "id": "T1608.002",
                "similarity": "0.64"
            },
            {
                "id": "T1001.001",
                "similarity": "0.63"
            },
            {
                "id": "T1003.004",
                "similarity": "0.63"
            },
            {
                "id": "T1003.005",
                "similarity": "0.63"
            },
            {
                "id": "T1003.007",
                "similarity": "0.63"
            },
            {
                "id": "T1003.008",
                "similarity": "0.63"
            },
            {
                "id": "T1005",
                "similarity": "0.63"
            },
            {
                "id": "T1006",
                "similarity": "0.63"
            },
            {
                "id": "T1011",
                "similarity": "0.63"
            },
            {
                "id": "T1014",
                "similarity": "0.63"
            },
            {
                "id": "T1021.002",
                "similarity": "0.63"
            },
            {
                "id": "T1021.006",
                "similarity": "0.63"
            },
            {
                "id": "T1027.002",
                "similarity": "0.63"
            },
            {
                "id": "T1027.003",
                "similarity": "0.63"
            },
            {
                "id": "T1030",
                "similarity": "0.63"
            },
            {
                "id": "T1048.003",
                "similarity": "0.63"
            },
            {
                "id": "T1053.002",
                "similarity": "0.63"
            },
            {
                "id": "T1055.002",
                "similarity": "0.63"
            },
            {
                "id": "T1055.005",
                "similarity": "0.63"
            },
            {
                "id": "T1055.009",
                "similarity": "0.63"
            },
            {
                "id": "T1059.001",
                "similarity": "0.63"
            },
            {
                "id": "T1087.004",
                "similarity": "0.63"
            },
            {
                "id": "T1092",
                "similarity": "0.63"
            },
            {
                "id": "T1102.002",
                "similarity": "0.63"
            },
            {
                "id": "T1102.003",
                "similarity": "0.63"
            },
            {
                "id": "T1112",
                "similarity": "0.63"
            },
            {
                "id": "T1137.004",
                "similarity": "0.63"
            },
            {
                "id": "T1218",
                "similarity": "0.63"
            },
            {
                "id": "T1218.001",
                "similarity": "0.63"
            },
            {
                "id": "T1218.002",
                "similarity": "0.63"
            },
            {
                "id": "T1218.009",
                "similarity": "0.63"
            },
            {
                "id": "T1482",
                "similarity": "0.63"
            },
            {
                "id": "T1484.001",
                "similarity": "0.63"
            },
            {
                "id": "T1490",
                "similarity": "0.63"
            },
            {
                "id": "T1498.002",
                "similarity": "0.63"
            },
            {
                "id": "T1518.001",
                "similarity": "0.63"
            },
            {
                "id": "T1535",
                "similarity": "0.63"
            },
            {
                "id": "T1543.004",
                "similarity": "0.63"
            },
            {
                "id": "T1547.004",
                "similarity": "0.63"
            },
            {
                "id": "T1547.010",
                "similarity": "0.63"
            },
            {
                "id": "T1547.011",
                "similarity": "0.63"
            },
            {
                "id": "T1547.015",
                "similarity": "0.63"
            },
            {
                "id": "T1552.001",
                "similarity": "0.63"
            },
            {
                "id": "T1552.003",
                "similarity": "0.63"
            },
            {
                "id": "T1552.004",
                "similarity": "0.63"
            },
            {
                "id": "T1552.007",
                "similarity": "0.63"
            },
            {
                "id": "T1553.005",
                "similarity": "0.63"
            },
            {
                "id": "T1555",
                "similarity": "0.63"
            },
            {
                "id": "T1555.001",
                "similarity": "0.63"
            },
            {
                "id": "T1556.002",
                "similarity": "0.63"
            },
            {
                "id": "T1559.002",
                "similarity": "0.63"
            },
            {
                "id": "T1564",
                "similarity": "0.63"
            },
            {
                "id": "T1567",
                "similarity": "0.63"
            },
            {
                "id": "T1567.002",
                "similarity": "0.63"
            },
            {
                "id": "T1574.002",
                "similarity": "0.63"
            },
            {
                "id": "T1574.007",
                "similarity": "0.63"
            },
            {
                "id": "T1583.006",
                "similarity": "0.63"
            },
            {
                "id": "T1585.002",
                "similarity": "0.63"
            },
            {
                "id": "T1587.003",
                "similarity": "0.63"
            },
            {
                "id": "T1590.001",
                "similarity": "0.63"
            },
            {
                "id": "T1591.002",
                "similarity": "0.63"
            },
            {
                "id": "T1591.004",
                "similarity": "0.63"
            },
            {
                "id": "T1592",
                "similarity": "0.63"
            },
            {
                "id": "T1592.001",
                "similarity": "0.63"
            },
            {
                "id": "T1596.003",
                "similarity": "0.63"
            },
            {
                "id": "T1596.005",
                "similarity": "0.63"
            },
            {
                "id": "T1597.002",
                "similarity": "0.63"
            },
            {
                "id": "T1599",
                "similarity": "0.63"
            },
            {
                "id": "T1608.003",
                "similarity": "0.63"
            },
            {
                "id": "T1611",
                "similarity": "0.63"
            },
            {
                "id": "T1001.003",
                "similarity": "0.62"
            },
            {
                "id": "T1012",
                "similarity": "0.62"
            },
            {
                "id": "T1020",
                "similarity": "0.62"
            },
            {
                "id": "T1021.003",
                "similarity": "0.62"
            },
            {
                "id": "T1027.001",
                "similarity": "0.62"
            },
            {
                "id": "T1036",
                "similarity": "0.62"
            },
            {
                "id": "T1037.003",
                "similarity": "0.62"
            },
            {
                "id": "T1046",
                "similarity": "0.62"
            },
            {
                "id": "T1048",
                "similarity": "0.62"
            },
            {
                "id": "T1048.002",
                "similarity": "0.62"
            },
            {
                "id": "T1053.007",
                "similarity": "0.62"
            },
            {
                "id": "T1055",
                "similarity": "0.62"
            },
            {
                "id": "T1059.005",
                "similarity": "0.62"
            },
            {
                "id": "T1059.006",
                "similarity": "0.62"
            },
            {
                "id": "T1070.004",
                "similarity": "0.62"
            },
            {
                "id": "T1090.003",
                "similarity": "0.62"
            },
            {
                "id": "T1102.001",
                "similarity": "0.62"
            },
            {
                "id": "T1105",
                "similarity": "0.62"
            },
            {
                "id": "T1136.001",
                "similarity": "0.62"
            },
            {
                "id": "T1202",
                "similarity": "0.62"
            },
            {
                "id": "T1213.002",
                "similarity": "0.62"
            },
            {
                "id": "T1217",
                "similarity": "0.62"
            },
            {
                "id": "T1219",
                "similarity": "0.62"
            },
            {
                "id": "T1497",
                "similarity": "0.62"
            },
            {
                "id": "T1499.001",
                "similarity": "0.62"
            },
            {
                "id": "T1505.002",
                "similarity": "0.62"
            },
            {
                "id": "T1542.001",
                "similarity": "0.62"
            },
            {
                "id": "T1546.005",
                "similarity": "0.62"
            },
            {
                "id": "T1552.002",
                "similarity": "0.62"
            },
            {
                "id": "T1555.004",
                "similarity": "0.62"
            },
            {
                "id": "T1558.001",
                "similarity": "0.62"
            },
            {
                "id": "T1562.002",
                "similarity": "0.62"
            },
            {
                "id": "T1564.005",
                "similarity": "0.62"
            },
            {
                "id": "T1564.009",
                "similarity": "0.62"
            },
            {
                "id": "T1566",
                "similarity": "0.62"
            },
            {
                "id": "T1567.001",
                "similarity": "0.62"
            },
            {
                "id": "T1570",
                "similarity": "0.62"
            },
            {
                "id": "T1573",
                "similarity": "0.62"
            },
            {
                "id": "T1583",
                "similarity": "0.62"
            },
            {
                "id": "T1587",
                "similarity": "0.62"
            },
            {
                "id": "T1589",
                "similarity": "0.62"
            },
            {
                "id": "T1589.003",
                "similarity": "0.62"
            },
            {
                "id": "T1591.003",
                "similarity": "0.62"
            },
            {
                "id": "T1592.003",
                "similarity": "0.62"
            },
            {
                "id": "T1595",
                "similarity": "0.62"
            },
            {
                "id": "T1595.001",
                "similarity": "0.62"
            },
            {
                "id": "T1599.001",
                "similarity": "0.62"
            },
            {
                "id": "T1600.001",
                "similarity": "0.62"
            },
            {
                "id": "T1610",
                "similarity": "0.62"
            },
            {
                "id": "T1612",
                "similarity": "0.62"
            },
            {
                "id": "T1115",
                "similarity": "0.62"
            },
            {
                "id": "T1020.001",
                "similarity": "0.61"
            },
            {
                "id": "T1027.004",
                "similarity": "0.61"
            },
            {
                "id": "T1036.001",
                "similarity": "0.61"
            },
            {
                "id": "T1049",
                "similarity": "0.61"
            },
            {
                "id": "T1053.005",
                "similarity": "0.61"
            },
            {
                "id": "T1053.006",
                "similarity": "0.61"
            },
            {
                "id": "T1055.001",
                "similarity": "0.61"
            },
            {
                "id": "T1069.002",
                "similarity": "0.61"
            },
            {
                "id": "T1087",
                "similarity": "0.61"
            },
            {
                "id": "T1090.001",
                "similarity": "0.61"
            },
            {
                "id": "T1114",
                "similarity": "0.61"
            },
            {
                "id": "T1127.001",
                "similarity": "0.61"
            },
            {
                "id": "T1137.002",
                "similarity": "0.61"
            },
            {
                "id": "T1495",
                "similarity": "0.61"
            },
            {
                "id": "T1497.001",
                "similarity": "0.61"
            },
            {
                "id": "T1498.001",
                "similarity": "0.61"
            },
            {
                "id": "T1542",
                "similarity": "0.61"
            },
            {
                "id": "T1547.002",
                "similarity": "0.61"
            },
            {
                "id": "T1547.013",
                "similarity": "0.61"
            },
            {
                "id": "T1562.009",
                "similarity": "0.61"
            },
            {
                "id": "T1564.004",
                "similarity": "0.61"
            },
            {
                "id": "T1574.006",
                "similarity": "0.61"
            },
            {
                "id": "T1574.012",
                "similarity": "0.61"
            },
            {
                "id": "T1585.001",
                "similarity": "0.61"
            },
            {
                "id": "T1587.002",
                "similarity": "0.61"
            },
            {
                "id": "T1590.002",
                "similarity": "0.61"
            },
            {
                "id": "T1590.003",
                "similarity": "0.61"
            },
            {
                "id": "T1590.006",
                "similarity": "0.61"
            },
            {
                "id": "T1591",
                "similarity": "0.61"
            },
            {
                "id": "T1593.002",
                "similarity": "0.61"
            },
            {
                "id": "T1596.001",
                "similarity": "0.61"
            },
            {
                "id": "T1596.002",
                "similarity": "0.61"
            },
            {
                "id": "T1596.004",
                "similarity": "0.61"
            },
            {
                "id": "T1597",
                "similarity": "0.61"
            },
            {
                "id": "T1600.002",
                "similarity": "0.61"
            },
            {
                "id": "T1602.002",
                "similarity": "0.61"
            },
            {
                "id": "T1609",
                "similarity": "0.61"
            },
            {
                "id": "T1613",
                "similarity": "0.61"
            },
            {
                "id": "T1614.001",
                "similarity": "0.61"
            },
            {
                "id": "T1007",
                "similarity": "0.60"
            },
            {
                "id": "T1027.006",
                "similarity": "0.60"
            },
            {
                "id": "T1037.002",
                "similarity": "0.60"
            },
            {
                "id": "T1053.003",
                "similarity": "0.60"
            },
            {
                "id": "T1057",
                "similarity": "0.60"
            },
            {
                "id": "T1059.002",
                "similarity": "0.60"
            },
            {
                "id": "T1059.004",
                "similarity": "0.60"
            },
            {
                "id": "T1059.007",
                "similarity": "0.60"
            },
            {
                "id": "T1070.003",
                "similarity": "0.60"
            },
            {
                "id": "T1071.004",
                "similarity": "0.60"
            },
            {
                "id": "T1106",
                "similarity": "0.60"
            },
            {
                "id": "T1114.001",
                "similarity": "0.60"
            },
            {
                "id": "T1114.002",
                "similarity": "0.60"
            },
            {
                "id": "T1137.001",
                "similarity": "0.60"
            },
            {
                "id": "T1205.001",
                "similarity": "0.60"
            },
            {
                "id": "T1216.001",
                "similarity": "0.60"
            },
            {
                "id": "T1218.004",
                "similarity": "0.60"
            },
            {
                "id": "T1221",
                "similarity": "0.60"
            },
            {
                "id": "T1480",
                "similarity": "0.60"
            },
            {
                "id": "T1497.003",
                "similarity": "0.60"
            },
            {
                "id": "T1505.003",
                "similarity": "0.60"
            },
            {
                "id": "T1547.003",
                "similarity": "0.60"
            },
            {
                "id": "T1559",
                "similarity": "0.60"
            },
            {
                "id": "T1568.002",
                "similarity": "0.60"
            },
            {
                "id": "T1572",
                "similarity": "0.60"
            },
            {
                "id": "T1590",
                "similarity": "0.60"
            },
            {
                "id": "T1590.005",
                "similarity": "0.60"
            },
            {
                "id": "T1593",
                "similarity": "0.60"
            },
            {
                "id": "T1598.002",
                "similarity": "0.60"
            },
            {
                "id": "T1600",
                "similarity": "0.60"
            },
            {
                "id": "T1601.002",
                "similarity": "0.60"
            },
            {
                "id": "T1135",
                "similarity": "0.60"
            },
            {
                "id": "T1001.002",
                "similarity": "0.59"
            },
            {
                "id": "T1010",
                "similarity": "0.59"
            },
            {
                "id": "T1011.001",
                "similarity": "0.59"
            },
            {
                "id": "T1016.001",
                "similarity": "0.59"
            },
            {
                "id": "T1036.004",
                "similarity": "0.59"
            },
            {
                "id": "T1036.007",
                "similarity": "0.59"
            },
            {
                "id": "T1048.001",
                "similarity": "0.59"
            },
            {
                "id": "T1069.001",
                "similarity": "0.59"
            },
            {
                "id": "T1070.001",
                "similarity": "0.59"
            },
            {
                "id": "T1070.002",
                "similarity": "0.59"
            },
            {
                "id": "T1087.003",
                "similarity": "0.59"
            },
            {
                "id": "T1090",
                "similarity": "0.59"
            },
            {
                "id": "T1090.002",
                "similarity": "0.59"
            },
            {
                "id": "T1102",
                "similarity": "0.59"
            },
            {
                "id": "T1104",
                "similarity": "0.59"
            },
            {
                "id": "T1137.003",
                "similarity": "0.59"
            },
            {
                "id": "T1564.003",
                "similarity": "0.59"
            },
            {
                "id": "T1569.001",
                "similarity": "0.59"
            },
            {
                "id": "T1573.002",
                "similarity": "0.59"
            },
            {
                "id": "T1589.002",
                "similarity": "0.59"
            },
            {
                "id": "T1591.001",
                "similarity": "0.59"
            },
            {
                "id": "T1593.001",
                "similarity": "0.59"
            },
            {
                "id": "T1598.001",
                "similarity": "0.59"
            },
            {
                "id": "T1601.001",
                "similarity": "0.59"
            },
            {
                "id": "T1620",
                "similarity": "0.59"
            },
            {
                "id": "T1008",
                "similarity": "0.58"
            },
            {
                "id": "T1036.006",
                "similarity": "0.58"
            },
            {
                "id": "T1037.005",
                "similarity": "0.58"
            },
            {
                "id": "T1070.005",
                "similarity": "0.58"
            },
            {
                "id": "T1071",
                "similarity": "0.58"
            },
            {
                "id": "T1071.001",
                "similarity": "0.58"
            },
            {
                "id": "T1071.003",
                "similarity": "0.58"
            },
            {
                "id": "T1074",
                "similarity": "0.58"
            },
            {
                "id": "T1074.002",
                "similarity": "0.58"
            },
            {
                "id": "T1083",
                "similarity": "0.58"
            },
            {
                "id": "T1120",
                "similarity": "0.58"
            },
            {
                "id": "T1137.006",
                "similarity": "0.58"
            },
            {
                "id": "T1499",
                "similarity": "0.58"
            },
            {
                "id": "T1548.003",
                "similarity": "0.58"
            },
            {
                "id": "T1558.004",
                "similarity": "0.58"
            },
            {
                "id": "T1590.004",
                "similarity": "0.58"
            },
            {
                "id": "T1597.001",
                "similarity": "0.58"
            },
            {
                "id": "T1598.003",
                "similarity": "0.58"
            },
            {
                "id": "T1614",
                "similarity": "0.58"
            },
            {
                "id": "T1074.001",
                "similarity": "0.58"
            },
            {
                "id": "T1016",
                "similarity": "0.57"
            },
            {
                "id": "T1029",
                "similarity": "0.57"
            },
            {
                "id": "T1036.005",
                "similarity": "0.57"
            },
            {
                "id": "T1037.001",
                "similarity": "0.57"
            },
            {
                "id": "T1071.002",
                "similarity": "0.57"
            },
            {
                "id": "T1095",
                "similarity": "0.57"
            },
            {
                "id": "T1189",
                "similarity": "0.57"
            },
            {
                "id": "T1480.001",
                "similarity": "0.57"
            },
            {
                "id": "T1547.001",
                "similarity": "0.57"
            },
            {
                "id": "T1559.001",
                "similarity": "0.57"
            },
            {
                "id": "T1571",
                "similarity": "0.57"
            },
            {
                "id": "T1573.001",
                "similarity": "0.57"
            },
            {
                "id": "T1598",
                "similarity": "0.57"
            },
            {
                "id": "T1059.003",
                "similarity": "0.56"
            },
            {
                "id": "T1070.006",
                "similarity": "0.56"
            },
            {
                "id": "T1129",
                "similarity": "0.56"
            },
            {
                "id": "T1564.001",
                "similarity": "0.56"
            },
            {
                "id": "T1001",
                "similarity": "0.55"
            },
            {
                "id": "T1036.002",
                "similarity": "0.55"
            },
            {
                "id": "T1087.001",
                "similarity": "0.55"
            },
            {
                "id": "T1087.002",
                "similarity": "0.55"
            },
            {
                "id": "T1124",
                "similarity": "0.55"
            },
            {
                "id": "T1568.001",
                "similarity": "0.55"
            },
            {
                "id": "T1574.011",
                "similarity": "0.55"
            },
            {
                "id": "T1132.002",
                "similarity": "0.55"
            },
            {
                "id": "T1619",
                "similarity": "0.55"
            },
            {
                "id": "T1003.001",
                "similarity": "0.54"
            },
            {
                "id": "T1018",
                "similarity": "0.54"
            },
            {
                "id": "T1220",
                "similarity": "0.53"
            },
            {
                "id": "T1213.001",
                "similarity": "0.53"
            },
            {
                "id": "T1055.013",
                "similarity": "0.52"
            },
            {
                "id": "T1090.004",
                "similarity": "0.52"
            },
            {
                "id": "T1568.003",
                "similarity": "0.52"
            },
            {
                "id": "T1132",
                "similarity": "0.51"
            },
            {
                "id": "T1546.004",
                "similarity": "0.51"
            },
            {
                "id": "T1187",
                "similarity": "0.51"
            },
            {
                "id": "T1137",
                "similarity": "0.51"
            },
            {
                "id": "T1553.006",
                "similarity": "0.51"
            },
            {
                "id": "T1132.001",
                "similarity": "0.50"
            }
        ]

    rag = APTRagSystem("./data/apt_data.json")
    matching_groups = rag.calculate_ttp_match(ttp_list)
    print(json.dumps(matching_groups[-1], indent=2))

