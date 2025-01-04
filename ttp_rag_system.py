import json
import numpy as np
from typing import List, Dict
import requests
from sklearn.metrics.pairwise import cosine_similarity

# Global configurations
SIMILARITY_THRESHOLD = 0.5
CHUNK_SIZE = 512  # Adjust based on your needs
OLLAMA_BASE_URL = "http://localhost:11434/api"
EMBEDDING_MODEL = "nomic-embed-text"  # Changed to a proper embedding model
LLM_MODEL = "llama3.2"

class RAGSystem_ttp:
    def __init__(self, json_file_path: str):
        self.vector_db = []
        self.json_file_path = json_file_path
        self.load_and_process_json()

    def get_embedding(self, text: str) -> List[float]:
        """Get embeddings using nomic-embed-text"""
        response = requests.post(
            f"{OLLAMA_BASE_URL}/embeddings",
            json={"model": EMBEDDING_MODEL, "prompt": text}
        )
        if response.status_code != 200:
            raise Exception(f"Error getting embedding: {response.text}")
        return response.json()["embedding"]

    def load_and_process_json(self):
        """Load JSON and create vector database"""
        with open(self.json_file_path, 'r') as file:
            data = json.load(file)
        
        for item in data:
            # Combine kill chain phase and description for embedding
            combined_text = f"{item['kill chain phases']} {item['description']}"
            embedding = self.get_embedding(combined_text)
            
            self.vector_db.append({
                'id': item['id'],
                'embedding': embedding,
                'original_data': item
            })

    # def find_similar_documents(self, query: Dict) -> List[Dict]:
    #     """Find similar documents based on query"""
    #     # Combine query fields
    #     query_text = f"{query['kill chain phases']} {query['description']}"
    #     query_embedding = self.get_embedding(query_text)

    #     results = []
    #     for doc in self.vector_db:
    #         similarity = cosine_similarity(
    #             [query_embedding], 
    #             [doc['embedding']]
    #         )[0][0]
            
    #         if similarity >= SIMILARITY_THRESHOLD:
    #             results.append({
    #                 'id': doc['id'],
    #                 'similarity': f"{similarity:.2f}"
    #             })

    #     # Sort by similarity score
    #     results.sort(key=lambda x: float(x['similarity']), reverse=True)
    #     return results


    def find_similar_documents(self, queries: List[Dict]) -> List[Dict]:
        """Find similar documents based on multiple queries
        
        Args:
            queries (List[Dict]): List of dictionaries, each containing 'kill chain phases' and 'description'
        
        Returns:
            List[Dict]: List of matching documents with their similarity scores
        """
        all_results = {}  # Use dictionary to track highest similarity per document

        for query in queries:
            # Combine query fields
            query_text = f"{query['kill chain phases']} {query['description']}"
            query_embedding = self.get_embedding(query_text)

            for doc in self.vector_db:
                similarity = cosine_similarity(
                    [query_embedding],
                    [doc['embedding']]
                )[0][0]

                # If document meets threshold and either hasn't been seen before
                # or new similarity is higher than previous
                if similarity >= SIMILARITY_THRESHOLD:
                    doc_id = doc['id']
                    if doc_id not in all_results or float(all_results[doc_id]['similarity']) < similarity:
                        all_results[doc_id] = {
                            'id': doc_id,
                            'similarity': f"{similarity:.2f}"
                        }

        # Convert dictionary to list and sort by similarity
        results = list(all_results.values())
        results.sort(key=lambda x: float(x['similarity']), reverse=True)
        
        return results


    def query_llm(self, prompt: str, context: List[Dict]) -> str:
        """Query LLM with context"""
        context_str = json.dumps(context)
        full_prompt = f"""Context: {context_str}\n\nQuestion: {prompt}\n\nAnswer:"""
        
        response = requests.post(
            f"{OLLAMA_BASE_URL}/generate",
            json={"model": LLM_MODEL, "prompt": full_prompt}
        )
        print (response.json())
        # return response.json()["response"]


