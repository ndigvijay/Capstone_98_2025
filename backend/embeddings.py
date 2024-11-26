import os
import pickle
from karateclub import Graph2Vec
from pymongo import MongoClient, UpdateOne
import networkx as nx
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
    handlers=[
        logging.FileHandler("extract_embeddings.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_graphs(graphs_directory):
    graphs = []
    graph_ids = []
    
    for filename in os.listdir(graphs_directory):
        if filename.endswith(".gpickle"):
            graph_path = os.path.join(graphs_directory, filename)
            try:
                with open(graph_path, 'rb') as f:
                    G = pickle.load(f)  # Load graph using pickle
                # Convert node labels to integers to ensure compatibility
                G = nx.convert_node_labels_to_integers(G, label_attribute="original_label")
                graphs.append(G)
                
                # Extract task_id from filename (assuming format 'graph_{task_id}.gpickle')
                task_id_str = filename.replace("graph_", "").replace(".gpickle", "")
                task_id = int(task_id_str)
                graph_ids.append(task_id)
                
                logger.info(f"Loaded and reindexed graph for task_id: {task_id}")
            except Exception as e:
                logger.error(f"Failed to load graph from {graph_path}: {e}")
    return graphs, graph_ids

def main():
    # Load environment variables
    load_dotenv()
    
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI')
    if not MONGO_URI:
        logger.error("MONGO_URI not found in environment variables.")
        raise ValueError("MONGO_URI not provided.")
    
    client = MongoClient(MONGO_URI, socketTimeoutMS=30000)
    db = client['malware_analysis']
    collection = db['test']
    
    # Directory where serialized graphs are stored
    graphs_directory = "graphs"
    
    # Load all graphs
    logger.info("Loading graphs...")
    graphs, graph_ids = load_graphs(graphs_directory)
    
    if not graphs:
        logger.error("No graphs found to process.")
        return
    
    # Initialize Graph2Vec
    logger.info("Initializing Graph2Vec with reduced dimensions to save memory...")
    g2v = Graph2Vec(dimensions=256, workers=4, min_count=1, epochs=100)
    
    # Process in batches
    batch_size = 10  # Adjust this based on available memory
    for i in range(0, len(graph_ids), batch_size):
        batch_graphs = graphs[i:i + batch_size]
        batch_ids = graph_ids[i:i + batch_size]

        # Fit Graph2Vec on the batch
        logger.info(f"Training Graph2Vec model for batch {i // batch_size + 1}...")
        g2v.fit(batch_graphs)
        batch_embeddings = g2v.get_embedding()

        # Store embeddings in MongoDB in a batch
        logger.info("Storing batch embeddings to MongoDB...")
        requests = [
            UpdateOne({'task_id': task_id}, {'$set': {'graph_embedding': embedding.tolist()}})
            for task_id, embedding in zip(batch_ids, batch_embeddings)
        ]
        
        if requests:
            try:
                collection.bulk_write(requests)
                logger.info(f"Completed batch {i // batch_size + 1}")
            except Exception as e:
                logger.error(f"Failed to store batch {i // batch_size + 1} embeddings: {e}")
    
    logger.info("Graph2Vec embedding extraction completed.")

if __name__ == "__main__":
    main()
