import os
import requests
from pymongo import MongoClient
import numpy as np
import pandas as pd
import logging
from dotenv import load_dotenv
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
import seaborn as sns

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
)
logger = logging.getLogger(__name__)

def extract_behavioral_features(doc):
    """Extract behavioral features from a MongoDB document."""
    features = {}
    
    summary = doc.get('summary', {})
    network = doc.get('network', {})
    
    # Example features from summary
    features['files_created'] = len(summary.get('file_created', []))
    features['files_written'] = len(summary.get('file_written', []))
    features['files_opened'] = len(summary.get('file_opened', []))
    features['dlls_loaded'] = len(summary.get('dll_loaded', []))
    features['commands_executed'] = len(summary.get('command_line', []))
    features['guids'] = len(summary.get('guid', []))
    features['files_failed'] = len(summary.get('file_failed', []))
    features['files_recreated'] = len(summary.get('file_recreated', []))

    # Example features from network
    features['dns_lookups'] = len(network.get('dns', []))
    features['tcp_connections'] = len(network.get('tcp', []))
    features['udp_connections'] = len(network.get('udp', []))
    features['http_requests'] = len(network.get('http', []))
    features['domains_contacted'] = len(network.get('domains', []))
    features['hosts_contacted'] = len(network.get('hosts', []))

    # You can extract more features based on available data and domain knowledge
    return features

def get_malware_type_from_virustotal(file_hash):
    """Query VirusTotal for malware type using file hash."""
    API_KEY = 'FOytx62i6L4AtkVLAdIEH3CBic14Njtp'  # Replace with your VirusTotal API key
    url = f'https://virusshare.com/apiv2/malware?apikey={API_KEY}&hash={file_hash}'
    
    response = requests.get(url)
    print(f"Response Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        # Extract the malware type from the response
        malware_type = data.get('response', {}).get('malware_type', 'Unknown')
        return malware_type
    elif response.status_code == 204:
        logger.warning("Rate limit exceeded. Waiting for 15 seconds.")
        time.sleep(15)  # Wait for 15 seconds before retrying
        return get_malware_type_from_virusshare(file_hash)
    else:
        logger.warning(f"VirusShare query failed for hash {file_hash}: {response.status_code}")
        return 'Unknown'
        # Extract the malware type from the response
    #     malware_type = data['data']['attributes'].get('popular_threat_classification', {}).get('suggested_threat_label', 'Unknown')
    #     print(malware_type)
    #     return malware_type
    # else:
    #     logger.warning(f"VirusTotal query failed for hash {file_hash}: {response.status_code}")
    #     return 'Unknown'

def assign_malware_category(features):
    """Assign a malware category based on behavioral features."""
    # Example heuristic rules (adjust these rules based on your domain knowledge)
    if features['files_created'] > 50 and features['files_written'] > 100:
        return 'Ransomware'
    elif features['tcp_connections'] > 10 and features['dns_lookups'] > 5:
        return 'Botnet'
    elif features['commands_executed'] > 5:
        return 'Trojan'
    elif features['http_requests'] > 20:
        return 'Adware'
    else:
        return 'Other'

def load_embeddings_and_features_from_mongodb(use_virustotal=False):
    """Connect to MongoDB and retrieve embeddings and behavioral features."""
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI')
    if not MONGO_URI:
        logger.error("MONGO_URI not found in environment variables.")
        raise ValueError("MONGO_URI not provided.")

    # Connect to MongoDB
    client = MongoClient(MONGO_URI)
    db = client['cuckoo']
    collection = db['malware_analysis']

    # Query to retrieve all documents with embeddings
    logger.info("Fetching embeddings and behavioral features from MongoDB...")
    cursor = collection.find({"graph_embedding": {"$exists": True}})

    embeddings = []
    task_ids = []
    md5_hashes = []
    behavioral_features_list = []
    malware_types = []

    for doc in cursor:
        embedding = doc.get('graph_embedding')
        if embedding:
            embeddings.append(embedding)
            task_ids.append(doc.get('task_id'))
            features = extract_behavioral_features(doc)
            behavioral_features_list.append(features)
            # Get MD5 hash
            md5_hash = doc.get('target', {}).get('file', {}).get('md5')
            print(md5_hash)
            md5_hashes.append(md5_hash)
            # Get malware type
            if use_virustotal:
                # Get malware type from VirusTotal
                malware_type = get_malware_type_from_virustotal(md5_hash)
                print(malware_type)
            else:
                # Assign malware type using heuristic rules
                malware_type = assign_malware_category(features)
            malware_types.append(malware_type)
        else:
            logger.warning(f"No embedding found for document with _id: {doc['_id']}")

    embeddings_array = np.array(embeddings)
    behavioral_features_df = pd.DataFrame(behavioral_features_list)
    logger.info(f"Total embeddings fetched: {len(embeddings_array)}")

    return embeddings_array, task_ids, md5_hashes, behavioral_features_df, malware_types

def determine_optimal_k(embeddings_scaled):
    """Determine the optimal number of clusters using the Elbow Method."""
    inertia = []
    K = range(1, 11)
    for k in K:
        kmeans = KMeans(n_clusters=k, random_state=42)
        kmeans.fit(embeddings_scaled)
        inertia.append(kmeans.inertia_)
    plt.figure(figsize=(8, 4))
    plt.plot(K, inertia, 'bx-')
    plt.xlabel('Number of clusters (k)')
    plt.ylabel('Inertia')
    plt.title('Elbow Method For Optimal k')
    plt.show()

def visualize_clusters_pca(embeddings_scaled, cluster_labels, malware_categories):
    """Visualize clusters using PCA and color-code by inferred malware categories."""
    # Perform PCA to reduce dimensions to 2D
    pca = PCA(n_components=2)
    embeddings_2d = pca.fit_transform(embeddings_scaled)

    plt.figure(figsize=(12, 8))
    sns.scatterplot(
        x=embeddings_2d[:, 0],
        y=embeddings_2d[:, 1],
        hue=malware_categories,
        style=cluster_labels,
        palette='tab10',
        s=100,
        alpha=0.7
    )
    plt.title('PCA Visualization of Malware Embeddings by Inferred Malware Category')
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')
    plt.legend(title='Malware Category')
    plt.show()

def evaluate_clustering(embeddings_scaled, cluster_labels):
    """Evaluate clustering performance using Silhouette Score."""
    if len(set(cluster_labels)) > 1:
        silhouette_avg = silhouette_score(embeddings_scaled, cluster_labels)
        print(f"The average silhouette_score is : {silhouette_avg}")
    else:
        print("Cannot compute silhouette score with only one cluster.")

def update_clusters_in_mongodb(task_ids, cluster_labels, malware_types):
    """Update the MongoDB documents with the cluster labels and malware types."""
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI')
    client = MongoClient(MONGO_URI)
    db = client['malware_analysis']
    collection = db['prev_sample']

    for task_id, cluster_label, malware_type in zip(task_ids, cluster_labels, malware_types):
        result = collection.update_one(
            {'task_id': task_id},
            {'$set': {
                'cluster_label': int(cluster_label),
                'malware_type': malware_type
            }}
        )
        if result.modified_count > 0:
            logger.info(f"Updated task_id {task_id} with cluster_label {cluster_label} and malware_type {malware_type}")
        else:
            logger.warning(f"Failed to update task_id {task_id}")

def main():
    # Set to True if you want to use VirusTotal for malware type identification
    use_virustotal = True  # Set to True if you have an API key and want to use VirusTotal

    # Step 1: Load embeddings, behavioral features, and malware types from MongoDB
    embeddings_array, task_ids, md5_hashes, behavioral_features_df, malware_types = load_embeddings_and_features_from_mongodb(use_virustotal=use_virustotal)

    # if embeddings_array.size == 0:
    #     logger.error("No embeddings found. Exiting.")
    #     return

    # # Step 2: Prepare the data for clustering
    # scaler = StandardScaler()
    # embeddings_scaled = scaler.fit_transform(embeddings_array)

    # # Optional: Determine the optimal number of clusters
    # # determine_optimal_k(embeddings_scaled)

    # # Step 3: Train K-Means clustering
    # k = 4  # Adjust this number based on your dataset and analysis
    # kmeans = KMeans(n_clusters=k, random_state=42)
    # cluster_labels = kmeans.fit_predict(embeddings_scaled)

    # # Step 4: Analyze and interpret the clusters
    # # Create a DataFrame that includes embeddings, cluster labels, task IDs, and behavioral features
    # df = pd.DataFrame(embeddings_scaled)
    # df['cluster'] = cluster_labels
    # df['task_id'] = task_ids
    # df['md5_hash'] = md5_hashes
    # df = pd.concat([df, behavioral_features_df], axis=1)
    # df['malware_type'] = malware_types

    # # Print cluster information
    # for cluster in sorted(df['cluster'].unique()):
    #     cluster_samples = df[df['cluster'] == cluster]
    #     print(f"Cluster {cluster} contains {len(cluster_samples)} samples.")
    #     print("Malware types in this cluster:")
    #     print(cluster_samples['malware_type'].value_counts())
    #     print("Average behavioral features in this cluster:")
    #     print(cluster_samples[behavioral_features_df.columns].mean())
    #     print("-" * 60)

    # # Optional: Evaluate clustering performance
    # evaluate_clustering(embeddings_scaled, cluster_labels)

    # # Visualize clusters using PCA
    # visualize_clusters_pca(embeddings_scaled, cluster_labels, df['malware_type'])

    # # Update MongoDB with cluster labels and inferred malware types
    # update_clusters_in_mongodb(task_ids, cluster_labels, malware_types)

if __name__ == "__main__":
    main()
