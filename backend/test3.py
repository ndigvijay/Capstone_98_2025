import os
import requests
import numpy as np
import pandas as pd
import logging
import time
import json
from dotenv import load_dotenv
from pymongo import MongoClient
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import matplotlib.pyplot as plt

# Load environment variables from .env file
load_dotenv()

# Retrieve the VirusShare API key from environment variables
API_KEY = os.getenv('VIRUSSHARE_API_KEY')
if not API_KEY:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
    )
    logger = logging.getLogger(__name__)
    logger.error("VIRUSSHARE_API_KEY not found in environment variables.")
    raise ValueError("VIRUSSHARE_API_KEY not provided.")

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format='%(asctime)s %(levelname)s: %(message)s',
)
logger = logging.getLogger(__name__)

def infer_malware_type(malware_names):
    """
    Infer malware type from a list of malware detection names.
    """
    malware_types = set()
    for name in malware_names:
        name_upper = name.upper()
        if 'TROJAN' in name_upper:
            malware_types.add('Trojan')
        if 'RANSOM' in name_upper or 'CRYPT' in name_upper:
            malware_types.add('Ransomware')
        if 'WORM' in name_upper:
            malware_types.add('Worm')
        if 'ADWARE' in name_upper:
            malware_types.add('Adware')
        if 'SPYWARE' in name_upper:
            malware_types.add('Spyware')
        if 'BACKDOOR' in name_upper:
            malware_types.add('Backdoor')
        if 'PHISH' in name_upper:
            malware_types.add('Phishing')
        if 'ROOTKIT' in name_upper:
            malware_types.add('Rootkit')
        if 'KEYLOGGER' in name_upper:
            malware_types.add('Keylogger')
        if 'DROPPER' in name_upper:
            malware_types.add('Dropper')
        if ('MINER' in name_upper or 'COIN' in name_upper or 
            'BITCOIN' in name_upper or 'COINHIVE' in name_upper):
            malware_types.add('Cryptocurrency Miner')
        # Add more conditions as needed
    if malware_types:
        return ', '.join(malware_types)
    else:
        return 'Unknown'

def extract_behavioral_features(doc):
    """
    Extract behavioral features from a MongoDB document.
    """
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

def get_malware_type_from_virusshare(file_hash, cache, retry_count=0, max_retries=5):
    """
    Fetch malware type from VirusShare API using file hash.
    
    Returns:
        malware_type (str): Inferred malware type.
        made_request (bool): Indicates whether an API request was made.
    """
    if file_hash in cache:
        logger.debug(f"Hash {file_hash} found in cache.")
        return cache[file_hash], False  # No API request made

    url = f'https://virusshare.com/apiv2/file?apikey={API_KEY}&hash={file_hash}'
    logger.debug(f"Sending request to VirusShare API: {url}")

    try:
        response = requests.get(url)
        logger.debug(f"Response Status Code for hash {file_hash}: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for hash {file_hash}: {e}")
        cache[file_hash] = 'Unknown'
        return 'Unknown', False  # No successful API request

    if response.status_code == 200:
        data = response.json()
        response_code = data.get('response')
        if response_code == 1:
            virustotal = data.get('virustotal', {})
            scans = virustotal.get('scans', {})
            malware_names = [
                av_data.get('result') 
                for av_data in scans.values() 
                if av_data.get('detected') and av_data.get('result')
            ]
            malware_type = infer_malware_type(malware_names)
        elif response_code == 2:
            malware_type = 'Benign'
        else:
            malware_type = 'Unknown'
        cache[file_hash] = malware_type
        logger.info(f"Hash {file_hash} classified as {malware_type}")
        return malware_type, True  # API request made
    elif response.status_code == 204:
        if retry_count < max_retries:
            sleep_time = 15 * (2 ** retry_count)  # Exponential backoff
            logger.warning(f"Rate limit exceeded. Waiting for {sleep_time} seconds before retrying.")
            time.sleep(sleep_time)
            return get_malware_type_from_virusshare(file_hash, cache, retry_count + 1, max_retries)
        else:
            logger.error(f"Max retries exceeded for hash {file_hash}. Marking as Unknown.")
            cache[file_hash] = 'Unknown'
            return 'Unknown', False
    else:
        logger.warning(f"VirusShare query failed for hash {file_hash}: {response.status_code}")
        cache[file_hash] = 'Unknown'
        return 'Unknown', False

def load_cache(cache_file='malware_cache.json'):
    """
    Load cache from a JSON file.
    
    Returns:
        cache (dict): Dictionary mapping file hashes to malware types.
    """
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cache = json.load(f)
        logger.debug(f"Loaded cache with {len(cache)} entries.")
        return cache
    else:
        logger.info("No existing cache found. Starting with an empty cache.")
        return {}

def save_cache(cache, cache_file='malware_cache.json'):
    """
    Save cache to a JSON file.
    """
    with open(cache_file, 'w') as f:
        json.dump(cache, f)
    logger.debug(f"Saved cache with {len(cache)} entries.")

def load_embeddings_and_features_from_mongodb(cache):
    """
    Load embeddings and behavioral features from MongoDB.
    
    Returns:
        embeddings_array (np.ndarray): Array of graph embeddings.
        task_ids (list): List of task IDs.
        md5_hashes (list): List of MD5 hashes.
        behavioral_features_df (pd.DataFrame): DataFrame of behavioral features.
        malware_types (list): List of inferred malware types.
    """
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI')
    if not MONGO_URI:
        logger.error("MONGO_URI not found in environment variables.")
        raise ValueError("MONGO_URI not provided.")

    # Connect to MongoDB
    client = MongoClient(MONGO_URI)
    db = client['cuckoo']
    collection = db['malware_analysis']

    # Start an explicit session
    with client.start_session() as session:
        logger.info("Fetching embeddings and behavioral features from MongoDB...")
        cursor = collection.find(
            {"graph_embedding": {"$exists": True}},
            no_cursor_timeout=True,
            session=session
        )

        try:
            embeddings = []
            task_ids = []
            md5_hashes = []
            behavioral_features_list = []
            malware_types = []

            request_count = 0  # To track the number of API requests in the current minute
            start_time = time.time()  # To track the start time of the current minute

            for doc in cursor:
                embedding = doc.get('graph_embedding')
                if not embedding:
                    logger.warning(f"No embedding found for document with _id: {doc['_id']}")
                    continue  # Skip this document

                embeddings.append(embedding)
                task_ids.append(doc.get('task_id'))
                features = extract_behavioral_features(doc)
                behavioral_features_list.append(features)
                
                # Get MD5 hash
                md5_hash = doc.get('target', {}).get('file', {}).get('md5')
                if not md5_hash:
                    logger.warning(f"No MD5 hash found for document with task_id: {doc.get('task_id')}")
                    md5_hashes.append(None)
                    malware_types.append('Unknown')
                    continue  # Skip API request for this document
                md5_hashes.append(md5_hash)

                # Get malware type from VirusShare
                malware_type, made_request = get_malware_type_from_virusshare(md5_hash, cache)
                malware_types.append(malware_type)

                if made_request:
                    request_count += 1

                    if request_count >= 4:
                        elapsed_time = time.time() - start_time
                        if elapsed_time < 60:
                            sleep_time = 60 - elapsed_time
                            logger.info(f"Sleeping for {sleep_time:.2f} seconds to comply with rate limit.")
                            time.sleep(sleep_time)
                        # Reset counters
                        request_count = 0
                        start_time = time.time()
                else:
                    logger.debug(f"Using cached malware type for hash {md5_hash}")

            if not embeddings:
                logger.warning("No embeddings were fetched from MongoDB.")

        finally:
            cursor.close()

    embeddings_array = np.array(embeddings)
    behavioral_features_df = pd.DataFrame(behavioral_features_list)
    logger.info(f"Total embeddings fetched: {len(embeddings_array)}")

    return embeddings_array, task_ids, md5_hashes, behavioral_features_df, malware_types

def determine_optimal_k(embeddings_scaled):
    """
    Determine the optimal number of clusters using the Elbow Method.
    """
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
    """
    Visualize clusters using PCA and color-code by inferred malware categories.
    """
    from sklearn.decomposition import PCA
    import seaborn as sns

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
    """
    Evaluate clustering performance using Silhouette Score.
    """
    if len(set(cluster_labels)) > 1:
        silhouette_avg = silhouette_score(embeddings_scaled, cluster_labels)
        print(f"The average silhouette_score is : {silhouette_avg}")
    else:
        print("Cannot compute silhouette score with only one cluster.")

def update_clusters_in_mongodb(task_ids, cluster_labels, malware_types):
    """
    Update the MongoDB documents with the cluster labels and malware types.
    """
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI')
    if not MONGO_URI:
        logger.error("MONGO_URI not found in environment variables.")
        raise ValueError("MONGO_URI not provided.")

    client = MongoClient(MONGO_URI)
    db = client['malware_analysis']  # Update as per your database
    collection = db['prev_sample']   # Update as per your collection

    for task_id, cluster_label, malware_type in zip(task_ids, cluster_labels, malware_types):
        if task_id is None:
            logger.warning("Encountered a task_id that is None. Skipping update.")
            continue
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
    """
    Main function to execute the malware analysis workflow.
    """
    # Load existing cache
    cache = load_cache()

    # Load embeddings and features from MongoDB
    embeddings_array, task_ids, md5_hashes, behavioral_features_df, malware_types = load_embeddings_and_features_from_mongodb(cache)

    # Save the cache after processing
    save_cache(cache)

    if embeddings_array.size == 0:
        logger.error("No embeddings found. Exiting.")
        return

    # Prepare the data for clustering
    scaler = StandardScaler()
    embeddings_scaled = scaler.fit_transform(embeddings_array)

    # Optional: Determine the optimal number of clusters using the Elbow Method
    # determine_optimal_k(embeddings_scaled)

    # Train K-Means clustering
    k = 4  # Adjust this number based on your dataset and analysis
    kmeans = KMeans(n_clusters=k, random_state=42)
    cluster_labels = kmeans.fit_predict(embeddings_scaled)

    # Analyze and interpret the clusters
    # Create a DataFrame that includes embeddings, cluster labels, task IDs, and behavioral features
    df = pd.DataFrame(embeddings_scaled)
    df['cluster'] = cluster_labels
    df['task_id'] = task_ids
    df['md5_hash'] = md5_hashes
    df = pd.concat([df, behavioral_features_df], axis=1)
    df['malware_type'] = malware_types

    # Print cluster information
    for cluster in sorted(df['cluster'].unique()):
        cluster_samples = df[df['cluster'] == cluster]
        print(f"\n{'-'*60}\nCluster {cluster} contains {len(cluster_samples)} samples.")
        print("Malware types in this cluster:")
        print(cluster_samples['malware_type'].value_counts())
        print("\nAverage behavioral features in this cluster:")
        print(cluster_samples[behavioral_features_df.columns].mean())
        print("-" * 60)

    # Optional: Evaluate clustering performance
    evaluate_clustering(embeddings_scaled, cluster_labels)

    # Visualize clusters using PCA
    visualize_clusters_pca(embeddings_scaled, cluster_labels, df['malware_type'])

    # Update MongoDB with cluster labels and inferred malware types
    update_clusters_in_mongodb(task_ids, cluster_labels, malware_types)

if __name__ == "__main__":
    main()
