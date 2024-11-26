# import os
# import requests
# import numpy as np
# import pandas as pd
# import logging
# import time
# import json
# from dotenv import load_dotenv
# from pymongo import MongoClient
# from sklearn.preprocessing import StandardScaler
# from sklearn.cluster import KMeans
# from sklearn.metrics import silhouette_score
# import matplotlib.pyplot as plt

# # Load environment variables
# load_dotenv()

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s %(levelname)s: %(message)s',
# )
# logger = logging.getLogger(__name__)

# def infer_malware_type(malware_names):
#     """Infer malware type from a list of malware detection names."""
#     malware_types = set()
#     for name in malware_names:
#         name_upper = name.upper()
#         if 'TROJAN' in name_upper:
#             malware_types.add('Trojan')
#         if 'RANSOM' in name_upper or 'CRYPT' in name_upper:
#             malware_types.add('Ransomware')
#         if 'WORM' in name_upper:
#             malware_types.add('Worm')
#         if 'ADWARE' in name_upper:
#             malware_types.add('Adware')
#         if 'SPYWARE' in name_upper:
#             malware_types.add('Spyware')
#         if 'BACKDOOR' in name_upper:
#             malware_types.add('Backdoor')
#         if 'PHISH' in name_upper:
#             malware_types.add('Phishing')
#         if 'ROOTKIT' in name_upper:
#             malware_types.add('Rootkit')
#         if 'KEYLOGGER' in name_upper:
#             malware_types.add('Keylogger')
#         if 'DROPPER' in name_upper:
#             malware_types.add('Dropper')
#         if 'MINER' in name_upper or 'COIN' in name_upper or 'BITCOIN' in name_upper or 'COINHIVE' in name_upper:
#             malware_types.add('Cryptocurrency Miner')
#     if malware_types:
#         return ', '.join(malware_types)
#     else:
#         return 'Unknown'



# def extract_behavioral_features(doc):
#     """Extract behavioral features from a MongoDB document."""
#     features = {}
    
#     summary = doc.get('summary', {})
#     network = doc.get('network', {})
    
#     # Example features from summary
#     features['files_created'] = len(summary.get('file_created', []))
#     features['files_written'] = len(summary.get('file_written', []))
#     features['files_opened'] = len(summary.get('file_opened', []))
#     features['dlls_loaded'] = len(summary.get('dll_loaded', []))
#     features['commands_executed'] = len(summary.get('command_line', []))
#     features['guids'] = len(summary.get('guid', []))
#     features['files_failed'] = len(summary.get('file_failed', []))
#     features['files_recreated'] = len(summary.get('file_recreated', []))

#     # Example features from network
#     features['dns_lookups'] = len(network.get('dns', []))
#     features['tcp_connections'] = len(network.get('tcp', []))
#     features['udp_connections'] = len(network.get('udp', []))
#     features['http_requests'] = len(network.get('http', []))
#     features['domains_contacted'] = len(network.get('domains', []))
#     features['hosts_contacted'] = len(network.get('hosts', []))

#     # You can extract more features based on available data and domain knowledge
#     return features

# def load_cache(cache_file='malware_cache.json'):
#     if os.path.exists(cache_file):
#         with open(cache_file, 'r') as f:
#             return json.load(f)
#     else:
#         return {}

# def save_cache(cache, cache_file='malware_cache.json'):
#     with open(cache_file, 'w') as f:
#         json.dump(cache, f)

# def get_malware_type_from_virusshare(file_hash, cache):
#     if file_hash in cache:
#         return cache[file_hash]
    
#     API_KEY = 'FOytx62i6L4AtkVLAdIEH3CBic14Njtp'  # Replace with your VirusShare API key
#     url = f'https://virusshare.com/apiv2/file?apikey={API_KEY}&hash={file_hash}'
    
#     response = requests.get(url)
#     print(f"Response Status Code: {response.status_code}")
    
#     if response.status_code == 200:
#         data = response.json()
#         print(data)
#         response_code = data.get('response')
#         if response_code == 1:
#             # It's malware; attempt to extract detailed malware type
#             virustotal = data.get('virustotal', {})
#             scans = virustotal.get('scans', {})
#             malware_names = []
#             for av_name, av_data in scans.items():
#                 if av_data.get('detected'):
#                     result = av_data.get('result')
#                     print(result)
#                     if result:
#                         malware_names.append(result)
#             malware_type = infer_malware_type(malware_names)
#         elif response_code == 2:
#             malware_type = 'Benign'
#         else:
#             malware_type = 'Unknown'
#         cache[file_hash] = malware_type
#         print(malware_type)
#         return malware_type
#     elif response.status_code == 204:
#         logger.warning("Rate limit exceeded. Waiting for 15 seconds.")
#         time.sleep(15)
#         return get_malware_type_from_virusshare(file_hash, cache)
#     else:
#         logger.warning(f"VirusShare query failed for hash {file_hash}: {response.status_code}")
#         cache[file_hash] = 'Unknown'
#         return 'Unknown'

# def load_embeddings_and_features_from_mongodb(cache):
#     # MongoDB Configuration
#     MONGO_URI = os.getenv('MONGO_URI')
#     if not MONGO_URI:
#         logger.error("MONGO_URI not found in environment variables.")
#         raise ValueError("MONGO_URI not provided.")

#     # Connect to MongoDB
#     client = MongoClient(MONGO_URI)
#     db = client['malware_analysis']
#     collection = db['dataset1']

#     # Start an explicit session
#     with client.start_session() as session:
#         # Use no_cursor_timeout=True and pass the session
#         logger.info("Fetching embeddings and behavioral features from MongoDB...")
#         cursor = collection.find(
#             {"graph_embedding": {"$exists": True}},
#             no_cursor_timeout=True,
#             session=session
#         )

#         try:
#             embeddings = []
#             task_ids = []
#             md5_hashes = []
#             behavioral_features_list = []
#             malware_types = []

#             request_count = 0  # To track the number of requests in the current minute
#             start_time = time.time()  # To track the start time of the current minute

#             for doc in cursor:
#                 embedding = doc.get('graph_embedding')
#                 if embedding:
#                     embeddings.append(embedding)
#                     task_ids.append(doc.get('task_id'))
#                     features = extract_behavioral_features(doc)
#                     behavioral_features_list.append(features)
#                     # Get MD5 hash
#                     md5_hash = doc.get('target', {}).get('file', {}).get('md5')
#                     md5_hashes.append(md5_hash)
#                     # Get malware type from VirusShare
#                     malware_type = get_malware_type_from_virusshare(md5_hash, cache)
#                     malware_types.append(malware_type)
#                     request_count += 1
#                     # Check if we've reached the rate limit
#                     if request_count >= 4:
#                         elapsed_time = time.time() - start_time
#                         if elapsed_time < 60:
#                             sleep_time = 60 - elapsed_time
#                             logger.info(f"Sleeping for {sleep_time:.2f} seconds to comply with rate limit.")
#                             time.sleep(sleep_time)
#                         request_count = 0
#                         start_time = time.time()
#                 else:
#                     logger.warning(f"No embedding found for document with _id: {doc['_id']}")
#         finally:
#             # Always close the cursor to avoid resource leaks
#             cursor.close()

#     embeddings_array = np.array(embeddings)
#     behavioral_features_df = pd.DataFrame(behavioral_features_list)
#     logger.info(f"Total embeddings fetched: {len(embeddings_array)}")

#     return embeddings_array, task_ids, md5_hashes, behavioral_features_df, malware_types


# def determine_optimal_k(embeddings_scaled):
#     """Determine the optimal number of clusters using the Elbow Method."""
#     inertia = []
#     K = range(1, 11)
#     for k in K:
#         kmeans = KMeans(n_clusters=k, random_state=42)
#         kmeans.fit(embeddings_scaled)
#         inertia.append(kmeans.inertia_)
#     plt.figure(figsize=(8, 4))
#     plt.plot(K, inertia, 'bx-')
#     plt.xlabel('Number of clusters (k)')
#     plt.ylabel('Inertia')
#     plt.title('Elbow Method For Optimal k')
#     plt.show()

# def visualize_clusters_pca(embeddings_scaled, cluster_labels, malware_categories):
#     """Visualize clusters using PCA and color-code by inferred malware categories."""
#     from sklearn.decomposition import PCA
#     import seaborn as sns

#     # Perform PCA to reduce dimensions to 2D
#     pca = PCA(n_components=2)
#     embeddings_2d = pca.fit_transform(embeddings_scaled)

#     plt.figure(figsize=(12, 8))
#     sns.scatterplot(
#         x=embeddings_2d[:, 0],
#         y=embeddings_2d[:, 1],
#         hue=malware_categories,
#         style=cluster_labels,
#         palette='tab10',
#         s=100,
#         alpha=0.7
#     )
#     plt.title('PCA Visualization of Malware Embeddings by Inferred Malware Category')
#     plt.xlabel('Principal Component 1')
#     plt.ylabel('Principal Component 2')
#     plt.legend(title='Malware Category')
#     plt.show()

# def evaluate_clustering(embeddings_scaled, cluster_labels):
#     """Evaluate clustering performance using Silhouette Score."""
#     if len(set(cluster_labels)) > 1:
#         silhouette_avg = silhouette_score(embeddings_scaled, cluster_labels)
#         print(f"The average silhouette_score is : {silhouette_avg}")
#     else:
#         print("Cannot compute silhouette score with only one cluster.")

# def update_clusters_in_mongodb(task_ids, cluster_labels, malware_types):
#     """Update the MongoDB documents with the cluster labels and malware types."""
#     # MongoDB Configuration
#     MONGO_URI = os.getenv('MONGO_URI')
#     client = MongoClient(MONGO_URI)
#     db = client['malware_analysis']
#     collection = db['dataset']

#     for task_id, cluster_label, malware_type in zip(task_ids, cluster_labels, malware_types):
#         result = collection.update_one(
#             {'task_id': task_id},
#             {'$set': {
#                 'cluster_label': int(cluster_label),
#                 'malware_type': malware_type
#             }}
#         )
#         if result.modified_count > 0:
#             logger.info(f"Updated task_id {task_id} with cluster_label {cluster_label} and malware_type {malware_type}")
#         else:
#             logger.warning(f"Failed to update task_id {task_id}")

# def main():
#     # Load existing cache
#     cache = load_cache()

#     embeddings_array, task_ids, md5_hashes, behavioral_features_df, malware_types = load_embeddings_and_features_from_mongodb(cache)

#     # Save the cache after processing
#     save_cache(cache)

#     if embeddings_array.size == 0:
#         logger.error("No embeddings found. Exiting.")
#         return

#     # Prepare the data for clustering
#     scaler = StandardScaler()
#     embeddings_scaled = scaler.fit_transform(embeddings_array)

#     # Optional: Determine the optimal number of clusters
#     # determine_optimal_k(embeddings_scaled)

#     # Train K-Means clustering
#     k = 4  # Adjust this number based on your dataset and analysis
#     kmeans = KMeans(n_clusters=k, random_state=42)
#     cluster_labels = kmeans.fit_predict(embeddings_scaled)

#     # Analyze and interpret the clusters
#     # Create a DataFrame that includes embeddings, cluster labels, task IDs, and behavioral features
#     df = pd.DataFrame(embeddings_scaled)
#     df['cluster'] = cluster_labels
#     df['task_id'] = task_ids
#     df['md5_hash'] = md5_hashes
#     df = pd.concat([df, behavioral_features_df], axis=1)
#     df['malware_type'] = malware_types

#     # Print cluster information
#     for cluster in sorted(df['cluster'].unique()):
#         cluster_samples = df[df['cluster'] == cluster]
#         print(f"Cluster {cluster} contains {len(cluster_samples)} samples.")
#         print("Malware types in this cluster:")
#         print(cluster_samples['malware_type'].value_counts())
#         print("Average behavioral features in this cluster:")
#         print(cluster_samples[behavioral_features_df.columns].mean())
#         print("-" * 60)

#     # Optional: Evaluate clustering performance
#     evaluate_clustering(embeddings_scaled, cluster_labels)

#     # Visualize clusters using PCA
#     visualize_clusters_pca(embeddings_scaled, cluster_labels, df['malware_type'])

#     # Update MongoDB with cluster labels and inferred malware types
#     update_clusters_in_mongodb(task_ids, cluster_labels, malware_types)

# if __name__ == "__main__":
#     main()



# import os
# import requests
# import numpy as np
# import pandas as pd
# import logging
# import time
# import json
# from dotenv import load_dotenv
# from pymongo import MongoClient
# from sklearn.preprocessing import StandardScaler
# from sklearn.cluster import KMeans
# from sklearn.metrics import silhouette_score
# import matplotlib.pyplot as plt

# # Load environment variables
# load_dotenv()

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s %(levelname)s: %(message)s',
# )
# logger = logging.getLogger(__name__)

# def infer_malware_type(malware_names):
#     """Infer malware type from a list of malware detection names."""
#     malware_types = set()
#     for name in malware_names:
#         name_upper = name.upper()
#         if 'TROJAN' in name_upper:
#             malware_types.add('Trojan')
#         if 'RANSOM' in name_upper or 'CRYPT' in name_upper:
#             malware_types.add('Ransomware')
#         if 'WORM' in name_upper:
#             malware_types.add('Worm')
#         if 'ADWARE' in name_upper:
#             malware_types.add('Adware')
#         if 'SPYWARE' in name_upper:
#             malware_types.add('Spyware')
#         if 'BACKDOOR' in name_upper:
#             malware_types.add('Backdoor')
#         if 'PHISH' in name_upper:
#             malware_types.add('Phishing')
#         if 'ROOTKIT' in name_upper:
#             malware_types.add('Rootkit')
#         if 'KEYLOGGER' in name_upper:
#             malware_types.add('Keylogger')
#         if 'DROPPER' in name_upper:
#             malware_types.add('Dropper')
#         if 'MINER' in name_upper or 'COIN' in name_upper or 'BITCOIN' in name_upper or 'COINHIVE' in name_upper:
#             malware_types.add('Cryptocurrency Miner')
#     if malware_types:
#         return ', '.join(malware_types)
#     else:
#         return 'Unknown'

# def extract_behavioral_features(doc):
#     """Extract behavioral features from a MongoDB document."""
#     features = {}
    
#     summary = doc.get('summary', {})
#     network = doc.get('network', {})
    
#     # Example features from summary
#     features['files_created'] = len(summary.get('file_created', []))
#     features['files_written'] = len(summary.get('file_written', []))
#     features['files_opened'] = len(summary.get('file_opened', []))
#     features['dlls_loaded'] = len(summary.get('dll_loaded', []))
#     features['commands_executed'] = len(summary.get('command_line', []))
#     features['guids'] = len(summary.get('guid', []))
#     features['files_failed'] = len(summary.get('file_failed', []))
#     features['files_recreated'] = len(summary.get('file_recreated', []))

#     # Example features from network
#     features['dns_lookups'] = len(network.get('dns', []))
#     features['tcp_connections'] = len(network.get('tcp', []))
#     features['udp_connections'] = len(network.get('udp', []))
#     features['http_requests'] = len(network.get('http', []))
#     features['domains_contacted'] = len(network.get('domains', []))
#     features['hosts_contacted'] = len(network.get('hosts', []))

#     # You can extract more features based on available data and domain knowledge
#     return features

# def load_cache(cache_file='malware_cache.json'):
#     if os.path.exists(cache_file):
#         with open(cache_file, 'r') as f:
#             return json.load(f)
#     else:
#         return {}

# def save_cache(cache, cache_file='malware_cache.json'):
#     with open(cache_file, 'w') as f:
#         json.dump(cache, f)

# def get_malware_type_from_virusshare(file_hash, cache):
#     if file_hash in cache:
#         return cache[file_hash]
    
#     API_KEY = 'FOytx62i6L4AtkVLAdIEH3CBic14Njtp'  # Replace with your VirusShare API key
#     url = f'https://virusshare.com/apiv2/file?apikey={API_KEY}&hash={file_hash}'
    
#     response = requests.get(url)
#     print(f"Response Status Code: {response.status_code}")
    
#     if response.status_code == 200:
#         data = response.json()
#         print(data)
#         response_code = data.get('response')
#         if response_code == 1:
#             # It's malware; attempt to extract detailed malware type
#             virustotal = data.get('virustotal', {})
#             scans = virustotal.get('scans', {})
#             malware_names = []
#             for av_name, av_data in scans.items():
#                 if av_data.get('detected'):
#                     result = av_data.get('result')
#                     print(result)
#                     if result:
#                         malware_names.append(result)
#             malware_type = infer_malware_type(malware_names)
#         elif response_code == 2:
#             malware_type = 'Benign'
#         else:
#             malware_type = 'Unknown'
#         cache[file_hash] = malware_type
#         print(malware_type)
#         return malware_type
#     elif response.status_code == 204:
#         logger.warning("Rate limit exceeded. Waiting for 15 seconds.")
#         time.sleep(15)
#         return get_malware_type_from_virusshare(file_hash, cache)
#     else:
#         logger.warning(f"VirusShare query failed for hash {file_hash}: {response.status_code}")
#         cache[file_hash] = 'Unknown'
#         return 'Unknown'

# def load_embeddings_and_features_from_mongodb(cache):
#     # MongoDB Configuration
#     MONGO_URI = os.getenv('MONGO_URI')
#     if not MONGO_URI:
#         logger.error("MONGO_URI not found in environment variables.")
#         raise ValueError("MONGO_URI not provided.")

#     # Connect to MongoDB
#     client = MongoClient(MONGO_URI)
#     db = client['malware_analysis']
#     collection = db['dataset1']

#     last_id = None
#     embeddings = []
#     task_ids = []
#     md5_hashes = []
#     behavioral_features_list = []
#     malware_types = []

#     while True:
#         # Start an explicit session
#         with client.start_session() as session:
#             # Use no_cursor_timeout=True and pass the session
#             logger.info("Fetching embeddings and behavioral features from MongoDB...")
#             query = {"graph_embedding": {"$exists": True}}
#             if last_id:
#                 query["_id"] = {"$gt": last_id}
            
#             cursor = collection.find(query, no_cursor_timeout=True, session=session)

#             try:
#                 request_count = 0
#                 start_time = time.time()
#                 for doc in cursor:
#                     last_id = doc['_id']  # Keep track of the last document ID processed
#                     embedding = doc.get('graph_embedding')
#                     if embedding:
#                         embeddings.append(embedding)
#                         task_ids.append(doc.get('task_id'))
#                         features = extract_behavioral_features(doc)
#                         behavioral_features_list.append(features)
#                         # Get MD5 hash
#                         md5_hash = doc.get('target', {}).get('file', {}).get('md5')
#                         md5_hashes.append(md5_hash)
#                         # Get malware type from VirusShare
#                         malware_type = get_malware_type_from_virusshare(md5_hash, cache)
#                         malware_types.append(malware_type)
#                         request_count += 1
#                         # Check if we've reached the rate limit
#                         if request_count >= 4:
#                             elapsed_time = time.time() - start_time
#                             if elapsed_time < 60:
#                                 sleep_time = 60 - elapsed_time
#                                 logger.info(f"Sleeping for {sleep_time:.2f} seconds to comply with rate limit.")
#                                 time.sleep(sleep_time)
#                             request_count = 0
#                             start_time = time.time()
#                     else:
#                         logger.warning(f"No embedding found for document with _id: {doc['_id']}")
#             except pymongo.errors.CursorNotFound:
#                 logger.warning("Cursor expired, restarting from last processed ID.")
#             finally:
#                 # Always close the cursor to avoid resource leaks
#                 cursor.close()
                
#             if not cursor.retrieved:  # Break the loop if there are no more documents
#                 break

#     embeddings_array = np.array(embeddings)
#     behavioral_features_df = pd.DataFrame(behavioral_features_list)
#     logger.info(f"Total embeddings fetched: {len(embeddings_array)}")

#     return embeddings_array, task_ids, md5_hashes, behavioral_features_df, malware_types


# def determine_optimal_k(embeddings_scaled):
#     """Determine the optimal number of clusters using the Elbow Method."""
#     inertia = []
#     K = range(1, 11)
#     for k in K:
#         kmeans = KMeans(n_clusters=k, random_state=42)
#         kmeans.fit(embeddings_scaled)
#         inertia.append(kmeans.inertia_)
#     plt.figure(figsize=(8, 4))
#     plt.plot(K, inertia, 'bx-')
#     plt.xlabel('Number of clusters (k)')
#     plt.ylabel('Inertia')
#     plt.title('Elbow Method For Optimal k')
#     plt.show()

# def visualize_clusters_pca(embeddings_scaled, cluster_labels, malware_categories):
#     """Visualize clusters using PCA and color-code by inferred malware categories."""
#     from sklearn.decomposition import PCA
#     import seaborn as sns

#     # Perform PCA to reduce dimensions to 2D
#     pca = PCA(n_components=2)
#     embeddings_2d = pca.fit_transform(embeddings_scaled)

#     plt.figure(figsize=(12, 8))
#     sns.scatterplot(
#         x=embeddings_2d[:, 0],
#         y=embeddings_2d[:, 1],
#         hue=malware_categories,
#         style=cluster_labels,
#         palette='tab10',
#         s=100,
#         alpha=0.7
#     )
#     plt.title('PCA Visualization of Malware Embeddings by Inferred Malware Category')
#     plt.xlabel('Principal Component 1')
#     plt.ylabel('Principal Component 2')
#     plt.legend(title='Malware Category')
#     plt.show()

# def evaluate_clustering(embeddings_scaled, cluster_labels):
#     """Evaluate clustering performance using Silhouette Score."""
#     if len(set(cluster_labels)) > 1:
#         silhouette_avg = silhouette_score(embeddings_scaled, cluster_labels)
#         print(f"The average silhouette_score is : {silhouette_avg}")
#     else:
#         print("Cannot compute silhouette score with only one cluster.")

# def update_clusters_in_mongodb(task_ids, cluster_labels, malware_types):
#     """Update the MongoDB documents with the cluster labels and malware types."""
#     # MongoDB Configuration
#     MONGO_URI = os.getenv('MONGO_URI')
#     client = MongoClient(MONGO_URI)
#     db = client['malware_analysis']
#     collection = db['dataset']

#     for task_id, cluster_label, malware_type in zip(task_ids, cluster_labels, malware_types):
#         result = collection.update_one(
#             {'task_id': task_id},
#             {'$set': {
#                 'cluster_label': int(cluster_label),
#                 'malware_type': malware_type
#             }}
#         )
#         if result.modified_count > 0:
#             logger.info(f"Updated task_id {task_id} with cluster_label {cluster_label} and malware_type {malware_type}")
#         else:
#             logger.warning(f"Failed to update task_id {task_id}")

# def main():
#     # Load existing cache
#     cache = load_cache()

#     embeddings_array, task_ids, md5_hashes, behavioral_features_df, malware_types = load_embeddings_and_features_from_mongodb(cache)

#     # Save the cache after processing
#     save_cache(cache)

#     if embeddings_array.size == 0:
#         logger.error("No embeddings found. Exiting.")
#         return

#     # Prepare the data for clustering
#     scaler = StandardScaler()
#     embeddings_scaled = scaler.fit_transform(embeddings_array)

#     # Optional: Determine the optimal number of clusters
#     # determine_optimal_k(embeddings_scaled)

#     # Train K-Means clustering
#     k = 4  # Adjust this number based on your dataset and analysis
#     kmeans = KMeans(n_clusters=k, random_state=42)
#     cluster_labels = kmeans.fit_predict(embeddings_scaled)

#     # Analyze and interpret the clusters
#     # Create a DataFrame that includes embeddings, cluster labels, task IDs, and behavioral features
#     df = pd.DataFrame(embeddings_scaled)
#     df['cluster'] = cluster_labels
#     df['task_id'] = task_ids
#     df['md5_hash'] = md5_hashes
#     df = pd.concat([df, behavioral_features_df], axis=1)
#     df['malware_type'] = malware_types

#     # Print cluster information
#     for cluster in sorted(df['cluster'].unique()):
#         cluster_samples = df[df['cluster'] == cluster]
#         print(f"Cluster {cluster} contains {len(cluster_samples)} samples.")
#         print("Malware types in this cluster:")
#         print(cluster_samples['malware_type'].value_counts())
#         print("Average behavioral features in this cluster:")
#         print(cluster_samples[behavioral_features_df.columns].mean())
#         print("-" * 60)

#     # Optional: Evaluate clustering performance
#     evaluate_clustering(embeddings_scaled, cluster_labels)

#     # Visualize clusters using PCA
#     visualize_clusters_pca(embeddings_scaled, cluster_labels, df['malware_type'])

#     # Update MongoDB with cluster labels and inferred malware types
#     update_clusters_in_mongodb(task_ids, cluster_labels, malware_types)

# if __name__ == "__main__":
#     main()

import os
import requests
import numpy as np
import pandas as pd
import logging
import time
import json
import pymongo  # Added this import
from dotenv import load_dotenv
from pymongo import MongoClient
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import matplotlib.pyplot as plt

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
)
logger = logging.getLogger(__name__)

def infer_malware_type(malware_names):
    """Infer malware type from a list of malware detection names."""
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
        if 'MINER' in name_upper or 'COIN' in name_upper or 'BITCOIN' in name_upper or 'COINHIVE' in name_upper:
            malware_types.add('Cryptocurrency Miner')
    if malware_types:
        return ', '.join(malware_types)
    else:
        return 'Unknown'

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

def load_cache(cache_file='malware_cache.json'):
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            return json.load(f)
    else:
        return {}

def save_cache(cache, cache_file='malware_cache.json'):
    with open(cache_file, 'w') as f:
        json.dump(cache, f)

def get_malware_type_from_virusshare(file_hash, cache):
    if file_hash in cache:
        return cache[file_hash]
    
    API_KEY = 'FOytx62i6L4AtkVLAdIEH3CBic14Njtp'  # Replace with your VirusShare API key
    url = f'https://virusshare.com/apiv2/file?apikey={API_KEY}&hash={file_hash}'
    
    response = requests.get(url)
    print(f"Response Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(data)
        response_code = data.get('response')
        if response_code == 1:
            # It's malware; attempt to extract detailed malware type
            virustotal = data.get('virustotal', {})
            scans = virustotal.get('scans', {})
            malware_names = []
            for av_name, av_data in scans.items():
                if av_data.get('detected'):
                    result = av_data.get('result')
                    print(result)
                    if result:
                        malware_names.append(result)
            malware_type = infer_malware_type(malware_names)
        elif response_code == 2:
            malware_type = 'Benign'
        else:
            malware_type = 'Unknown'
        cache[file_hash] = malware_type
        print(malware_type)
        return malware_type
    elif response.status_code == 204:
        logger.warning("Rate limit exceeded. Waiting for 15 seconds.")
        time.sleep(15)
        return get_malware_type_from_virusshare(file_hash, cache)
    else:
        logger.warning(f"VirusShare query failed for hash {file_hash}: {response.status_code}")
        cache[file_hash] = 'Unknown'
        return 'Unknown'

def load_embeddings_and_features_from_mongodb(cache):
    # MongoDB Configuration
    MONGO_URI = os.getenv('MONGO_URI')
    if not MONGO_URI:
        logger.error("MONGO_URI not found in environment variables.")
        raise ValueError("MONGO_URI not provided.")

    # Connect to MongoDB
    client = MongoClient(MONGO_URI)
    db = client['malware_analysis']
    collection = db['dataset1']

    batch_size = 1000
    last_id = None

    embeddings = []
    task_ids = []
    md5_hashes = []
    behavioral_features_list = []
    malware_types = []

    while True:
        query = {"graph_embedding": {"$exists": True}}
        if last_id:
            query["_id"] = {"$gt": last_id}

        # Fetch a batch of documents
        documents = list(collection.find(query).sort("_id").limit(batch_size))

        if not documents:
            break

        # Process the documents
        for doc in documents:
            last_id = doc['_id']
            embedding = doc.get('graph_embedding')
            if embedding:
                embeddings.append(embedding)
                task_ids.append(doc.get('task_id'))
                features = extract_behavioral_features(doc)
                behavioral_features_list.append(features)
                # Get MD5 hash
                md5_hash = doc.get('target', {}).get('file', {}).get('md5')
                md5_hashes.append(md5_hash)
            else:
                logger.warning(f"No embedding found for document with _id: {doc['_id']}")

    # Now process md5_hashes to get malware types
    md5_to_malware_type = {}
    unique_md5_hashes = set(md5_hashes)

    request_count = 0
    start_time = time.time()

    for md5_hash in unique_md5_hashes:
        # First, check if the malware type is already in the cache
        if md5_hash in cache:
            malware_type = cache[md5_hash]
        else:
            # Check if malware type is already stored in MongoDB
            doc = collection.find_one({'target.file.md5': md5_hash})
            if doc and 'malware_type' in doc:
                malware_type = doc['malware_type']
                cache[md5_hash] = malware_type  # Update cache
            else:
                # Get malware type from VirusShare
                malware_type = get_malware_type_from_virusshare(md5_hash, cache)
                # Save malware type into MongoDB
                result = collection.update_many(
                    {'target.file.md5': md5_hash},
                    {'$set': {'malware_type': malware_type}}
                )
                if result.modified_count > 0:
                    logger.info(f"Updated malware_type for md5 hash {md5_hash}")
                else:
                    logger.warning(f"Failed to update malware_type for md5 hash {md5_hash}")
                # Increment request count
                request_count += 1
                # Check if we've reached the rate limit
                if request_count >= 4:
                    elapsed_time = time.time() - start_time
                    if elapsed_time < 60:
                        sleep_time = 60 - elapsed_time
                        logger.info(f"Sleeping for {sleep_time:.2f} seconds to comply with rate limit.")
                        time.sleep(sleep_time)
                    request_count = 0
                    start_time = time.time()

        md5_to_malware_type[md5_hash] = malware_type

    # Now, build the malware_types list
    for md5_hash in md5_hashes:
        malware_type = md5_to_malware_type.get(md5_hash, 'Unknown')
        malware_types.append(malware_type)

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
    collection = db['dataset1']  # Ensure this matches the collection used earlier

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
    # Load existing cache
    cache = load_cache()

    embeddings_array, task_ids, md5_hashes, behavioral_features_df, malware_types = load_embeddings_and_features_from_mongodb(cache)

    # Save the cache after processing
    save_cache(cache)

    if embeddings_array.size == 0:
        logger.error("No embeddings found. Exiting.")
        return

    # Prepare the data for clustering
    scaler = StandardScaler()
    embeddings_scaled = scaler.fit_transform(embeddings_array)

    # Optional: Determine the optimal number of clusters
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
        print(f"Cluster {cluster} contains {len(cluster_samples)} samples.")
        print("Malware types in this cluster:")
        print(cluster_samples['malware_type'].value_counts())
        print("Average behavioral features in this cluster:")
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

