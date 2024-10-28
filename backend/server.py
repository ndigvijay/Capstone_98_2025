# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import requests
# from pymongo import MongoClient
# import time

# app = Flask(__name__)
# CORS(app)

# # Configure MongoDB
# # client = MongoClient('mongodb://localhost:27017/')
# client = MongoClient('mongodb+srv://ndv005:ndv005@cluster0.cpdeub1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
# db = client['malware_analysis'] 
# collection = db['sample']  

# @app.route("/")
# def home():
#     return "Welcome to the Malware Analysis API!"

# @app.route("/malware-file", methods=["POST"])
# def malware_file():
#     if 'file' not in request.files:
#         return jsonify({"error": "No file part in the request"}), 400
    
#     file = request.files['file']
    
#     if file.filename == '':
#         return jsonify({"error": "No file selected for uploading"}), 400
    
#     files = {'file': (file.filename, file.stream, file.content_type)}
    
#     headers = {
#         'Authorization': 'Bearer HUdLik62eVxEWyLPfjIkag'
#     }
    
#     # Submit file to Cuckoo Sandbox
#     response = requests.post('http://localhost:8090/tasks/create/file', files=files, headers=headers)
#     if response.status_code == 200:
#         response_json = response.json()
#         task_id = response_json["task_id"]
#         print(f"Task ID: {task_id}")

#         # Poll for task completion
#         task_completed = False
#         while not task_completed:
#             time.sleep(5)  # Wait for 5 seconds before polling again
#             status_response = requests.get(f'http://localhost:8090/tasks/view/{task_id}', headers=headers)
#             if status_response.status_code == 200:
#                 status_data = status_response.json()
#                 # Check if the task status is 'reported'
#                 if status_data.get('task', {}).get('status') == 'reported':
#                     task_completed = True
#                 else:
#                     print(f"Task {task_id} status: {status_data.get('task', {}).get('status')}")
#             else:
#                 return jsonify({"error": "Failed to check task status"}), 500


#         # Retrieve the task summary
#         summary_response = requests.get(f'http://localhost:8090/tasks/summary/{task_id}', headers=headers)
#         if summary_response.status_code == 200:
#             summary_data = summary_response.json()
#             collection.insert_one({
#                 'task_id': task_id,
#                 'summary': summary_data
#             })
#             print(f"Summary of task {task_id} stored in MongoDB")
#             return jsonify({"task_id": task_id, "summary": summary_data}), 200
#         else:
#             return jsonify({"error": "Failed to retrieve task summary from Cuckoo Sandbox"}), 500
#     else:
#         return jsonify({"error": "Failed to process the file with Cuckoo Sandbox"}), 500

# if __name__ == "__main__":
#     app.run(debug=True)





from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from pymongo import MongoClient
import time
import json
import networkx as nx
import matplotlib
# matplotlib.use('Agg')  # Commented out to enable interactive plotting
import matplotlib.pyplot as plt
import community as community_louvain

app = Flask(__name__)
CORS(app)

# Configure MongoDB
client = MongoClient('mongodb+srv://ndv005:ndv005@cluster0.cpdeub1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client['malware_analysis']
collection = db['sample1']

@app.route("/")
def home():
    return "Welcome to the Malware Analysis API!"

@app.route("/malware-file", methods=["POST"])
def malware_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No file selected for uploading"}), 400

    files = {'file': (file.filename, file.stream, file.content_type)}

    headers = {
        'Authorization': 'Bearer HUdLik62eVxEWyLPfjIkag'
    }

    # Submit file to Cuckoo Sandbox
    response = requests.post('http://localhost:8090/tasks/create/file', files=files, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        task_id = response_json["task_id"]
        print(f"Task ID: {task_id}")

        # Poll for task completion
        task_completed = False
        while not task_completed:
            time.sleep(5)  # Wait for 5 seconds before polling again
            status_response = requests.get(f'http://localhost:8090/tasks/view/{task_id}', headers=headers)
            if status_response.status_code == 200:
                status_data = status_response.json()
                # Check if the task status is 'reported'
                if status_data.get('task', {}).get('status') == 'reported':
                    task_completed = True
                else:
                    print(f"Task {task_id} status: {status_data.get('task', {}).get('status')}")
            else:
                return jsonify({"error": "Failed to check task status"}), 500

        # Retrieve the full report
        report_response = requests.get(f'http://localhost:8090/tasks/report/{task_id}', headers=headers)
        if report_response.status_code == 200:
            report_data = report_response.json()

            # Extract essential data to avoid DocumentTooLarge error
            essential_data = {
                'task_id': task_id,
                'summary': report_data.get('behavior', {}).get('summary', {}),
                'network': report_data.get('network', {}),
                'target': report_data.get('target', {}),
                'info': report_data.get('info', {}),
            }

            # Insert the essential data into MongoDB and get the inserted_id
            result = collection.insert_one(essential_data)
            print(f"Essential data of task {task_id} stored in MongoDB")

            # Convert the ObjectId to a string
            essential_data['_id'] = str(result.inserted_id)

            # Process the report to generate graphs
            process_report(report_data, task_id)

            # Return the response with the modified essential_data
            return jsonify({"task_id": task_id, "report": essential_data}), 200
        else:
            return jsonify({"error": "Failed to retrieve task report from Cuckoo Sandbox"}), 500
    else:
        return jsonify({"error": "Failed to process the file with Cuckoo Sandbox"}), 500

def process_report(report, task_id):
    # Create a graph object
    G = nx.Graph()

    # Initialize counters for actions
    dll_accessed_count = 0
    file_opened_count = 0
    file_read_count = 0
    file_modified_count = 0
    file_deleted_count = 0
    registry_opened_count = 0
    network_operations_count = 0

    # Access the behavior summary
    summary = report.get('behavior', {}).get('summary', {})

    # Process DLLs (DLLs accessed)
    dlls = summary.get('dll_loaded', [])
    dll_accessed_count = len(dlls)
    for dll in dlls:
        G.add_node(dll, type='DLL', label=dll)

    # Process files (Files opened, read, modified, deleted)
    files_failed = summary.get('file_failed', [])
    files_opened = summary.get('file_opened', [])
    file_read = summary.get('file_read', [])
    file_written = summary.get('file_written', [])
    file_deleted = summary.get('file_deleted', [])

    file_opened_count = len(files_opened)
    file_read_count = len(file_read)
    file_modified_count = len(file_written)
    file_deleted_count = len(file_deleted)

    for file in set(files_failed + files_opened + file_read + file_written + file_deleted):
        G.add_node(file, type='File', label='')  # Add an empty label for files

    # Process registry keys (Opened)
    regkeys_opened = summary.get('regkey_opened', [])
    registry_opened_count = len(regkeys_opened)

    for regkey in regkeys_opened:
        G.add_node(regkey, type='Registry Key', label=regkey)

    # Process directories (optional)
    directories_enumerated = summary.get('directory_enumerated', [])
    for directory in directories_enumerated:
        G.add_node(directory, type='Directory', label=directory)

    # Process network operations (UDP, domains, DNS lookups)
    network_data = report.get('network', {})
    network_operations_count = len(network_data.get("udp", [])) + \
                               len(network_data.get("domains", [])) + \
                               len(network_data.get('dns', []))

    # Process UDP connections
    udp_connections = network_data.get('udp', [])
    for udp in udp_connections:
        udp_info = f"UDP: {udp['dst']}"
        G.add_node(udp_info, type='Network', label=udp_info)

    # Process domain resolutions
    domains = network_data.get('domains', [])
    for domain in domains:
        domain_info = f"Domain: {domain['domain']}"
        G.add_node(domain_info, type='Network', label=domain_info)

    # Process DNS requests
    dns_requests = network_data.get('dns', [])
    for dns in dns_requests:
        dns_info = f"DNS: {dns['request']}"
        G.add_node(dns_info, type='Network', label=dns_info)

    print("Network operations:", network_operations_count)

    # Add edges based on interactions
    for file in files_opened:
        for dll in dlls:
            G.add_edge(file, dll, interaction='opened')
    for file in files_failed:
        for dll in dlls:
            G.add_edge(file, dll, interaction='failed')

    for regkey in regkeys_opened:
        for file in files_opened + files_failed:
            G.add_edge(regkey, file, interaction='opened')

    for directory in directories_enumerated:
        for file in files_opened + files_failed:
            G.add_edge(directory, file, interaction='accessed')

    # Add edges between network nodes and relevant nodes (e.g., files or DLLs)
    for udp in udp_connections:
        udp_info = f"UDP: {udp['dst']}"
        for file in files_opened:
            G.add_edge(udp_info, file, interaction='networked')

    for domain in domains:
        domain_info = f"Domain: {domain['domain']}"
        for dll in dlls:
            G.add_edge(domain_info, dll, interaction='networked')

    for dns in dns_requests:
        dns_info = f"DNS: {dns['request']}"
        for file in files_opened:
            G.add_edge(dns_info, file, interaction='networked')

    # Output the counts
    print("Summary of operations:")
    print(f"Number of DLLs accessed: {dll_accessed_count}")
    print(f"Number of files opened: {file_opened_count}")
    print(f"Number of files read: {file_read_count}")
    print(f"Number of files modified: {file_modified_count}")
    print(f"Number of files deleted: {file_deleted_count}")
    print(f"Number of registry keys opened: {registry_opened_count}")
    print(f"Number of network operations performed: {network_operations_count}")

    # Define positions for the nodes: files at the center, others surrounding
    pos = nx.spring_layout(G, k=0.5, seed=42)  # Spring layout for non-fixed nodes

    # Manually set the position for the 'File' nodes in the center
    for node in G.nodes():
        if G.nodes[node]['type'] == 'File':
            pos[node] = [0, 0]  # Force all 'File' nodes to be at the center

    # Set node colors
    node_colors_map = {
        'DLL': 'lightblue',
        'File': 'lightgreen',
        'Registry Key': 'red',
        'Directory': 'yellow',
        'Network': 'lightpink'
    }
    node_color_list = [node_colors_map.get(G.nodes[node].get('type', 'Unknown'), 'grey') for node in G.nodes()]

    # Set edge colors based on interaction
    edge_colors = []
    for (u, v, d) in G.edges(data=True):
        if d['interaction'] == 'opened':
            edge_colors.append('green')
        elif d['interaction'] == 'failed':
            edge_colors.append('red')
        else:
            edge_colors.append('black')

    # Separate label dictionaries: don't label 'File' nodes
    labels = {node: G.nodes[node]['label'] for node in G.nodes() if G.nodes[node]['type'] != 'File'}

    # Draw the graph with the manually positioned 'File' nodes
    plt.figure(figsize=(30, 16))
    nx.draw(G, pos, labels=labels, node_color=node_color_list, node_size=2000, font_size=10, font_weight='bold', edge_color=edge_colors)

    # Draw edge labels
    edge_labels = nx.get_edge_attributes(G, 'interaction')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

    plt.title("Behavioral Analysis Graph with File Nodes at the Center (No File Labels)")
    plt.show()  # Display the plot interactively

    # Community Detection
    partition = community_louvain.best_partition(G)
    node_colors = [partition.get(node) for node in G.nodes()]
    plt.figure(figsize=(30, 16))
    nx.draw(G, pos, node_color=node_colors, with_labels=False, node_size=2000, cmap=plt.cm.rainbow)
    plt.title("Community Detection")
    plt.show()  # Display the plot interactively

    # Betweenness Centrality
    centrality = nx.betweenness_centrality(G)
    plt.figure(figsize=(30, 16))
    nodes = nx.draw_networkx_nodes(G, pos, node_size=2000, cmap=plt.cm.Blues, node_color=list(centrality.values()))
    nx.draw_networkx_edges(G, pos)
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=10, font_weight='bold')
    plt.title("Betweenness Centrality")
    plt.colorbar(nodes)
    plt.show()  # Display the plot interactively

if __name__ == "__main__":
    app.run(debug=True)
