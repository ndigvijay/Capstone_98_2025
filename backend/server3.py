import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
import time
import requests
import networkx as nx
import matplotlib.pyplot as plt
import logging
from functools import wraps
from dotenv import load_dotenv
# from networkx.readwrite.gpickle import write_gpickle  # Import the correct write_gpickle
import pickle  # Import pickle for serialization

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configure MongoDB
MONGO_URI = os.getenv('MONGO_URI')
if not MONGO_URI:
    logger.error("MONGO_URI not found in environment variables.")
    raise ValueError("MONGO_URI not provided.")

client = MongoClient(MONGO_URI)
db = client['malware_analysis']
collection = db['dataset1']



@app.route("/")
def home():
    return "Welcome to the Malware Analysis API!"

@app.route("/malware-file", methods=["POST"])
def malware_file():
    try:
        if 'file' not in request.files:
            logger.warning("No file part in the request.")
            return jsonify({"error": "No file part in the request"}), 400

        file = request.files['file']

        if file.filename == '':
            logger.warning("No file selected for uploading.")
            return jsonify({"error": "No file selected for uploading"}), 400

        # Validate file type and size
        ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'scr'}
        MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

        # def allowed_file(filename):
        #     return '.' in filename and \
        #            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

        # if not allowed_file(file.filename):
        #     logger.warning(f"File type not allowed: {file.filename}")
        #     return jsonify({"error": "File type not allowed"}), 400

        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        if file_length > MAX_FILE_SIZE:
            logger.warning(f"File too large: {file_length} bytes.")
            return jsonify({"error": "File is too large"}), 400

        files = {'file': (file.filename, file.stream, file.content_type)}

        headers = {
            'Authorization': f'Bearer {os.getenv("CUCKOO_API_KEY")}'
        }

        # Submit file to Cuckoo Sandbox
        response = requests.post('http://localhost:8090/tasks/create/file', files=files, headers=headers)
        response.raise_for_status()
        response_json = response.json()
        task_id = response_json.get("task_id")
        if not task_id:
            logger.error("No task_id found in Cuckoo Sandbox response.")
            return jsonify({"error": "Invalid response from Cuckoo Sandbox"}), 500

        logger.info(f"Task ID: {task_id}")

        # Poll for task completion with timeout
        max_attempts = 60  # e.g., 5 minutes
        attempt = 0
        task_completed = False
        while not task_completed and attempt < max_attempts:
            time.sleep(5)  # Wait for 5 seconds before polling again
            status_response = requests.get(f'http://localhost:8090/tasks/view/{task_id}', headers=headers)
            if status_response.status_code == 200:
                status_data = status_response.json()
                status = status_data.get('task', {}).get('status')
                if status == 'reported':
                    task_completed = True
                else:
                    logger.info(f"Task {task_id} status: {status}")
            else:
                logger.error("Failed to check task status.")
                return jsonify({"error": "Failed to check task status"}), 500
            attempt += 1

        if not task_completed:
            logger.error("Task timed out.")
            return jsonify({"error": "Task timed out"}), 504

        # Retrieve the full report
        report_response = requests.get(f'http://localhost:8090/tasks/report/{task_id}', headers=headers)
        if report_response.status_code == 200:
            report_data = report_response.json()

            # Extract essential data
            essential_data = {
                'task_id': task_id,
                'summary': report_data.get('behavior', {}).get('summary', {}),
                'network': report_data.get('network', {}),
                'target': report_data.get('target', {}),
                'info': report_data.get('info', {}),
            }

            # Insert the essential data into MongoDB and get the inserted_id
            result = collection.insert_one(essential_data)
            logger.info(f"Essential data of task {task_id} stored in MongoDB")

            # Convert the ObjectId to a string
            essential_data['_id'] = str(result.inserted_id)

            # Process the report to generate graphs
            image_path = process_report(report_data, task_id)

            # Construct the image URL
            image_url = request.host_url + image_path

            # Return the response with the modified essential_data and graph URL
            return jsonify({
                "task_id": task_id,
                "report": essential_data,
                "graph_url": image_url
            }), 200
        else:
            logger.error("Failed to retrieve task report from Cuckoo Sandbox.")
            return jsonify({"error": "Failed to retrieve task report from Cuckoo Sandbox"}), 500
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return jsonify({"error": "Failed to process the file with Cuckoo Sandbox"}), 500
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500

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

    logger.info(f"Network operations: {network_operations_count}")

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
    logger.info("Summary of operations:")
    logger.info(f"Number of DLLs accessed: {dll_accessed_count}")
    logger.info(f"Number of files opened: {file_opened_count}")
    logger.info(f"Number of files read: {file_read_count}")
    logger.info(f"Number of files modified: {file_modified_count}")
    logger.info(f"Number of files deleted: {file_deleted_count}")
    logger.info(f"Number of registry keys opened: {registry_opened_count}")
    logger.info(f"Number of network operations performed: {network_operations_count}")

    # Define positions for the nodes using spring layout
    pos = nx.spring_layout(G, k=0.5, seed=42)

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

    # Create graphs directory if it doesn't exist
    graphs_dir = "graph_again"
    graphs_img_dir = "graphs_img"
    os.makedirs(graphs_dir, exist_ok=True)
    os.makedirs(graphs_img_dir, exist_ok=True)


    # Serialize and save the NetworkX graph structure
    graph_pickle_path = f"graph_again/graph_{task_id}.gpickle"
    # write_gpickle(G, graph_pickle_path)
    with open(graph_pickle_path, 'wb') as f:
        pickle.dump(G, f)  # Use pickle to write the graph to a file
    logger.info(f"Graph structure saved to {graph_pickle_path}")

    

    logger.info(f"Graph image saved to {image_path}")

    return graph_pickle_path  # Return the path to the serialized graph

@app.route("/graphs/<filename>", methods=["GET"])
def serve_graph(filename):
    return send_from_directory("graphs", filename)



if __name__ == "__main__":
    # Run the app with Flask's built-in server or use a production server like Gunicorn
    app.run(debug=True)
