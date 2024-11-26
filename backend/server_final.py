import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
import time
import requests
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Use the non-GUI backend before importing pyplot
import matplotlib.pyplot as plt
import logging
from functools import wraps
from dotenv import load_dotenv
import pickle  # Import pickle for serialization
from networkx.drawing.nx_agraph import graphviz_layout
from pyvis.network import Network

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
collection = db['test']

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
        # ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'scr'}
        # MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

        # def allowed_file(filename):
        #     return '.' in filename and \
        #            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

        # if not allowed_file(file.filename):
        #     logger.warning(f"File type not allowed: {file.filename}")
        #     return jsonify({"error": "File type not allowed"}), 400

        # file.seek(0, os.SEEK_END)
        # file_length = file.tell()
        # file.seek(0)
        # if file_length > MAX_FILE_SIZE:
        #     logger.warning(f"File too large: {file_length} bytes.")
        #     return jsonify({"error": "File is too large"}), 400

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
            image_filename = os.path.basename(image_path)
            image_url = request.host_url + f"graphs_img/{image_filename}"

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
    try:
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
            G.add_node(file, type='File', label='')  

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
        pos = nx.spring_layout(G, k=10, seed=42)

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

        # Create directories if they don't exist
        graphs_dir = "graphs"
        graphs_img_dir = "graphs_img"
        os.makedirs(graphs_dir, exist_ok=True)
        os.makedirs(graphs_img_dir, exist_ok=True)

        # Set up the figure size before plotting
        plt.figure(figsize=(20, 20))  # Increased figure size for better readability

        # # Draw the graph
        # nx.draw_networkx(
        #     G, pos, labels=labels, node_color=node_color_list,
        #     node_size=2000, font_size=10, font_weight='bold',
        #     edge_color=edge_colors
        # )

        # # Draw edge labels
        # edge_labels = nx.get_edge_attributes(G, 'interaction')
        # nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

        # plt.title("Behavioral Analysis Graph with File Nodes at the Center (No File Labels)")

        # # Save the figure
        # image_path = os.path.join(graphs_img_dir, f"graph_{task_id}.png")
        # plt.savefig(image_path, dpi=150)
        # plt.close()


        # --- Enhancements Start Here ---

        num_nodes = G.number_of_nodes()
        num_edges = G.number_of_edges()
        logger.info(f"Total nodes: {num_nodes}, Total edges: {num_edges}")
        # Initialize a PyVis network
        net = Network(notebook=False, cdn_resources='remote')

        # Adjust the physics settings for large graphs
        if num_nodes > 5000:
            net.barnes_hut()
        else:
            net.force_atlas_2based()

        # Add nodes and edges to the PyVis network
        for node, data in G.nodes(data=True):
            node_type = data.get('type', 'Unknown')
            label = data.get('label', '')
            color = {
                'DLL': 'lightblue',
                'File': 'lightgreen',
                'Registry Key': 'red',
                'Directory': 'yellow',
                'Network': 'lightpink'
            }.get(node_type, 'grey')
            net.add_node(node, label=label, color=color)

        for source, target, data in G.edges(data=True):
            interaction = data.get('interaction', 'other')
            color = {
                'opened': 'green',
                'failed': 'red',
                'accessed': 'orange',
                'networked': 'blue'
            }.get(interaction, 'black')
            net.add_edge(source, target, color=color)

        # Save the network to an HTML file
        graphs_html_dir = "graphs_html"
        os.makedirs(graphs_html_dir, exist_ok=True)
        html_path = os.path.join(graphs_html_dir, f"graph_{task_id}.html")
        net.write_html(html_path)
        logger.info(f"Graph saved to {html_path}")

        # Serialize and save the NetworkX graph structure
        graph_pickle_path = f"graphs/graph_{task_id}.gpickle"
        with open(graph_pickle_path, 'wb') as f:
            pickle.dump(G, f)
        logger.info(f"Graph structure saved to {graph_pickle_path}")

        return html_path  # Return the path to the HTML file
    except Exception as e:
        logger.error(f"Error in process_report: {e}")
        raise

        # Use `kamada_kawai_layout` for better performance on larger graphs
    #     pos = nx.kamada_kawai_layout(G)

    #     # Node and Edge Settings
    #     node_size = 100  
    #     font_size = 2
    #     edge_widths = []
    #     edge_colors = []

    #     # Set figure size to 15x15 inches
    #     plt.figure(figsize=(7, 7))

    #     # Labels for all nodes
    #     labels = {node: G.nodes[node]['label'] for node in G.nodes()}
    #     logger.info(f"Number of labeled nodes: {len(labels)}")

    #     # Define edge colors and widths based on interaction type
    #     for (u, v, d) in G.edges(data=True):
    #         interaction = d.get('interaction', 'other')
    #         if interaction == 'opened':
    #             edge_colors.append('green')
    #             edge_widths.append(0.2)
    #         elif interaction == 'failed':
    #             edge_colors.append('red')
    #             edge_widths.append(0.2)
    #         elif interaction == 'accessed':
    #             edge_colors.append('orange')
    #             edge_widths.append(0.1)
    #         elif interaction == 'networked':
    #             edge_colors.append('blue')
    #             edge_widths.append(0.1)
    #         else:
    #             edge_colors.append('black')
    #             edge_widths.append(0.1)

    #     # Node colors based on type
    #     node_colors_map = {
    #         'DLL': 'lightblue',
    #         'File': 'lightgreen',
    #         'Registry Key': 'red',
    #         'Directory': 'yellow',
    #         'Network': 'lightpink'
    #     }
    #     node_color_list = [node_colors_map.get(G.nodes[node].get('type', 'Unknown'), 'grey') for node in G.nodes()]

    #     # Draw the Graph
    #     nx.draw_networkx(
    #         G,
    #         pos,
    #         labels=labels,
    #         node_color=node_color_list,
    #         node_size=node_size,
    #         font_size=font_size,
    #         edge_color=edge_colors,
    #         width=edge_widths
    #     )

    #     plt.title("Behavioral Analysis Graph with Optimized Layout")

    #     # Save the Graph
    #     graphs_dir = "graphs"
    #     graphs_img_dir = "graphs_img"
    #     os.makedirs(graphs_dir, exist_ok=True)
    #     os.makedirs(graphs_img_dir, exist_ok=True)

    #     # Save as PNG
    #     image_path_png = os.path.join(graphs_img_dir, f"graph_{task_id}.png")
    #     plt.savefig(image_path_png, dpi=150, bbox_inches='tight')
    #     logger.info(f"Graph saved to {image_path_png}")

    #     # Save as SVG for better scalability (optional)
    #     image_path_svg = os.path.join(graphs_img_dir, f"graph_{task_id}.svg")
    #     plt.savefig(image_path_svg, format='svg', dpi=300, bbox_inches='tight')
    #     logger.info(f"Graph saved to {image_path_svg}")

    #     plt.close()

    #     logger.info(f"Graph saved to {graphs_img_dir}")


    #     # Serialize and save the NetworkX graph structure
    #     graph_pickle_path = f"graphs/graph_{task_id}.gpickle"
    #     # write_gpickle(G, graph_pickle_path)
    #     with open(graph_pickle_path, 'wb') as f:
    #         pickle.dump(G, f)  # Use pickle to write the graph to a file
    #     logger.info(f"Graph structure saved to {graph_pickle_path}")

    #     return graphs_img_dir
    # except Exception as e:
    #     logger.error(f"Error in process_report: {e}")
    #     raise

@app.route("/graphs/<filename>", methods=["GET"])
def serve_graph(filename):
    return send_from_directory("graphs", filename)

@app.route("/graphs_img/<filename>", methods=["GET"])
def serve_graph_image(filename):
    return send_from_directory("graphs_img", filename)

if __name__ == "__main__":
    # Run the app with Flask's built-in server or use a production server like Gunicorn
    app.run(debug=True)

