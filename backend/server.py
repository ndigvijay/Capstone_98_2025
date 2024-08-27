from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from pymongo import MongoClient
import time

app = Flask(__name__)
CORS(app)

# Configure MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['malware_analysis'] 
collection = db['task_summaries']  

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
        'Authorization': 'Bearer 4L-B9ky3KrnSdreio8lZVQ'
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


        # Retrieve the task summary
        summary_response = requests.get(f'http://localhost:8090/tasks/summary/{task_id}', headers=headers)
        if summary_response.status_code == 200:
            summary_data = summary_response.json()
            collection.insert_one({
                'task_id': task_id,
                'summary': summary_data
            })
            print(f"Summary of task {task_id} stored in MongoDB")
            return jsonify({"task_id": task_id, "summary": summary_data}), 200
        else:
            return jsonify({"error": "Failed to retrieve task summary from Cuckoo Sandbox"}), 500
    else:
        return jsonify({"error": "Failed to process the file with Cuckoo Sandbox"}), 500

if __name__ == "__main__":
    app.run(debug=True)
