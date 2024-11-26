import requests
import json

# URL of the Flask server's endpoint
url = "http://localhost:5000/malware-file"

# Path to the test file you want to upload
test_file_path = "/home/ndv/Downloads/1/1"

# Open the file in binary mode
with open(test_file_path, 'rb') as file_to_upload:
    # Prepare the files dictionary for the POST request
    files = {'file': (test_file_path, file_to_upload, 'application/octet-stream')}
    
    try:
        # Send POST request to the server
        response = requests.post(url, files=files)
        
        # Print the status code of the response
        print("Status Code:", response.status_code)
        
        # Attempt to parse the response as JSON and print it
        try:
            response_json = response.json()
            print("Response JSON:")
            print(json.dumps(response_json, indent=4))
        except json.JSONDecodeError:
            print("Response is not in JSON format.")
            print("Response Text:")
            print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
