import unittest
import json
import sys
import os
from unittest.mock import patch


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server_final_1 import app 

class FlaskAppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    @patch('server_final_1.process_report')
    def test_malware_file_upload(self, mock_process_report):
        # Set the return value of the mocked function
        mock_process_report.return_value = 'graphs_html/graph_1424.html'

        # Path to the test file (ensure this file exists)
        test_file_path = '/home/ndv/Downloads/1/1'

        with open(test_file_path, 'rb') as file_to_upload:
            # Mimic the file upload in Flask test client
            data = {
                'file': (file_to_upload, os.path.basename(test_file_path))
            }
            response = self.app.post('/malware-file', data=data, content_type='multipart/form-data')

            # Check if the response is successful
            self.assertEqual(response.status_code, 200)

            # Attempt to parse the response data
            response_data = json.loads(response.data.decode('utf-8'))

            # Perform assertions on the response data
            self.assertIn('task_id', response_data)
            self.assertIn('report', response_data)
            self.assertIn('graph_url', response_data)
            print("Test passed. Response data:")
            print(json.dumps(response_data, indent=4))

if __name__ == '__main__':
    unittest.main()
