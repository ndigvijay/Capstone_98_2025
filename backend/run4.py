import json
from neo4j import GraphDatabase

# Load the JSON report
with open("/home/hg/Desktop/capstone/project/json_files/2.json", 'r') as file:
    report = json.load(file)

# Connect to Neo4j
uri = "bolt://localhost:7687"
username = "neo4j"
password = "password1"
driver = GraphDatabase.driver(uri, auth=(username, password))

def create_graph(tx, key, value):
    # Create a node for the current key
    tx.run("CREATE (n:Node {name: $key, value: $value})", key=key, value=value)
    
    # Create a node for the first child only, if it exists
    if isinstance(value, dict):
        for sub_key, sub_value in value.items():
            # Create a child node for the first child only
            tx.run("CREATE (m:Node {name: $sub_key, value: $sub_value})", sub_key=sub_key, sub_value=sub_value)
            tx.run("MATCH (a:Node {name: $key}), (b:Node {name: $sub_key}) "
                   "CREATE (a)-[:CONTAINS]->(b)", key=key, sub_key=sub_key)
            break  # Stop after the first child

# Start a new session and transaction to create the graph
with driver.session() as session:
    with session.begin_transaction() as tx:
        for key, value in report["summary"].items():
            create_graph(tx, key, value)

# Fetch all nodes for visualization
def fetch_all_nodes():
    with driver.session() as session:
        result = session.run("MATCH (n) RETURN n")
        return [record["n"] for record in result]

# Fetch all nodes and print them
nodes = fetch_all_nodes()

# Print the nodes for visualization
print("Nodes:")
for node in nodes:
    print(f"Name: {node['name']}, Value: {node['value']}")

# Close the driver
driver.close()
