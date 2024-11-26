from sklearn.preprocessing import MultiLabelBinarizer

def extract_behavior_features(report):
    summary = report.get('behavior', {}).get('summary', {})
    
    features = {}
    
    # Initialize MultiLabelBinarizer for each categorical field
    mlb_dll = MultiLabelBinarizer()
    mlb_files_opened = MultiLabelBinarizer()
    mlb_files_failed = MultiLabelBinarizer()
    mlb_regkeys = MultiLabelBinarizer()
    mlb_directories = MultiLabelBinarizer()
    mlb_udp = MultiLabelBinarizer()
    mlb_domains = MultiLabelBinarizer()
    mlb_dns = MultiLabelBinarizer()
    
    # Fit and transform each feature
    features_dll = mlb_dll.fit_transform([summary.get('dll_loaded', [])])
    features_files_opened = mlb_files_opened.fit_transform([summary.get('file_opened', [])])
    features_files_failed = mlb_files_failed.fit_transform([summary.get('file_failed', [])])
    features_regkeys = mlb_regkeys.fit_transform([summary.get('regkey_opened', [])])
    features_directories = mlb_directories.fit_transform([summary.get('directory_enumerated', [])])
    
    # Network features
    network_data = report.get('network', {})
    udp = [udp['dst'] for udp in network_data.get('udp', [])]
    domains = [domain['domain'] for domain in network_data.get('domains', [])]
    dns = [dns['request'] for dns in network_data.get('dns', [])]
    
    features_udp = mlb_udp.fit_transform([udp])
    features_domains = mlb_domains.fit_transform([domains])
    features_dns = mlb_dns.fit_transform([dns])
    
    # Combine all features into a single vector
    import numpy as np
    combined_features = np.hstack([
        features_dll,
        features_files_opened,
        features_files_failed,
        features_regkeys,
        features_directories,
        features_udp,
        features_domains,
        features_dns
    ])
    
    return combined_features.flatten()






