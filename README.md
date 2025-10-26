# Graph Based Malware Analysis API

A malware analysis platform that leverages graph theory and machine learning to classify and analyze malicious executables. This system analyzes pre-trained malware (.exe binaries) and provides classification probabilities for different malware types using advanced graph-based techniques.


## Demo

Watch the complete demonstration of the Graph Based Malware Analysis API:

https://github.com/user-attachments/assets/98_Demo.mp4

<video src="98_Demo.mp4" controls width="100%"></video>

*Note: If the video player doesn't display above, you can find it in the repository root as `98_Demo.mp4` or [click here to download](./98_Demo.mp4)*

## Overview

This project combines static malware analysis with graph-based behavioral modeling to identify and classify malware threats. By analyzing the behavioral patterns and relationships within malware samples, our system provides detailed insights into malware classification with probability scores for each malware family.

## Tech Stack

### Backend
- **Flask** - Web framework and REST API
- **NetworkX** - Graph creation and analysis
- **PyMongo** - MongoDB database integration
- **Matplotlib & PyVis** - Graph visualization
- **Cuckoo Sandbox** - Dynamic malware analysis

### Frontend
- **React 18** - UI framework
- **React Router** - Navigation
- **Tailwind CSS** - Styling

### Database
- **MongoDB** - NoSQL database for malware analysis data

## Project Structure

```
Capstone_98_2025/
├── backend/
│   ├── server_final.py       # Flask server
│   ├── embeddings.py          
│   ├── requirements.txt      
│   └── test/                 
│       ├── test_flask_server.py
│       ├── unit_test.py
│       └── graphs/            # Generated graph visualizations
├── frontend/
│   └── malware/
│       ├── src/               # React source files
│       ├── public/            
│       └── package.json      
└── README.md
```


## License

This project is developed for educational and research purposes.

---

