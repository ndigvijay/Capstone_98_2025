# Graph Based Malware Analysis API

A malware analysis platform that leverages graph theory and machine learning to classify and analyze malicious executables. This system analyzes pre-trained malware (.exe binaries) and provides classification probabilities for different malware types using advanced graph-based techniques.


## Demo

Watch the complete demonstration of the Graph Based Malware Analysis API:

### [**Watch Demo Video **](https://drive.google.com/file/d/1Gu4Q5r6v5ktXGo0ZMa7dfEkRERb559e5/view?usp=sharing)

[![Watch Demo](https://img.shields.io/badge/▶️_Watch_Demo-4285F4?style=for-the-badge&logo=googledrive&logoColor=white)](https://drive.google.com/file/d/1Gu4Q5r6v5ktXGo0ZMa7dfEkRERb559e5/view?usp=sharing)

*Alternative: The demo video is also available in the repository root as [`98_Demo.mp4`](./98_Demo.mp4)*

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

