# ENDGAME v5 – Attack Surface Intelligence Engine (Sudipta Karmakar - sudipta7431)

ENDGAME is an **advanced recon & attack surface intelligence tool** designed for:
- Bug bounty hunters
- Penetration testers
- Security researchers
- Red teamers

It performs **safe, non-exploitive analysis** and produces a **single interactive HTML report**.

---

## ✨ Features

### 🌐 Crawling & Discovery
- HTTP crawler (multi-threaded)
- Headless browser crawling
- Subdomain & deep path discovery
- Cookie-aware crawling

### 🧠 Intelligence & Analysis
- Advanced parameter-based vulnerability classification
- Behavioral analysis
- Differential response analysis
- Semantic JSON response diffing
- JavaScript logic intelligence
- JavaScript logic graph (Condition → API → Source)
- GraphQL surface discovery
- GraphQL depth intelligence

### 🧬 API Intelligence
- OpenAPI / Swagger parsing
- Auth detection
- Dangerous method detection (PUT / DELETE)
- Sensitive parameter detection
- API → Endpoint correlation

### 📊 Reporting
- Single self-contained HTML report
- Searchable & sortable UI
- JSON + intelligence unified
- Automatic filename based on target domain

---

## ⚙️ Installation

### 1️⃣ Clone the repository
    git clone https://github.com/yourusername/endgame.git
    cd endgame

### 2️⃣ Create a Virtual Enviroment (Recommended)
    python3 -m venv .venv
    source .venv/bin/activate

### 3️⃣ Install dependencies
    pip install -r requirements.txt
    pip install playwright (important for macos or linux)


🚀 Usage Examples

🔹 Basic scan
    
    python endgame.py -u https://xyz.com

🔹 Browser + diff scan
    
    python endgame.py -u https://xyz.com --browser --diff

🔹 Scan with cookie (authenticated surface)
    
    python endgame.py -u https://xyz.com --cookie="session=admin; role=admin" --browser --diff

🔹 API Intelligence using OpenApi
    
    python endgame.py -u https://xyz.com --api-fuzz openapi.json

🔹 Full power scan
    
    python endgame.py -u https://xyz.com --cookie="session=aytdfguyas" --browser --api-fuzz openapi.json --diff

📄 Output
    
    A single HTML report is generated automatically.File name is derived from the domain.

    Example: output/reports/xyz.com.html

📄 The report contains:

    Endpoint intelligence & priority
    JavaScript logic intelligence
    JS logic graph
    API intelligence
    GraphQL intelligence
    Behavioral & differential analysis
    Semantic response differences
    Raw JSON (expandable)

🛡️ Safety & Ethics
    
    1. No exploitation
    2. No payload fuzzing
    3. No brute force
    4. Designed for authorized testing only
    5. Use only on targets you own or have permission to test.

📌 Roadmap
    
    1. Knowledge Graph visualization
    2. Automatic OpenAPI extraction from JS
    3. Attack surface scoring v2
    4. Correlation engine (API ↔ JS ↔ Vulns)
    5. Plugin system

📜 License

    MIT License

⭐ Author

    Developed by Sudipta Karmakar(sudipta7431)
    Security Researcher & Cybersecurity Analyst

    If you find ENDGAME useful, consider giving it a ⭐ on GitHub.