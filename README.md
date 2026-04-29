# 🛡️ Agentic Threat Hunting & Autonomous Investigation Assistant  
### Integrated with RSA NetWitness SIEM

## 📌 Overview
This project is an AI-powered Security Operations Centre (SOC) assistant designed to automate alert triage, investigation, and incident reporting.

The system integrates with NetWitness SIEM APIs and leverages agentic AI to replicate real-world SOC workflows across Tier 1, Tier 2, and Tier 3 analysts.

It aims to:
- Reduce manual investigation effort  
- Improve threat context understanding  
- Accelerate incident response time  

---

## 🎯 Objectives
The system will:
1. Fetch alerts from NetWitness via REST APIs  
2. Perform automated investigation pivots  
3. Enrich alerts using threat intelligence platforms  
4. Correlate evidence across multiple sources  
5. Compute risk scores dynamically  
6. Generate analyst-ready incident reports  
7. Recommend response actions based on playbooks  

---

## 🧠 System Architecture

### Core Components
- **Backend Orchestrator**: FastAPI  
- **Agent Framework**: LangChain  
- **Database**: PostgreSQL  
- **Vector Store**: Chroma  
- **SIEM Integration**: RSA NetWitness  

---

## ⚙️ Key Features

### 🔴 Agentic SOC Workflow
The system is designed around three specialised AI agents:

#### Triage Agent (Tier 1)
- Validates alerts  
- Filters false positives  
- Performs initial enrichment  

#### Investigation Agent (Tier 2)
- Executes deep-dive analysis  
- Correlates logs and indicators  
- Maps activity to Cyber Kill Chain and MITRE ATT&CK  

#### Response Agent (Tier 3)
- Calculates risk score  
- Recommends containment and remediation  
- Generates final incident report  

---

### 🌐 Threat Intelligence Enrichment
The system integrates with external platforms:
- VirusTotal  
- AbuseIPDB  
- AlienVault OTX  
- GreyNoise  
- URLhaus  

---

### 📊 Risk Scoring Engine
Risk is calculated based on:
- Indicator reputation (malicious, suspicious, clean)  
- Number of correlated events  
- Attack stage (Kill Chain progression)  
- Confidence level from enrichment sources  

Outputs:
- Low / Medium / High severity classification  
- Confidence score  
- Recommended actions  

---

### 📄 Automated Incident Reporting
The system generates:
- Human-readable summaries  
- Indicators of Compromise (IOCs)  
- Attack timeline  
- MITRE ATT&CK mapping  
- Recommended response actions  

---

## 🔄 Workflow Overview
1. Alert generated in NetWitness  
2. Alert fetched via API  
3. Triage Agent validates and enriches data  
4. Investigation Agent performs correlation and analysis  
5. Response Agent computes risk and generates report  
6. Final output delivered to analyst dashboard  

---

## 🛠️ Tech Stack

| Category        | Technology        |
|----------------|------------------|
| Backend        | FastAPI          |
| AI / Agents    | LangChain        |
| Database       | PostgreSQL       |
| Vector DB      | Chroma           |
| SIEM           | RSA NetWitness   |
| Data Processing| Pandas, NumPy, Scikit-learn |
| Version Control| GitHub           |

---

## 📁 Project Structure
```bash
/backend
  /api              # FastAPI routes
  /agents           # Triage, Investigation, Response agents
  /services         # Threat intel integrations
  /models           # Data schemas
  /utils            # Helper functions

/database
  schema.sql        # PostgreSQL schema

/playbooks
  incident_response_playbooks.json

/docs
  architecture_diagram.png
  workflow_diagram.png
```

---

## 🚀 Setup Instructions

### 1. Clone Repository
```bash
git clone https://github.com/your-repo/fyp-agentic-soc.git
cd fyp-agentic-soc
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate     # macOS/Linux
venv\Scripts\activate        # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file:
```env
NETWITNESS_API_KEY=your_key
VT_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
```

### 5. Run Application
```bash
uvicorn main:app --reload
```

---

## 📌 Use Cases
- Phishing / Malspam Detection  
- Suspicious IP Communication  
- Malware Callback Detection  
- Brute Force Login Attempts  

---

## 📊 Expected Impact
- Reduce manual SOC workload by ~50%  
- Improve threat context visibility by ~40%  
- Faster incident detection and response  

---

## 👥 Team Members
- KHO SOONG YANG (Team Leader) — Agentic Investigation & Reporting Engine  
- SHAHRUL GUNAWAN — Integration & Dashboard Module  
- TEO RUI XUAN — Threat Hunting & Detection Engine  

---

## 📚 Future Improvements
- Real-time streaming detection  
- Integration with SOAR platforms  
- Automated response execution  
- Fine-tuned LLM for cybersecurity reasoning  

---

## 📜 License
This project is developed for academic purposes under Republic Polytechnic.
