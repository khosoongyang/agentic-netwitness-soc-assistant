# 🛡️ Agentic Threat Hunting & Autonomous Investigation Assistant  
### Integrated with RSA NetWitness SIEM

---

## 📌 Overview
This project is an AI-powered Security Operations Centre (SOC) assistant that automates alert triage, investigation, and incident reporting.

The system integrates with NetWitness SIEM and simulates real-world SOC workflows through multiple AI agents that replicate Tier 1, Tier 2, and Tier 3 analysts.

It is designed to handle high-volume security alerts and transform them into structured, actionable intelligence.

---

## 🎯 System Objectives
The system is designed to:

- Fetch alerts from NetWitness via REST APIs  
- Perform automated investigation pivots  
- Enrich alerts using multiple threat intelligence sources  
- Correlate logs and indicators across datasets  
- Compute dynamic risk scores  
- Execute playbook-driven analysis  
- Generate analyst-ready incident reports  
- Recommend response and remediation actions  

---

## 🧠 System Architecture Overview

The system follows a modular, agent-driven architecture:

```
NetWitness SIEM → FastAPI Backend → AI Agents → Data Layer → Dashboard
```

### Flow Breakdown

1. Alerts are generated in NetWitness  
2. FastAPI retrieves alerts via API  
3. Triage Agent validates and enriches alerts  
4. Investigation Agent performs correlation and deep analysis  
5. Response Agent calculates risk and generates reports  
6. Results are stored and displayed on dashboard  

---

## 🔴 Agentic SOC Workflow

### 1. Triage Agent (Tier 1)
- Filters false positives  
- Validates alert authenticity  
- Performs initial enrichment (IP, URL, hash checks)  
- Prioritises alerts  

---

### 2. Investigation Agent (Tier 2)
- Executes multi-step investigation workflows  
- Correlates logs across sources  
- Identifies attack patterns  
- Maps activity to:
  - Cyber Kill Chain  
  - MITRE ATT&CK  

---

### 3. Response Agent (Tier 3)
- Computes risk scores  
- Determines severity levels  
- Recommends containment and remediation  
- Generates final incident reports  

---

## 🌐 Threat Intelligence Integration

The system integrates multiple intelligence sources:

- VirusTotal  
- AbuseIPDB  
- AlienVault OTX  
- GreyNoise  
- URLhaus  

These sources provide:
- IP reputation  
- Malware indicators  
- URL classification  
- Threat validation  

---

## 📊 Risk Scoring Model

Risk scores are computed based on:

- Indicator severity (malicious, suspicious, benign)  
- Number of correlated indicators  
- Attack progression stage  
- Confidence level from enrichment sources  

### Output:
- Severity: Low / Medium / High  
- Confidence Score  
- Recommended Actions  

---

## 📄 Automated Reporting

The system generates structured reports containing:

- Incident summary  
- Timeline of events  
- Indicators of Compromise (IOCs)  
- MITRE ATT&CK mapping  
- Risk assessment  
- Response recommendations  

---

# 🛠️ Tech Stack

## 1. Core Environment
- Python 3.x  
- Git  
- VS Code / PyCharm  

---

## 2. Backend & Orchestration
- FastAPI  

---

## 3. Agentic AI Layer
- LangChain  

---

## 4. Data Layer
- PostgreSQL (Relational Database)  
- ChromaDB (Vector Database)  

---

## 5. Data Processing & Detection
- Pandas  
- NumPy  
- Scikit-learn  

---

## 6. Frontend Layer (Hybrid)
- Streamlit (Development & Testing Interface)  
- React (SOC Dashboard)  

---

## 7. LLM Engine
- LLM API (e.g. OpenAI GPT)  

---

## 8. Threat Intelligence APIs
- VirusTotal  
- AbuseIPDB  
- AlienVault OTX  
- GreyNoise  
- URLhaus  

---

## 📁 Project Structure

```bash
/backend
  /api              # FastAPI routes
  /agents           # Triage, Investigation, Response agents
  /services         # Threat intelligence integrations
  /models           # Data schemas
  /utils            # Helper functions

/database
  schema.sql        # PostgreSQL schema

/vector_db
  chroma_store/     # Embeddings storage

/playbooks
  incident_playbooks.json

/frontend
  /react-dashboard  # Main SOC UI
  /streamlit-app    # Testing & debugging UI

/docs
  architecture.png
  workflow.png
```

---

## 🔄 End-to-End Workflow

1. Alert generated in NetWitness  
2. Alert retrieved via API  
3. Triage Agent validates alert  
4. Threat intelligence enrichment performed  
5. Investigation Agent correlates data  
6. Risk scoring computed  
7. Response Agent generates report  
8. Results stored in database  
9. Output displayed on dashboard  

---

## 📌 Use Cases

- Phishing / Malspam Detection  
- Suspicious IP Activity  
- Malware Callback Detection  
- Brute Force Login Attempts  
- Anomalous Network Behaviour  

---

## 📊 Expected Impact

- Reduction in manual SOC workload  
- Improved investigation speed  
- Better threat visibility  
- Consistent and structured incident reporting  

---

## 👥 Team Members

- Kho Soong Yang  
  Agentic Investigation & Reporting Engine  

- Shahrul Gunawan  
  Integration & Dashboard Module  

- Teo Rui Xuan  
  Threat Hunting & Detection Engine  

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
source venv/bin/activate
# Windows:
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
```env
NETWITNESS_API_KEY=your_key
VT_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
```

### 5. Run Backend
```bash
uvicorn main:app --reload
```

---

## 📚 Future Enhancements

- Real-time alert streaming  
- SOAR integration  
- Automated response execution  
- Fine-tuned cybersecurity LLM  
- Advanced anomaly detection models  

---

## 📜 License
Developed for academic purposes under Republic Polytechnic.
