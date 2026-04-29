# 🛡️ Agentic Threat Hunting & Autonomous Investigation Assistant  
### Integrated with RSA NetWitness SIEM

---

## 📌 Overview
This project is an AI-powered Security Operations Centre (SOC) assistant that automates alert triage, investigation, and incident reporting.

The system integrates with NetWitness SIEM and simulates real-world SOC workflows through multiple AI agents that replicate Tier 1, Tier 2, and Tier 3 analysts.

It is designed to handle high-volume security alerts and transform them into structured, actionable intelligence. :contentReference[oaicite:0]{index=0}

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

### 🔍 Internal Data Flow

1. **Alert Ingestion**
   - Alerts are retrieved from NetWitness via REST APIs  
   - Raw logs are normalised into structured JSON format  

2. **Pre-processing Layer**
   - Key fields extracted (IP, domain, hash, user activity)  
   - Data cleaned and standardised for downstream processing  

3. **Agent Pipeline Execution**
   - Data passed sequentially through:
     - Triage Agent → Investigation Agent → Response Agent  

4. **Data Storage**
   - Structured results stored in PostgreSQL  
   - Contextual embeddings stored in ChromaDB  

5. **Output Layer**
   - Results displayed in dashboard  
   - Reports generated for analysts  

---

## 🔴 Agentic SOC Workflow

### 🧩 Agent Design Concept
Each agent operates as:
- A reasoning unit (LLM)
- A tool user (API calls, database queries)
- A playbook executor (structured workflow)

---

### 1. Triage Agent (Tier 1)

**Input:**
- Raw alert from NetWitness  

**Process:**
- Extract indicators (IP, URL, hash)  
- Query threat intelligence APIs  
- Validate whether alert is a false positive  

**Output:**
- Enriched alert  
- Initial severity classification  

---

### 2. Investigation Agent (Tier 2)

**Input:**
- Enriched alert  

**Process:**
- Perform correlation:
  - Cross-log correlation  
  - Indicator relationship mapping  
- Query historical data from database  
- Retrieve similar past incidents from ChromaDB (RAG)  
- Map findings to:
  - Cyber Kill Chain stages  
  - MITRE ATT&CK techniques  

**Output:**
- Investigation findings  
- Attack pattern identification  

---

### 3. Response Agent (Tier 3)

**Input:**
- Investigation results  

**Process:**
- Compute risk score  
- Evaluate impact and likelihood  
- Apply predefined playbooks  

**Output:**
- Final incident report  
- Recommended actions (containment, eradication, recovery)  

---

## 🌐 Threat Intelligence Integration

Integrated APIs:

- VirusTotal  
- AbuseIPDB  
- AlienVault OTX  
- GreyNoise  
- URLhaus  

### 🔍 Enrichment Process
For each indicator:
1. Query multiple APIs  
2. Aggregate responses  
3. Assign confidence score  
4. Store enrichment results  

---

## 📊 Risk Scoring Model

### 🧮 Risk Calculation Logic

Risk Score is derived from:

```
Risk = (Severity Weight × Indicator Score) 
     + (Correlation Weight × Event Frequency)
     + (Attack Stage Weight × Kill Chain Progression)
```

### Factors Explained:

- **Indicator Score**  
  Based on reputation from threat intelligence  

- **Event Frequency**  
  Number of related logs/events  

- **Kill Chain Stage**
  Later stages = higher risk  

---

### Output:
- Severity: Low / Medium / High  
- Confidence Score  
- Recommended Actions  

---

## 📄 Automated Reporting

Each report includes:

- Executive summary  
- Detailed investigation steps  
- Timeline of attack  
- Indicators of Compromise (IOCs)  
- MITRE ATT&CK mapping  
- Risk analysis  
- Recommended response actions  

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
  schema.sql

/vector_db
  chroma_store/

/playbooks
  incident_playbooks.json

/frontend
  /react-dashboard
  /streamlit-app

/docs
  architecture.png
  workflow.png
```

---

## 🔄 End-to-End Workflow (Detailed)

1. Alert generated in NetWitness  
2. Alert retrieved via API  
3. Logs normalised into structured format  
4. Indicators extracted  
5. Threat intelligence enrichment executed  
6. Triage Agent validates alert  
7. Investigation Agent correlates evidence  
8. Risk score computed  
9. Response Agent generates report  
10. Data stored in database  
11. Results displayed on dashboard  

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
- Faster investigation cycles  
- Improved detection accuracy  
- Consistent reporting standards  

---

## 👥 Team Members

- Kho Soong Yang  
  Agentic Investigation & Reporting Engine  

- Shahrul Gunawan  
  Integration & Dashboard Module  

- Teo Rui Xuan  
  Threat Hunting & Detection Engine  

---

## 📚 Future Enhancements

- Real-time alert streaming  
- SOAR integration  
- Automated containment scripts  
- Fine-tuned cybersecurity LLM  
- Advanced anomaly detection  

---

## 📜 License
Developed for academic purposes under Republic Polytechnic.
