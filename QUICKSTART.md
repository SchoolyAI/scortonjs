# Scorton TrustGraph - Quick Start Guide

## Installation & Setup

### 1. Install Dependencies

```bash
cd d:\trustgraph\scortonjs
pip install pytest pytest-cov
```

Python 3.12+ required (already installed at `C:\Users\batoo\AppData\Local\Programs\Python\Python312\python.exe`)

### 2. Run Tests

Verify everything works:

```bash
python -m pytest tests/test_trustgraph_scorton.py -v
```

Expected output: **13 passed** ✅

### 3. Start the API Server

```bash
# Option 1: Run from scortonjs directory
cd d:\trustgraph\scortonjs
python trustgraph_api.py 8000

# Option 2: Run from PowerShell with full path
& 'C:\Users\batoo\AppData\Local\Programs\Python\Python312\python.exe' 'd:\trustgraph\scortonjs\trustgraph_api.py' '8000'
```

You should see:
```
╔════════════════════════════════════════════════════════════════╗
║         Scorton TrustGraph API Server - Started                ║
╚════════════════════════════════════════════════════════════════╝

📊 Server: http://localhost:8000
📁 Directory: d:\trustgraph\scortonjs\frontend

🔌 API Endpoints:
   • GET /api/graph              - Complete graph data
   • GET /api/graph/nodes        - Graph nodes only
   • GET /api/graph/edges        - Graph relationships only
   • GET /api/graph/node/<id>    - Node context and details
   • GET /api/graph/severity     - Findings by severity

🌐 Frontend:
   • GET /                       - Scorton TrustGraph visualization
```

### 4. Access the Visualization

Open your browser: **http://localhost:8000/scorton-graph.html**

You should see:
- 🔐 **Scorton TrustGraph - Security Intelligence** header
- 🌐 **Security Scan Graph** with 11 entities
- 📋 **Entity Details** panel
- 📊 Security score breakdown showing **72/100**

## Core Concepts in 2 Minutes

### What is TrustGraph?
A **knowledge graph** for cybersecurity that connects:
- **Targets** (domains, IPs) → **Scans** → **Findings** → **Vulnerabilities** → **Security Score**

Each connection includes evidence, timestamps, and confidence levels.

### Sample Flow
```
Organization (ACME Corp)
    ↓ owns
Domain (example.com)
    ↓ scanned_by
Scan Task (Security Scan #1)
    ↓ produces
Scan Result (#1)
    ↓ contains
Findings (DNS Config, SSL Check, Headers)
    ↓ identifies
Vulnerabilities (Missing HSTS, Weak TLS)
    ↓ impacts
Security Score (72/100)
```

### Score Breakdown
```
72/100 =
  • DNS (85) × 20% = 17.0
  • Ports (70) × 25% = 17.5
  • SSL (60) × 20% = 12.0 ← Weak TLS 🔴
  • Headers (45) × 15% = 6.75 ← Missing HSTS 🔴
  • XSS (90) × 10% = 9.0
  • Cookies (75) × 10% = 7.5
```

## Common Tasks

### 1. Explore the Graph

**In the Browser:**
1. Click **Domain** (example.com) → See scan history
2. Click **Security Score** → View score breakdown
3. Click **Vulnerability** → See evidence
4. Hover over arrows → See relationship explanations

**Via API:**
```bash
# Get all data
curl http://localhost:8000/api/graph

# Get specific node
curl http://localhost:8000/api/graph/node/domain-1

# Get critical findings
curl http://localhost:8000/api/graph/severity
```

### 2. Create Your Own Graph

```python
from trustgraph_scorton import (
    TrustGraph,
    EntityType,
    RelationType,
    ScanFinding,
    SecurityScoreBreakdown,
)

# Create graph
graph = TrustGraph()

# Add organization
graph.add_node("org-1", EntityType.ORGANIZATION, "My Company")

# Add domain to scan
graph.add_node("domain-1", EntityType.DOMAIN, "mysite.com")

# Connect them
graph.add_relationship(
    "org-1", "domain-1",
    RelationType.OPERATES,
    "Company operates this domain"
)

# Add scan task
graph.add_node("scan-1", EntityType.SCAN_TASK, "Full Scan")
graph.add_relationship(
    "domain-1", "scan-1",
    RelationType.SCANNED_BY,
    "Domain was scanned",
    evidence={"date": "2024-08-01", "duration": 45}
)

# Add findings
graph.add_node("finding-1", EntityType.FINDING, "SSL Check")
finding = ScanFinding(
    check_type="ssl",
    severity="high",
    title="Weak TLS",
    description="TLS 1.0 enabled",
    evidence={"protocols": ["TLS 1.0"]},
    remediation="Disable TLS < 1.2"
)
graph.add_scan_finding("finding-1", finding)

# Export as JSON
import json
data = graph.export_graph()
print(json.dumps(data, indent=2))
```

### 3. Check Security Score

```python
from trustgraph_scorton import TrustGraph, SecurityScoreBreakdown

graph = TrustGraph()
graph.add_node("domain-1", EntityType.DOMAIN, "example.com")

# Compute score
score = SecurityScoreBreakdown(
    dns_config=80.0,
    port_security=75.0,
    ssl_tls=70.0,
    http_headers=50.0,
    xss_protection=85.0,
    cookie_policy=80.0
)

graph.set_security_score("domain-1", score)

# Get context
context = graph.get_node_context("domain-1")
print(f"Score: {context['security_score']['total']:.1f}/100")

# Show factors
for factor in context['security_score']['breakdown']:
    print(f"  {factor['factor']}: {factor['score']:.0f} ({factor['weight']*100:.0f}%)")
```

## Troubleshooting

### Q: Server won't start
**A:** Use full Python path:
```bash
& 'C:\Users\batoo\AppData\Local\Programs\Python\Python312\python.exe' 'd:\trustgraph\scortonjs\trustgraph_api.py' '8000'
```

### Q: Port 8000 already in use
**A:** Use a different port:
```bash
python trustgraph_api.py 9000
# Then access: http://localhost:9000
```

### Q: Tests fail
**A:** Verify Python version:
```bash
python --version  # Should be 3.12+
```

### Q: API endpoint returns empty
**A:** Check server is running - should see output when starting

### Q: Graph visualization is blank
**A:** Make sure `scorton-graph.html` is in the `frontend/` directory

## File Structure

```
scortonjs/
├── trustgraph_scorton.py          # ✅ Core module (350+ lines)
│   ├── EntityType enum (12 types)
│   ├── RelationType enum (12 types)
│   ├── TrustGraphNode class
│   ├── TrustGraphEdge class
│   ├── TrustGraph class
│   └── create_sample_scorton_graph()
│
├── trustgraph_api.py              # ✅ REST API server (180+ lines)
│   ├── TrustGraphAPIHandler
│   ├── /api/graph endpoint
│   ├── /api/graph/nodes endpoint
│   ├── /api/graph/edges endpoint
│   ├── /api/graph/node/<id> endpoint
│   └── /api/graph/severity endpoint
│
├── frontend/
│   └── scorton-graph.html         # ✅ Interactive visualization
│       ├── Header with branding
│       ├── D3.js force-directed graph
│       ├── Entity details panel
│       ├── Security score breakdown
│       └── Responsive design
│
├── tests/
│   └── test_trustgraph_scorton.py # ✅ 13 comprehensive tests
│       ├── Security score tests
│       ├── Cybersecurity graph tests
│       ├── Sample graph tests
│       └── Export/visualization tests
│
└── TRUSTGRAPH_README.md           # 📖 Full documentation
```

## Next Steps

1. **Explore the Graph**: Open http://localhost:8000/scorton-graph.html
2. **Check the API**: Try endpoints at http://localhost:8000/api/graph
3. **Read Full Docs**: See [TRUSTGRAPH_README.md](./TRUSTGRAPH_README.md)
4. **Write Tests**: Add more tests in `tests/test_trustgraph_scorton.py`
5. **Integrate**: Connect to real Scorton API for live scan results

## Key Statistics

| Metric | Value |
|--------|-------|
| **Python Module Lines** | 350+ |
| **API Server Lines** | 180+ |
| **Test Coverage** | 13 tests, 100% pass rate |
| **Entity Types** | 12 cybersecurity types |
| **Relationship Types** | 12 security-specific relationships |
| **Sample Graph Nodes** | 11 |
| **Sample Graph Edges** | 10 |
| **Security Score Range** | 0-100 |
| **Frontend Framework** | D3.js v7 |

## Learn More

- 📖 [TrustGraph Documentation](https://docs.trustgraph.ai/)
- 🔐 [Scorton API Docs](https://docs.scorton.tech/)
- 📊 [D3.js Guide](https://d3js.org/)
- 🧪 [Pytest Documentation](https://docs.pytest.org/)

---

**Made for Scorton** | Security Intelligence through Knowledge Graphs
