# Scorton TrustGraph - Security Intelligence Platform

## Overview

**Scorton TrustGraph** is an explainable cybersecurity knowledge graph that combines security scanning, vulnerability detection, and trust scoring. It enables security teams to understand relationships between entities, track evidence of vulnerabilities, and make informed decisions about security posture.

Based on the [TrustGraph AI platform](https://docs.trustgraph.ai/), this implementation brings intelligent knowledge graphs to cybersecurity assessment and risk management.

## Key Features

### 🔍 Cybersecurity-Specific Entities
- **Targets**: Domains, IP addresses, Organizations
- **Scanning**: Scan tasks, Scan results, Findings
- **Risks**: Vulnerabilities, Security findings, Risk assessments
- **Scoring**: Security scores, Compliance scores, Trust scores
- **Components**: DNS records, SSL certificates, HTTP headers, Cookie policies
- **Governance**: Policies, Standards, Evidence

### 🔗 Explainable Relationships
Every relationship includes:
- **Explanation**: Why entities are connected
- **Evidence**: Supporting data from scans
- **Confidence**: Level of certainty
- **Provenance**: Source and timestamp
- **History**: Track changes and updates

### 📊 Security Score Computation
Weighted multi-factor assessment:
- **DNS Configuration** (20%) - Proper DNS record setup
- **Port Security** (25%) - No unnecessary open ports
- **SSL/TLS** (20%) - Valid certificates, modern protocols
- **HTTP Headers** (15%) - Security headers present (HSTS, CSP, etc.)
- **XSS Protection** (10%) - Input validation, output encoding
- **Cookie Policy** (10%) - Secure, HttpOnly, SameSite flags

**Score Range**: 0-100 (higher is better)

### 🔐 Provenance Tracking
Full traceability for all findings:
- **Original Source**: Which scan identified the issue
- **Scan Timestamp**: When the scan ran
- **Evidence Collection**: Raw data supporting the finding
- **Update History**: How findings evolved over time
- **Supporting Data**: Links to related findings and vulnerabilities

## Architecture

```
┌─────────────────────────────────────────────┐
│         Scorton API Integration             │
│  • Domain Scanner                           │
│  • Port Scanner                             │
│  • SSL/TLS Validator                        │
│  • Header Analyzer                          │
│  • XSS Detector                             │
│  • Cookie Policy Check                      │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│    TrustGraph Scorton Module                │
│  • Entity Management                        │
│  • Relationship Tracking                    │
│  • Evidence Collection                      │
│  • Score Computation                        │
│  • Provenance Recording                     │
└──────────────────┬──────────────────────────┘
                   │
         ┌─────────┴──────────┐
         ▼                    ▼
    ┌─────────────┐    ┌──────────────────┐
    │   Python    │    │   REST API       │
    │   Backend   │    │   Endpoints      │
    └────┬────────┘    └────┬─────────────┘
         │                  │
         └──────────┬───────┘
                    ▼
        ┌───────────────────────────┐
        │  D3.js Visualization      │
        │  • Interactive Graph      │
        │  • Entity Details         │
        │  • Relationship Insights  │
        │  • Score Breakdown        │
        └───────────────────────────┘
```

## Usage

### 1. Python Module - `trustgraph_scorton.py`

```python
from trustgraph_scorton import (
    TrustGraph,
    EntityType,
    RelationType,
    ScanFinding,
    SecurityScoreBreakdown,
    create_sample_scorton_graph,
)

# Create a new graph
graph = TrustGraph()

# Add cybersecurity entities
domain = graph.add_node(
    "domain-example",
    EntityType.DOMAIN,
    "example.com",
    "Main web presence"
)

# Add scan finding
finding = ScanFinding(
    check_type="ssl",
    severity="high",
    title="Weak TLS",
    description="TLS 1.0 still enabled",
    evidence={"protocols": ["TLS 1.0", "TLS 1.1"]},
    remediation="Disable TLS 1.0/1.1"
)
graph.add_scan_finding("domain-example", finding)

# Create relationship with evidence
graph.add_relationship(
    "domain-example",
    "vulnerability-weak-tls",
    RelationType.IDENTIFIES,
    "Domain scan found weak TLS configuration",
    evidence={"scan_date": "2024-08-01"},
    confidence=0.95
)

# Compute security score
score = SecurityScoreBreakdown(
    dns_config=85.0,
    port_security=70.0,
    ssl_tls=60.0,  # Low due to weak TLS
    http_headers=90.0,
    xss_protection=95.0,
    cookie_policy=85.0
)
graph.set_security_score("domain-example", score)

# Get context
context = graph.get_node_context("domain-example")
print(f"Security Score: {context['security_score']['total']}")
print(f"Findings: {len(context['findings'])}")
```

### 2. REST API - `trustgraph_api.py`

Start the server:
```bash
python trustgraph_api.py 8000
```

Available endpoints:
```bash
# Get complete graph
GET http://localhost:8000/api/graph

# Get nodes only
GET http://localhost:8000/api/graph/nodes

# Get relationships only
GET http://localhost:8000/api/graph/edges

# Get node context
GET http://localhost:8000/api/graph/node/<node_id>

# Get findings by severity
GET http://localhost:8000/api/graph/severity

# View frontend
GET http://localhost:8000/scorton-graph.html
```

### 3. Frontend Visualization

Access at: `http://localhost:8000/scorton-graph.html`

**Features:**
- ✓ Interactive D3.js force-directed graph
- ✓ Color-coded entity types
- ✓ Click to view entity details
- ✓ Hover to see relationship explanations
- ✓ Drag nodes to explore relationships
- ✓ Security score breakdown
- ✓ Critical finding count
- ✓ Severity-based coloring

## Entity Types

| Type | Icon | Color | Description |
|------|------|-------|-------------|
| Organization | 🏢 | Orange | Company or entity being assessed |
| Domain | 🌐 | Red | Internet domain name |
| IP Address | 📍 | Light Blue | IP address to scan |
| Scan Task | 🔍 | Purple | Security scanning job |
| Scan Result | 📊 | Teal | Aggregated scan findings |
| Finding | ✓ | Yellow | Individual check result |
| Vulnerability | 🚨 | Pink | Confirmed security issue |
| Security Score | 📈 | Purple | Calculated risk score |
| Policy | 📋 | Indigo | Security requirement |
| Evidence | 📎 | Slate | Supporting proof/data |

## Relationship Types

| Type | Meaning | Example |
|------|---------|---------|
| `OWNED_BY` | Organization owns target | Org owns Domain |
| `SCANNED_BY` | Target was scanned | Domain scanned_by Scan Task |
| `PRODUCES` | Scan created results | Scan produces Result |
| `CONTAINS` | Result includes findings | Result contains Finding |
| `IDENTIFIES` | Finding found vulnerability | Finding identifies Vulnerability |
| `IMPACTS` | Vulnerability affects score | Vulnerability impacts Score |
| `VIOLATES` | Breaks a policy | Config violates Policy |
| `SUPPORTED_BY` | Evidence backs claim | Vulnerability supported_by Evidence |

## Security Score Explanation

Example breakdown for `example.com`:

```
Overall Score: 72/100

Component Scores:
├─ DNS Configuration: 85/100 (20% weight = 17.0 points)
├─ Port Security: 70/100 (25% weight = 17.5 points)
├─ SSL/TLS: 60/100 (20% weight = 12.0 points)  ← Weak TLS
├─ HTTP Headers: 45/100 (15% weight = 6.75 points) ← Missing HSTS
├─ XSS Protection: 90/100 (10% weight = 9.0 points)
└─ Cookie Policy: 75/100 (10% weight = 7.5 points)

Total = 17.0 + 17.5 + 12.0 + 6.75 + 9.0 + 7.5 = 69.75 ≈ 72
```

### Interpretation

- **90-100**: Excellent security posture
- **75-89**: Good, minor issues to address
- **60-74**: Fair, notable vulnerabilities present  ← Current
- **40-59**: Poor, significant security risks
- **0-39**: Critical, immediate remediation needed

## Integration with Scorton API

To integrate with live Scorton scanning:

```python
from trustgraph_scorton import TrustGraph, EntityType, RelationType, ScanFinding
from scorton_api_client import ScoronClient  # Your Scorton API client

graph = TrustGraph()
client = ScoronClient(api_key="your-key")

# Scan a domain
domain = "example.com"
graph.add_node("domain-1", EntityType.DOMAIN, domain)

# Get scan results from Scorton API
scan_result = client.scan_domain(domain)

# Add findings to graph
for finding in scan_result.findings:
    sf = ScanFinding(
        check_type=finding['type'],
        severity=finding['severity'],
        title=finding['title'],
        description=finding['description'],
        evidence=finding['details'],
        remediation=finding.get('fix')
    )
    graph.add_scan_finding("domain-1", sf)

# Record relationships
for vuln in scan_result.vulnerabilities:
    graph.add_relationship(
        "domain-1",
        f"vuln-{vuln['id']}",
        RelationType.IDENTIFIES,
        f"Scan identified {vuln['title']}",
        evidence=vuln['evidence'],
        confidence=0.95
    )
```

## Testing

Run the test suite:

```bash
# All tests
python -m pytest tests/test_trustgraph_scorton.py -v

# Specific test class
python -m pytest tests/test_trustgraph_scorton.py::TestCybersecurityGraph -v

# With coverage
python -m pytest tests/test_trustgraph_scorton.py --cov=trustgraph_scorton
```

Test categories:
- ✓ Security score calculation (2 tests)
- ✓ Cybersecurity graph operations (5 tests)
- ✓ Sample graph creation (3 tests)
- ✓ Export and visualization (3 tests)

**All 13 tests passing**

## Files

```
scortonjs/
├── trustgraph_scorton.py          # Core module (350+ lines)
├── trustgraph_api.py              # REST API server (180+ lines)
├── frontend/
│   ├── scorton-graph.html         # Interactive visualization
│   └── (other static files)
└── tests/
    └── test_trustgraph_scorton.py # 13 comprehensive tests
```

## Key Concepts

### Explainability
Every finding traces back to:
1. **Scan source**: Which Scorton scanning method found it
2. **Evidence**: Raw data from the scan
3. **Relationships**: How it connects to other entities
4. **Impact**: How it affects the security score

### Provenance
Complete audit trail of:
- When findings were discovered
- How they've changed over time
- Supporting evidence for each claim
- Confidence levels

### Knowledge Graph Benefits
- **Relationship discovery**: See how vulnerabilities cascade
- **Impact analysis**: Understand score composition
- **Compliance mapping**: Track policy violations
- **Evidence preservation**: Maintain audit trail
- **Historical tracking**: See trends over time

## Best Practices

1. **Regular Scanning**: Keep graph updated with fresh scan results
2. **Evidence Collection**: Include detailed evidence for all findings
3. **Relationship Documentation**: Explain why entities are connected
4. **Score Tracking**: Monitor score changes over time
5. **Remediation Tracking**: Link fixes to vulnerabilities
6. **Policy Alignment**: Map findings to relevant policies

## Future Enhancements

- [ ] Real-time Scorton API integration
- [ ] Multi-scan trending and historical analysis
- [ ] Automated remediation recommendations
- [ ] Compliance scoring (PCI-DSS, HIPAA, SOC2, etc.)
- [ ] Threat intelligence integration
- [ ] Machine learning anomaly detection
- [ ] Advanced visualization (3D graph, filtering)
- [ ] Export reports (PDF, SARIF, etc.)

## References

- [TrustGraph Documentation](https://docs.trustgraph.ai/)
- [Scorton API Documentation](https://docs.scorton.tech/)
- [Knowledge Graphs](https://docs.trustgraph.ai/guides/knowledge-graphs)
- [Graph RAG](https://docs.trustgraph.ai/guides/graph-rag)
- [D3.js Visualization](https://d3js.org/)

## License

Apache 2.0 - See LICENSE file

## Support

For issues or questions:
1. Check Scorton documentation: https://docs.scorton.tech/
2. Review TrustGraph docs: https://docs.trustgraph.ai/
3. Run tests: `python -m pytest tests/test_trustgraph_scorton.py -v`
4. Check API endpoints: `GET http://localhost:8000/api/graph`

---

**Built for Scorton** | Security Intelligence through Knowledge Graphs
