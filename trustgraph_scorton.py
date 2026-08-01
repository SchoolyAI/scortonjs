"""
TrustGraph for Scorton - Cybersecurity Knowledge Graph
Combines knowledge graphs with security scanning data to provide explainable
vulnerability assessment, security scoring, and provenance tracking.

This module builds on TrustGraph principles to create a domain-specific
graph for cybersecurity analysis, integrating Scorton's scanning capabilities.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import copy
from enum import Enum


class EntityType(Enum):
    """Cybersecurity-specific entity types"""
    # Targets
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    ORGANIZATION = "organization"
    
    # Scanning
    SCAN_TASK = "scan_task"
    SCAN_RESULT = "scan_result"
    
    # Findings
    FINDING = "finding"
    VULNERABILITY = "vulnerability"
    RISK = "risk"
    
    # Security Components
    DNS_RECORD = "dns_record"
    SSL_CERT = "ssl_cert"
    HTTP_HEADER = "http_header"
    COOKIE_POLICY = "cookie_policy"
    OPEN_PORT = "open_port"
    
    # Scoring
    SECURITY_SCORE = "security_score"
    COMPLIANCE_SCORE = "compliance_score"
    TRUST_SCORE = "trust_score"
    
    # Metadata
    POLICY = "policy"
    STANDARD = "standard"
    EVIDENCE = "evidence"
    SCAN_HISTORY = "scan_history"


class RelationType(Enum):
    """Cybersecurity relationship types"""
    # Scanning
    SCANNED_BY = "scanned_by"
    PRODUCES = "produces"
    CONTAINS = "contains"
    IDENTIFIES = "identifies"
    
    # Risk
    INDICATES = "indicates"
    IMPACTS = "impacts"
    CONFIRMS = "confirms"
    MITIGATES = "mitigates"
    
    # Policy
    VIOLATES = "violates"
    COMPLIES_WITH = "complies_with"
    BASED_ON = "based_on"
    
    # Evidence
    SUPPORTED_BY = "supported_by"
    PROVES = "proves"
    CONTRADICTS = "contradicts"
    
    # Ownership
    OWNED_BY = "owned_by"
    OPERATES = "operates"
    MANAGES = "manages"


@dataclass
class ScanFinding:
    """Result of a specific scan check"""
    check_type: str  # dns, ssl, headers, xss, cookies, ports
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: Dict[str, Any]
    remediation: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class SecurityScoreBreakdown:
    """Detailed breakdown of security score computation"""
    dns_config: float = 0.0  # 20%
    port_security: float = 0.0  # 25%
    ssl_tls: float = 0.0  # 20%
    http_headers: float = 0.0  # 15%
    xss_protection: float = 0.0  # 10%
    cookie_policy: float = 0.0  # 10%
    
    def total_score(self) -> float:
        """Calculate weighted security score (0-100)"""
        weights = {
            'dns': (self.dns_config, 0.20),
            'port': (self.port_security, 0.25),
            'ssl': (self.ssl_tls, 0.20),
            'headers': (self.http_headers, 0.15),
            'xss': (self.xss_protection, 0.10),
            'cookies': (self.cookie_policy, 0.10)
        }
        return sum(score * weight for score, weight in weights.values())
    
    def contributing_factors(self) -> List[Dict[str, Any]]:
        """List all factors contributing to score"""
        return [
            {"factor": "DNS Configuration", "score": self.dns_config, "weight": 0.20},
            {"factor": "Port Security", "score": self.port_security, "weight": 0.25},
            {"factor": "SSL/TLS", "score": self.ssl_tls, "weight": 0.20},
            {"factor": "HTTP Headers", "score": self.http_headers, "weight": 0.15},
            {"factor": "XSS Protection", "score": self.xss_protection, "weight": 0.10},
            {"factor": "Cookie Policy", "score": self.cookie_policy, "weight": 0.10},
        ]


ENTITY_ICON_MAP = {
    EntityType.ORGANIZATION: {"icon": "building", "icon_class": "fas fa-building"},
    EntityType.DOMAIN: {"icon": "globe", "icon_class": "fas fa-globe-americas"},
    EntityType.IP_ADDRESS: {"icon": "network-wired", "icon_class": "fas fa-network-wired"},
    EntityType.SCAN_TASK: {"icon": "magnifying-glass", "icon_class": "fas fa-magnifying-glass"},
    EntityType.SCAN_RESULT: {"icon": "chart-line", "icon_class": "fas fa-chart-line"},
    EntityType.FINDING: {"icon": "triangle-exclamation", "icon_class": "fas fa-triangle-exclamation"},
    EntityType.VULNERABILITY: {"icon": "bug", "icon_class": "fas fa-bug"},
    EntityType.RISK: {"icon": "shield-halved", "icon_class": "fas fa-shield-halved"},
    EntityType.DNS_RECORD: {"icon": "server", "icon_class": "fas fa-server"},
    EntityType.SSL_CERT: {"icon": "lock", "icon_class": "fas fa-lock"},
    EntityType.HTTP_HEADER: {"icon": "file-code", "icon_class": "fas fa-file-code"},
    EntityType.COOKIE_POLICY: {"icon": "cookie-bite", "icon_class": "fas fa-cookie-bite"},
    EntityType.OPEN_PORT: {"icon": "plug", "icon_class": "fas fa-plug"},
    EntityType.SECURITY_SCORE: {"icon": "gauge-high", "icon_class": "fas fa-gauge-high"},
    EntityType.COMPLIANCE_SCORE: {"icon": "clipboard-check", "icon_class": "fas fa-clipboard-check"},
    EntityType.TRUST_SCORE: {"icon": "hands-holding-circle", "icon_class": "fas fa-hands-holding-circle"},
    EntityType.POLICY: {"icon": "shield", "icon_class": "fas fa-shield"},
    EntityType.STANDARD: {"icon": "file-contract", "icon_class": "fas fa-file-contract"},
    EntityType.EVIDENCE: {"icon": "file-lines", "icon_class": "fas fa-file-lines"},
    EntityType.SCAN_HISTORY: {"icon": "history", "icon_class": "fas fa-history"},
}


def get_entity_icon_metadata(entity_type: EntityType) -> Dict[str, str]:
    """Return icon metadata for visualization."""
    return ENTITY_ICON_MAP.get(entity_type, {"icon": "circle", "icon_class": "fas fa-circle"})


class TrustGraphNode:
    """Cybersecurity entity in the trust graph"""
    
    def __init__(
        self,
        node_id: str,
        entity_type: EntityType,
        label: str,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        scan_findings: Optional[List[ScanFinding]] = None,
        security_score: Optional[SecurityScoreBreakdown] = None,
    ):
        self.id = node_id
        self.type = entity_type
        self.label = label
        self.description = description
        self.metadata = metadata or {}
        self.scan_findings = scan_findings or []
        self.security_score = security_score
        self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
        self.tags = []
        self.supporting_info = {}
    
    def add_finding(self, finding: ScanFinding):
        """Record a scan finding"""
        self.scan_findings.append(finding)
        self.updated_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        icon_metadata = get_entity_icon_metadata(self.type)
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "description": self.description,
            "metadata": self.metadata,
            "findings_count": len(self.scan_findings),
            "security_score": self.security_score.total_score() if self.security_score else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tags": self.tags,
            "icon": icon_metadata["icon"],
            "icon_class": icon_metadata["icon_class"],
        }


class TrustGraphEdge:
    """Relationship between entities with provenance tracking"""
    
    def __init__(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        explanation: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
    ):
        self.source_id = source_id
        self.target_id = target_id
        self.type = relation_type
        self.explanation = explanation
        self.evidence = evidence or {}
        self.confidence = confidence
        self.origin = "scorton_scan"  # Source of this relationship
        self.created_at = datetime.now().isoformat()
        self.history = [self._snapshot()]
    
    def _snapshot(self) -> Dict[str, Any]:
        """Create a snapshot of current state"""
        return {
            "type": self.type.value,
            "explanation": self.explanation,
            "evidence": copy.deepcopy(self.evidence),
            "confidence": self.confidence,
            "timestamp": datetime.now().isoformat(),
        }
    
    def update(self, explanation: str = "", evidence: Optional[Dict[str, Any]] = None, confidence: float = 1.0):
        """Update relationship with new information"""
        self.explanation = explanation or self.explanation
        self.evidence = evidence or self.evidence
        self.confidence = confidence
        self.history.append(self._snapshot())
    
    def get_provenance(self) -> Dict[str, Any]:
        """Get full provenance information"""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship_type": self.type.value,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "origin": self.origin,
            "created_at": self.created_at,
            "update_history": self.history,
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.type.value,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "evidence_count": len(self.evidence),
        }


class TrustGraph:
    """Scorton cybersecurity knowledge graph with explainability"""
    
    def __init__(self):
        self.nodes: Dict[str, TrustGraphNode] = {}
        self.edges: Dict[str, TrustGraphEdge] = {}
        self.created_at = datetime.now().isoformat()
    
    def add_node(
        self,
        node_id: str,
        entity_type: EntityType,
        label: str,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TrustGraphNode:
        """Add a cybersecurity entity to the graph"""
        node = TrustGraphNode(node_id, entity_type, label, description, metadata)
        self.nodes[node_id] = node
        return node
    
    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        explanation: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
    ) -> TrustGraphEdge:
        """Add a security-grounded relationship"""
        edge_id = f"{source_id}_{relation_type.value}_{target_id}"
        edge = TrustGraphEdge(source_id, target_id, relation_type, explanation, evidence, confidence)
        self.edges[edge_id] = edge
        return edge
    
    def update_relationship(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        explanation: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
    ):
        """Update relationship with new evidence"""
        edge_id = f"{source_id}_{relation_type.value}_{target_id}"
        if edge_id in self.edges:
            self.edges[edge_id].update(explanation, evidence, confidence)
    
    def add_scan_finding(self, node_id: str, finding: ScanFinding):
        """Record a scan finding for an entity"""
        if node_id in self.nodes:
            self.nodes[node_id].add_finding(finding)
    
    def set_security_score(self, node_id: str, score: SecurityScoreBreakdown):
        """Set security score for a node"""
        if node_id in self.nodes:
            self.nodes[node_id].security_score = score
    
    def get_node_context(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get complete context for a node"""
        if node_id not in self.nodes:
            return None
        
        node = self.nodes[node_id]
        
        # Find all relationships
        outgoing = [e for e in self.edges.values() if e.source_id == node_id]
        incoming = [e for e in self.edges.values() if e.target_id == node_id]
        
        return {
            "node": node.to_dict(),
            "findings": [
                {
                    "check_type": f.check_type,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in node.scan_findings
            ],
            "security_score": {
                "total": node.security_score.total_score() if node.security_score else None,
                "breakdown": node.security_score.contributing_factors() if node.security_score else None,
            },
            "relationships": {
                "outgoing": [e.to_dict() for e in outgoing],
                "incoming": [e.to_dict() for e in incoming],
            },
            "provenance": {
                "created_at": node.created_at,
                "updated_at": node.updated_at,
                "sources": list(set(e.origin for e in outgoing + incoming)),
            }
        }
    
    def search_by_type(self, entity_type: EntityType) -> List[TrustGraphNode]:
        """Search entities by type"""
        return [n for n in self.nodes.values() if n.type == entity_type]
    
    def search_by_severity(self) -> Dict[str, List[str]]:
        """Find high-severity findings across graph"""
        result = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for node in self.nodes.values():
            for finding in node.scan_findings:
                result[finding.severity].append(f"{node.label}: {finding.title}")
        return result
    
    def get_score_history(self, node_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get security score evolution for a node"""
        if node_id not in self.nodes:
            return None
        # This would be extended with actual historical tracking
        return [self.nodes[node_id].to_dict()]
    
    def export_graph(self) -> Dict[str, Any]:
        """Export complete graph for visualization"""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "statistics": {
                "total_nodes": len(self.nodes),
                "total_relationships": len(self.edges),
                "entity_types": [t.value for t in EntityType],
                "created_at": self.created_at,
            }
        }


def create_sample_scorton_graph() -> TrustGraph:
    """Create sample Scorton security assessment graph"""
    graph = TrustGraph()
    
    # Organization
    graph.add_node(
        "org-acme",
        EntityType.ORGANIZATION,
        "ACME Corp",
        "Technology company needing security assessment"
    )
    
    # Domain
    graph.add_node(
        "domain-acme",
        EntityType.DOMAIN,
        "example.com",
        "Main web presence"
    )
    
    # IP Address
    graph.add_node(
        "ip-1",
        EntityType.IP_ADDRESS,
        "192.0.2.1",
        "Primary web server IP"
    )
    
    # Scan Task
    graph.add_node(
        "scan-1",
        EntityType.SCAN_TASK,
        "Security Scan #1",
        "Comprehensive security assessment on 2024-08-01"
    )
    
    # Scan Result
    graph.add_node(
        "result-1",
        EntityType.SCAN_RESULT,
        "Scan Result #1",
        "Aggregated findings from scan #1"
    )
    
    # Findings
    graph.add_node(
        "finding-dns",
        EntityType.FINDING,
        "DNS Config",
        "DNS records properly configured"
    )
    
    graph.add_node(
        "finding-ssl",
        EntityType.FINDING,
        "SSL Certificate",
        "SSL/TLS certificate validation"
    )
    
    graph.add_node(
        "finding-headers",
        EntityType.FINDING,
        "Missing Security Headers",
        "Missing critical HTTP security headers"
    )
    
    # Vulnerabilities
    graph.add_node(
        "vuln-missing-hsts",
        EntityType.VULNERABILITY,
        "Missing HSTS Header",
        "HTTP Strict Transport Security header not found"
    )
    
    graph.add_node(
        "vuln-weak-ssl",
        EntityType.VULNERABILITY,
        "Outdated TLS Version",
        "TLS 1.0 and 1.1 still enabled"
    )
    
    # Security Score
    graph.add_node(
        "score-acme",
        EntityType.SECURITY_SCORE,
        "ACME Security Score",
        "Overall security assessment score"
    )
    
    # Policies
    graph.add_node(
        "policy-hsts",
        EntityType.POLICY,
        "HSTS Policy",
        "HTTP Strict Transport Security requirement"
    )
    
    # Relationships
    graph.add_relationship(
        "org-acme", "domain-acme",
        RelationType.OPERATES,
        "Organization operates this domain"
    )
    
    graph.add_relationship(
        "domain-acme", "scan-1",
        RelationType.SCANNED_BY,
        "Domain was scanned for vulnerabilities",
        {"scan_date": "2024-08-01", "duration_seconds": 45}
    )
    
    graph.add_relationship(
        "scan-1", "result-1",
        RelationType.PRODUCES,
        "Scan produced detailed results",
        {"total_findings": 15, "critical": 2, "high": 3}
    )
    
    graph.add_relationship(
        "result-1", "finding-dns",
        RelationType.CONTAINS,
        "Results contain DNS findings"
    )

    graph.add_relationship(
        "result-1", "finding-ssl",
        RelationType.CONTAINS,
        "Results contain SSL findings"
    )
    
    graph.add_relationship(
        "result-1", "finding-headers",
        RelationType.CONTAINS,
        "Results contain HTTP header analysis"
    )
    
    graph.add_relationship(
        "finding-ssl", "vuln-weak-ssl",
        RelationType.IDENTIFIES,
        "SSL findings indicate outdated TLS version",
        {"evidence": "TLS 1.0 and 1.1 are still enabled", "severity": "high"}
    )
    
    graph.add_relationship(
        "finding-headers", "vuln-missing-hsts",
        RelationType.IDENTIFIES,
        "Missing headers indicate HSTS vulnerability",
        {"evidence": "No HSTS header in response", "severity": "high"}
    )
    
    graph.add_relationship(
        "vuln-weak-ssl", "score-acme",
        RelationType.IMPACTS,
        "TLS weakness reduces security score",
        {"score_impact": -6}
    )
    
    graph.add_relationship(
        "vuln-missing-hsts", "score-acme",
        RelationType.IMPACTS,
        "Vulnerability reduces security score",
        {"score_impact": -8}
    )
    
    graph.add_relationship(
        "vuln-missing-hsts", "policy-hsts",
        RelationType.VIOLATES,
        "Missing header violates HSTS policy"
    )
    
    # Add security score
    score = SecurityScoreBreakdown(
        dns_config=85.0,
        port_security=70.0,
        ssl_tls=60.0,
        http_headers=45.0,
        xss_protection=90.0,
        cookie_policy=75.0
    )
    graph.set_security_score("score-acme", score)
    
    # Add scan findings
    finding1 = ScanFinding(
        check_type="headers",
        severity="high",
        title="Missing HSTS Header",
        description="HTTP Strict-Transport-Security header is missing",
        evidence={"expected": "Strict-Transport-Security: max-age=31536000", "actual": "not present"},
        remediation="Add HSTS header to all HTTPS responses"
    )
    graph.add_scan_finding("finding-headers", finding1)
    
    finding2 = ScanFinding(
        check_type="ssl",
        severity="high",
        title="Weak TLS Versions Enabled",
        description="TLS 1.0 and 1.1 are still enabled",
        evidence={"protocols_found": ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]},
        remediation="Disable TLS 1.0 and 1.1, keep only 1.2 and 1.3"
    )
    graph.add_scan_finding("finding-ssl", finding2)
    
    return graph
