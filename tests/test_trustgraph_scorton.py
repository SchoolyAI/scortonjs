"""
Tests for TrustGraph Scorton - Cybersecurity Knowledge Graph
Validates explainability, provenance tracking, and security scoring
"""

import pytest
from trustgraph_scorton import (
    TrustGraph,
    EntityType,
    RelationType,
    ScanFinding,
    SecurityScoreBreakdown,
    create_sample_scorton_graph,
)


class TestScoringBreakdown:
    """Test security score computation"""
    
    def test_security_score_calculation(self):
        """Verify score calculation from components"""
        score = SecurityScoreBreakdown(
            dns_config=100.0,      # 20% weight
            port_security=80.0,    # 25% weight
            ssl_tls=70.0,         # 20% weight
            http_headers=60.0,    # 15% weight
            xss_protection=90.0,  # 10% weight
            cookie_policy=80.0    # 10% weight
        )
        
        total = score.total_score()
        # 100*0.2 + 80*0.25 + 70*0.2 + 60*0.15 + 90*0.1 + 80*0.1
        # = 20 + 20 + 14 + 9 + 9 + 8 = 80
        assert 79.9 < total < 80.1
    
    def test_contributing_factors(self):
        """Verify score breakdown shows all factors"""
        score = SecurityScoreBreakdown(dns_config=100.0)
        factors = score.contributing_factors()
        
        assert len(factors) == 6
        assert any(f["factor"] == "DNS Configuration" for f in factors)
        assert all("score" in f and "weight" in f for f in factors)


class TestCybersecurityGraph:
    """Test graph operations with security entities"""
    
    def test_add_security_entity(self):
        """Test adding cybersecurity entities"""
        graph = TrustGraph()
        
        node = graph.add_node(
            "domain-1",
            EntityType.DOMAIN,
            "example.com",
            "Sample domain"
        )
        
        assert node.id == "domain-1"
        assert node.type == EntityType.DOMAIN
        assert node.label == "example.com"
    
    def test_scan_findings_tracking(self):
        """Test recording and retrieving scan findings"""
        graph = TrustGraph()
        graph.add_node("domain-1", EntityType.DOMAIN, "example.com")
        
        finding = ScanFinding(
            check_type="ssl",
            severity="high",
            title="Weak TLS",
            description="TLS 1.0 enabled",
            evidence={"protocols": ["TLS 1.0"]}
        )
        
        graph.add_scan_finding("domain-1", finding)
        context = graph.get_node_context("domain-1")
        
        assert len(context["findings"]) == 1
        assert context["findings"][0]["severity"] == "high"
        assert context["findings"][0]["check_type"] == "ssl"
    
    def test_security_relationship_with_evidence(self):
        """Test security relationships track evidence"""
        graph = TrustGraph()
        graph.add_node("domain-1", EntityType.DOMAIN, "example.com")
        graph.add_node("vuln-1", EntityType.VULNERABILITY, "Missing HSTS")
        
        edge = graph.add_relationship(
            "domain-1", "vuln-1",
            RelationType.IDENTIFIES,
            "Domain scan identified HSTS vulnerability",
            evidence={"missing_header": "Strict-Transport-Security", "severity": "high"},
            confidence=0.95
        )
        
        provenance = edge.get_provenance()
        assert provenance["confidence"] == 0.95
        assert "missing_header" in provenance["evidence"]
        assert provenance["origin"] == "scorton_scan"
    
    def test_finding_severity_search(self):
        """Test searching for critical findings"""
        graph = TrustGraph()
        
        # Add nodes with findings
        graph.add_node("domain-1", EntityType.DOMAIN, "example.com")
        graph.add_node("domain-2", EntityType.DOMAIN, "test.com")
        
        # Critical finding
        finding1 = ScanFinding(
            check_type="ssl", severity="critical",
            title="No HTTPS", description="", evidence={}
        )
        graph.add_scan_finding("domain-1", finding1)
        
        # High finding
        finding2 = ScanFinding(
            check_type="headers", severity="high",
            title="Missing CSP", description="", evidence={}
        )
        graph.add_scan_finding("domain-2", finding2)
        
        # Low finding
        finding3 = ScanFinding(
            check_type="dns", severity="low",
            title="Slow DNS", description="", evidence={}
        )
        graph.add_scan_finding("domain-2", finding3)
        
        severity_map = graph.search_by_severity()
        assert len(severity_map["critical"]) > 0
        assert len(severity_map["high"]) > 0
        assert len(severity_map["low"]) > 0
    
    def test_security_score_assignment(self):
        """Test assigning security scores to domains"""
        graph = TrustGraph()
        graph.add_node("domain-1", EntityType.DOMAIN, "example.com")
        
        score = SecurityScoreBreakdown(
            dns_config=90.0,
            port_security=85.0,
            ssl_tls=75.0,
            http_headers=70.0,
            xss_protection=95.0,
            cookie_policy=80.0
        )
        
        graph.set_security_score("domain-1", score)
        context = graph.get_node_context("domain-1")
        
        assert context["security_score"]["total"] is not None
        assert 0 <= context["security_score"]["total"] <= 100
        assert len(context["security_score"]["breakdown"]) == 6


class TestSampleGraph:
    """Test the sample Scorton security assessment graph"""
    
    def test_sample_graph_creation(self):
        """Test sample graph builds without errors"""
        graph = create_sample_scorton_graph()
        
        assert len(graph.nodes) > 0
        assert len(graph.edges) > 0
    
    def test_sample_graph_relationships(self):
        """Test sample graph has proper security flow"""
        graph = create_sample_scorton_graph()
        
        # Should have domain scanned
        domain_nodes = graph.search_by_type(EntityType.DOMAIN)
        assert len(domain_nodes) > 0
        
        # Should have vulnerabilities
        vuln_nodes = graph.search_by_type(EntityType.VULNERABILITY)
        assert len(vuln_nodes) > 0
        
        # Should have security score
        score_nodes = graph.search_by_type(EntityType.SECURITY_SCORE)
        assert len(score_nodes) > 0
    
    def test_sample_graph_provenance(self):
        """Test sample graph tracks full provenance"""
        graph = create_sample_scorton_graph()
        
        # Get context for a domain
        domain_nodes = graph.search_by_type(EntityType.DOMAIN)
        if domain_nodes:
            domain_id = domain_nodes[0].id
            context = graph.get_node_context(domain_id)
            
            # Should have provenance info
            assert "provenance" in context
            assert "created_at" in context["provenance"]
            assert "sources" in context["provenance"]

    def test_tls_vulnerability_is_connected(self):
        """Test the TLS vulnerability is connected to the rest of the graph"""
        graph = create_sample_scorton_graph()
        exported = graph.export_graph()

        tls_edges = [
            edge for edge in exported["edges"]
            if edge["source"] == "vuln-weak-ssl" or edge["target"] == "vuln-weak-ssl"
        ]

        assert len(tls_edges) > 0


class TestExportAndVisualization:
    """Test graph export for frontend visualization"""
    
    def test_export_graph_structure(self):
        """Test exporting graph maintains all data"""
        graph = create_sample_scorton_graph()
        exported = graph.export_graph()
        
        assert "nodes" in exported
        assert "edges" in exported
        assert "statistics" in exported
        assert exported["statistics"]["total_nodes"] > 0
        assert exported["statistics"]["total_relationships"] > 0
    
    def test_node_serialization(self):
        """Test nodes serialize correctly for frontend"""
        graph = TrustGraph()
        graph.add_node("domain-1", EntityType.DOMAIN, "example.com")
        
        exported = graph.export_graph()
        nodes = exported["nodes"]
        
        assert len(nodes) == 1
        assert nodes[0]["id"] == "domain-1"
        assert nodes[0]["type"] == "domain"
        assert nodes[0]["label"] == "example.com"
    
    def test_export_graph_includes_icon_metadata(self):
        """Test nodes expose icon metadata for the frontend"""
        graph = create_sample_scorton_graph()
        exported = graph.export_graph()

        assert len(exported["nodes"]) > 0
        for node in exported["nodes"]:
            assert "icon" in node
            assert "icon_class" in node

    def test_edge_serialization(self):
        """Test relationships serialize correctly for frontend"""
        graph = TrustGraph()
        graph.add_node("domain-1", EntityType.DOMAIN, "example.com")
        graph.add_node("vuln-1", EntityType.VULNERABILITY, "XSS")
        
        graph.add_relationship(
            "domain-1", "vuln-1",
            RelationType.IDENTIFIES,
            "Found vulnerability",
            confidence=0.9
        )
        
        exported = graph.export_graph()
        edges = exported["edges"]
        
        assert len(edges) == 1
        assert edges[0]["source"] == "domain-1"
        assert edges[0]["target"] == "vuln-1"
        assert edges[0]["confidence"] == 0.9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
