import pytest

from trustgraph import TrustGraph, TrustGraphNode, TrustGraphEdge


def test_graph_nodes_capture_context_and_provenance():
    graph = TrustGraph(name="trustscore-context")

    organization = TrustGraphNode(
        id="entity:acme",
        name="Acme Corp",
        entity_type="organization",
        description="Vendor under review for compliance risk",
        metadata={"risk_score": 0.72},
        tags=["vendor", "critical"],
        supporting_info=["Registered in 2023"],
        timestamps={"created": "2024-01-01"},
    )
    person = TrustGraphNode(
        id="entity:jane",
        name="Jane Doe",
        entity_type="person",
        description="Primary compliance contact",
        tags=["contact"],
    )
    graph.add_node(organization)
    graph.add_node(person)

    relationship = TrustGraphEdge(
        id="rel:acme-jane",
        source_id="entity:acme",
        target_id="entity:jane",
        predicate="employs",
        explanation="Acme Corp employs Jane Doe as its compliance officer.",
        evidence=["employment record", "HR export"],
        provenance={"source": "hr_export", "source_type": "document"},
        origin="HR system",
    )
    graph.add_relationship(relationship)

    context = graph.get_node_context("entity:acme")

    assert context["node"]["name"] == "Acme Corp"
    assert context["relationships"][0]["explanation"].startswith("Acme Corp employs")
    assert context["related_entities"][0]["id"] == "entity:jane"
    assert relationship.provenance["source"] == "hr_export"


def test_graph_keeps_relationship_history_and_supports_updates():
    graph = TrustGraph()
    node_a = TrustGraphNode(id="entity:a", name="Alpha", entity_type="organization")
    node_b = TrustGraphNode(id="entity:b", name="Beta", entity_type="organization")
    graph.add_node(node_a)
    graph.add_node(node_b)

    edge = TrustGraphEdge(
        id="rel:alpha-beta",
        source_id="entity:a",
        target_id="entity:b",
        predicate="shares_control",
        explanation="Alpha and Beta share a delegated control relationship.",
        evidence=["policy document"],
        provenance={"source": "policy"},
        origin="Policy review",
    )
    graph.add_relationship(edge)

    graph.update_relationship(
        "rel:alpha-beta",
        explanation="Updated after verification from the audit log.",
        evidence=["policy document", "audit log"],
    )

    history = graph.get_history("rel:alpha-beta")
    assert len(history) == 2
    assert history[-1]["explanation"].startswith("Updated after verification")
    assert history[-1]["evidence"][-1] == "audit log"


def test_graph_supports_search_and_semantic_filtering():
    graph = TrustGraph()
    graph.add_node(TrustGraphNode(id="entity:1", name="Compliance Office", entity_type="team", tags=["governance"], description="Handles policy oversight"))
    graph.add_node(TrustGraphNode(id="entity:2", name="Vendor Portal", entity_type="system", tags=["vendor"], description="Used for external onboarding"))

    graph.add_relationship(
        TrustGraphEdge(
            id="rel:1",
            source_id="entity:1",
            target_id="entity:2",
            predicate="oversees",
            explanation="The Compliance Office oversees the Vendor Portal.",
            evidence=["access policy"],
            provenance={"source": "policy"},
            origin="Governance policy",
        )
    )

    matches = graph.search_nodes("policy")
    assert any(node["id"] == "entity:1" for node in matches)

    filtered = graph.filter_nodes(entity_type="team", tag="governance")
    assert filtered[0]["id"] == "entity:1"
