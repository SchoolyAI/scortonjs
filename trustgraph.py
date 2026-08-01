from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple


class TrustGraphNode:
    """A semantically rich node in a TrustGraph context graph."""

    def __init__(
        self,
        id: str,
        name: str,
        entity_type: str,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        connected_entities: Optional[List[str]] = None,
        timestamps: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        supporting_info: Optional[List[str]] = None,
    ) -> None:
        self.id = id
        self.name = name
        self.entity_type = entity_type
        self.description = description or ""
        self.metadata = metadata or {}
        self.connected_entities = connected_entities or []
        self.timestamps = timestamps or {}
        self.tags = tags or []
        self.supporting_info = supporting_info or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "entity_type": self.entity_type,
            "description": self.description,
            "metadata": deepcopy(self.metadata),
            "connected_entities": list(self.connected_entities),
            "timestamps": deepcopy(self.timestamps),
            "tags": list(self.tags),
            "supporting_info": list(self.supporting_info),
        }


class TrustGraphEdge:
    """An explainable, provenance-rich relationship in a TrustGraph."""

    def __init__(
        self,
        id: str,
        source_id: str,
        target_id: str,
        predicate: str,
        explanation: str,
        evidence: Optional[List[str]] = None,
        provenance: Optional[Dict[str, Any]] = None,
        origin: Optional[str] = None,
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.id = id
        self.source_id = source_id
        self.target_id = target_id
        self.predicate = predicate
        self.explanation = explanation
        self.evidence = evidence or []
        self.provenance = provenance or {}
        self.origin = origin or ""
        self.history = history or [{
            "explanation": explanation,
            "evidence": list(self.evidence),
            "provenance": deepcopy(self.provenance),
            "origin": self.origin,
        }]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "predicate": self.predicate,
            "explanation": self.explanation,
            "evidence": list(self.evidence),
            "provenance": deepcopy(self.provenance),
            "origin": self.origin,
            "history": deepcopy(self.history),
        }


class TrustGraph:
    """A lightweight explainable context graph for trust reasoning."""

    def __init__(self, name: str = "trustgraph") -> None:
        self.name = name
        self.nodes: Dict[str, TrustGraphNode] = {}
        self.edges: Dict[str, TrustGraphEdge] = {}

    def add_node(self, node: TrustGraphNode) -> None:
        self.nodes[node.id] = node

    def add_relationship(self, edge: TrustGraphEdge) -> None:
        self.edges[edge.id] = edge
        self.nodes.setdefault(edge.source_id, TrustGraphNode(id=edge.source_id, name=edge.source_id, entity_type="unknown"))
        self.nodes.setdefault(edge.target_id, TrustGraphNode(id=edge.target_id, name=edge.target_id, entity_type="unknown"))

    def update_relationship(self, edge_id: str, explanation: Optional[str] = None, evidence: Optional[List[str]] = None, provenance: Optional[Dict[str, Any]] = None, origin: Optional[str] = None) -> TrustGraphEdge:
        edge = self.edges[edge_id]
        if explanation is not None:
            edge.explanation = explanation
        if evidence is not None:
            edge.evidence = evidence
        if provenance is not None:
            edge.provenance = provenance
        if origin is not None:
            edge.origin = origin
        edge.history.append({
            "explanation": edge.explanation,
            "evidence": list(edge.evidence),
            "provenance": deepcopy(edge.provenance),
            "origin": edge.origin,
        })
        return edge

    def get_node_context(self, node_id: str) -> Dict[str, Any]:
        node = self.nodes[node_id]
        matched_edges = [
            edge
            for edge in self.edges.values()
            if edge.source_id == node_id or edge.target_id == node_id
        ]
        relationships = [edge.to_dict() for edge in matched_edges]
        related_entities = [
            {"id": edge.target_id if edge.source_id == node_id else edge.source_id}
            for edge in matched_edges
        ]
        return {
            "node": node.to_dict(),
            "relationships": relationships,
            "related_entities": related_entities,
        }

    def search_nodes(self, query: str) -> List[Dict[str, Any]]:
        query = query.lower()
        return [
            node.to_dict()
            for node in self.nodes.values()
            if query in node.name.lower() or query in node.description.lower() or query in " ".join(node.tags).lower()
        ]

    def filter_nodes(self, entity_type: Optional[str] = None, tag: Optional[str] = None) -> List[Dict[str, Any]]:
        nodes = []
        for node in self.nodes.values():
            if entity_type and node.entity_type != entity_type:
                continue
            if tag and tag not in node.tags:
                continue
            nodes.append(node.to_dict())
        return nodes

    def get_history(self, edge_id: str) -> List[Dict[str, Any]]:
        return deepcopy(self.edges[edge_id].history)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges.values()],
        }
