#!/usr/bin/env python3
"""
Scorton TrustGraph API Server
Serves cybersecurity knowledge graph data for visualization and analysis
"""

import json
import sys
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from trustgraph_scorton import create_sample_scorton_graph


class TrustGraphAPIHandler(SimpleHTTPRequestHandler):
    """HTTP handler for TrustGraph API endpoints"""
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        
        # API endpoints
        if parsed_path.path == '/api/graph':
            self.serve_graph_data()
        elif parsed_path.path == '/api/graph/nodes':
            self.serve_nodes()
        elif parsed_path.path == '/api/graph/edges':
            self.serve_edges()
        elif parsed_path.path.startswith('/api/graph/node/'):
            node_id = parsed_path.path.split('/')[-1]
            self.serve_node_context(node_id)
        elif parsed_path.path == '/api/graph/severity':
            self.serve_severity_findings()
        elif parsed_path.path == '/':
            # Serve Scorton-specific frontend
            self.path = '/scorton-graph.html'
            super().do_GET()
        else:
            # Serve static files
            super().do_GET()
    
    def serve_graph_data(self):
        """Serve complete graph data"""
        try:
            graph = create_sample_scorton_graph()
            exported = graph.export_graph()
            
            # Convert to JSON-serializable format
            response = {
                "nodes": exported["nodes"],
                "edges": exported["edges"],
                "statistics": exported["statistics"]
            }
            
            self.send_json_response(response)
        except Exception as e:
            self.send_error_response(str(e))
    
    def serve_nodes(self):
        """Serve graph nodes only"""
        try:
            graph = create_sample_scorton_graph()
            exported = graph.export_graph()
            self.send_json_response({"nodes": exported["nodes"]})
        except Exception as e:
            self.send_error_response(str(e))
    
    def serve_edges(self):
        """Serve graph edges only"""
        try:
            graph = create_sample_scorton_graph()
            exported = graph.export_graph()
            self.send_json_response({"edges": exported["edges"]})
        except Exception as e:
            self.send_error_response(str(e))
    
    def serve_node_context(self, node_id):
        """Serve detailed context for a specific node"""
        try:
            graph = create_sample_scorton_graph()
            context = graph.get_node_context(node_id)
            
            if context is None:
                self.send_json_response({"error": f"Node {node_id} not found"}, status=404)
            else:
                self.send_json_response(context)
        except Exception as e:
            self.send_error_response(str(e))
    
    def serve_severity_findings(self):
        """Serve findings grouped by severity"""
        try:
            graph = create_sample_scorton_graph()
            severity_map = graph.search_by_severity()
            self.send_json_response(severity_map)
        except Exception as e:
            self.send_error_response(str(e))
    
    def send_json_response(self, data, status=200):
        """Send JSON response"""
        response_body = json.dumps(data, indent=2).encode('utf-8')
        
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response_body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response_body)
    
    def send_error_response(self, error_message, status=500):
        """Send error JSON response"""
        error_data = {"error": error_message}
        self.send_json_response(error_data, status=status)
    
    def log_message(self, format, *args):
        """Override to customize logging"""
        print(f"[{self.client_address[0]}] {format % args}")


def run_server(port=8000, directory='frontend'):
    """Run the TrustGraph API server"""
    # Change to the specified directory
    import os
    frontend_path = Path(__file__).parent / directory
    os.chdir(frontend_path)
    
    server_address = ('', port)
    httpd = HTTPServer(server_address, TrustGraphAPIHandler)
    
    print(f"""
╔════════════════════════════════════════════════════════════════╗
║         Scorton TrustGraph API Server - Started                ║
╚════════════════════════════════════════════════════════════════╝

📊 Server: http://localhost:{port}
📁 Directory: {frontend_path}

🔌 API Endpoints:
   • GET /api/graph              - Complete graph data
   • GET /api/graph/nodes        - Graph nodes only
   • GET /api/graph/edges        - Graph relationships only
   • GET /api/graph/node/<id>    - Node context and details
   • GET /api/graph/severity     - Findings by severity

🌐 Frontend:
   • GET /                       - Scorton TrustGraph visualization

📚 Features:
   ✓ Cybersecurity knowledge graph
   ✓ Entity relationship mapping
   ✓ Vulnerability tracking
   ✓ Security score computation
   ✓ Provenance tracking
   ✓ Interactive visualization

⚡ Press Ctrl+C to stop the server
    """)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n✋ Server stopped.")
        httpd.server_close()


if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port)
