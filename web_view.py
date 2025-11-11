#!/usr/bin/env python3
"""
MCP Security Framework - Web View

A simple web interface for viewing assessment reports.
Runs independently from the CLI tool.

Usage:
    python web_view.py [--port PORT] [--host HOST] [--reports-dir DIR]

Security:
    - Only binds to localhost by default
    - No external network access
    - Read-only access to reports
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from flask import Flask, render_template, jsonify, send_from_directory, abort

app = Flask(__name__)

# Add JSON filter for Jinja2 templates
@app.template_filter('tojson')
def tojson_filter(value):
    """Convert value to JSON string for display in templates."""
    return json.dumps(value, indent=2, default=str)

# Default configuration
REPORTS_DIR = Path("reports")
HOST = "127.0.0.1"  # localhost only for security
PORT = 5000


def load_report_metadata(report_dir: Path) -> Optional[Dict]:
    """Load metadata.json from a report directory."""
    metadata_path = report_dir / "metadata.json"
    if not metadata_path.exists():
        return None
    
    try:
        with open(metadata_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def load_report_json(report_dir: Path) -> Optional[Dict]:
    """Load report.json from a report directory."""
    report_path = report_dir / "report.json"
    if not report_path.exists():
        return None
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def get_all_reports(reports_dir: Path) -> List[Dict]:
    """Get list of all available reports with metadata."""
    reports = []
    
    if not reports_dir.exists():
        return reports
    
    for report_dir in sorted(reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if not report_dir.is_dir():
            continue
        
        metadata = load_report_metadata(report_dir)
        if metadata:
            reports.append({
                'id': report_dir.name,
                'name': report_dir.name.replace('_', ' '),
                'metadata': metadata,
                'path': str(report_dir.relative_to(reports_dir))
            })
    
    return reports


@app.route('/')
def index():
    """Main page showing list of all reports."""
    reports = get_all_reports(REPORTS_DIR)
    return render_template('index.html', reports=reports)


@app.route('/api/reports')
def api_reports():
    """API endpoint to get list of all reports."""
    reports = get_all_reports(REPORTS_DIR)
    return jsonify(reports)


@app.route('/report/<report_id>')
def view_report(report_id: str):
    """View a specific report."""
    # Security: prevent path traversal
    if '..' in report_id or '/' in report_id or '\\' in report_id:
        abort(404)
    
    report_dir = REPORTS_DIR / report_id
    if not report_dir.exists() or not report_dir.is_dir():
        abort(404)
    
    report_data = load_report_json(report_dir)
    metadata = load_report_metadata(report_dir)
    
    if not report_data:
        abort(404)
    
    return render_template('report.html', 
                         report_id=report_id,
                         report_name=report_id.replace('_', ' '),
                         report_data=report_data,
                         metadata=metadata)


@app.route('/api/report/<report_id>')
def api_report(report_id: str):
    """API endpoint to get a specific report as JSON."""
    # Security: prevent path traversal
    if '..' in report_id or '/' in report_id or '\\' in report_id:
        abort(404)
    
    report_dir = REPORTS_DIR / report_id
    if not report_dir.exists() or not report_dir.is_dir():
        abort(404)
    
    report_data = load_report_json(report_dir)
    if not report_data:
        abort(404)
    
    return jsonify(report_data)


@app.route('/api/report/<report_id>/sarif')
def api_report_sarif(report_id: str):
    """API endpoint to get SARIF report."""
    # Security: prevent path traversal
    if '..' in report_id or '/' in report_id or '\\' in report_id:
        abort(404)
    
    report_dir = REPORTS_DIR / report_id
    sarif_path = report_dir / "report.sarif"
    
    if not sarif_path.exists():
        abort(404)
    
    try:
        with open(sarif_path, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    except Exception:
        abort(500)


def main():
    """Main entry point."""
    global REPORTS_DIR, HOST, PORT
    
    parser = argparse.ArgumentParser(
        description="MCP Security Framework - Web View",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start web view on default port (5000)
  python web_view.py

  # Start on custom port
  python web_view.py --port 8080

  # Use custom reports directory
  python web_view.py --reports-dir ./my-reports

Security Note:
  The web view only binds to localhost (127.0.0.1) by default for security.
  Only use --host 0.0.0.0 if you understand the security implications.
        """
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to run the web server on (default: 5000)'
    )
    parser.add_argument(
        '--host',
        type=str,
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1 for localhost only)'
    )
    parser.add_argument(
        '--reports-dir',
        type=str,
        default='reports',
        help='Directory containing reports (default: ./reports)'
    )
    
    args = parser.parse_args()
    
    # Update global configuration
    REPORTS_DIR = Path(args.reports_dir).resolve()
    HOST = args.host
    PORT = args.port
    
    # Ensure reports directory exists
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    print("=" * 70)
    print("  MCP Security Framework - Web View")
    print("=" * 70)
    print(f"\n[*] Reports directory: {REPORTS_DIR}")
    print(f"[*] Server: http://{HOST}:{PORT}")
    print(f"[*] Security: {'Localhost only' if HOST == '127.0.0.1' else 'WARNING: Accessible from network'}")
    print("\n[+] Starting web server...")
    print("[+] Press Ctrl+C to stop\n")
    
    try:
        app.run(host=HOST, port=PORT, debug=False)
    except KeyboardInterrupt:
        print("\n[+] Shutting down web server...")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())

