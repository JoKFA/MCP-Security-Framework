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
import asyncio
import threading
import traceback
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from flask import Flask, render_template, jsonify, abort, request

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





# Assessment status tracking
assessment_status = {}
assessment_lock = threading.Lock()


class LogCapture:
    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self.logs = []
        self.stdout = sys.stdout
        self.stderr = sys.stderr
    
    def write(self, text):
        if text.strip():
            self.logs.append(text.rstrip())
            if len(self.logs) > 100:
                self.logs = self.logs[-100:]
            with assessment_lock:
                if self.assessment_id in assessment_status:
                    assessment_status[self.assessment_id]['logs'] = self.logs[-20:]
        self.stdout.write(text)
    
    def flush(self):
        self.stdout.flush()
    
    def fileno(self):
        return self.stdout.fileno()
    
    def isatty(self):
        return self.stdout.isatty()
    
    def __enter__(self):
        sys.stdout = self
        sys.stderr = self
        return self
    
    def __exit__(self, *args):
        sys.stdout = self.stdout
        sys.stderr = self.stderr






def validate_report_id(report_id: str):
    if '..' in report_id or '/' in report_id or '\\' in report_id:
        abort(404)


@app.route('/')
def index():
    reports = get_all_reports(REPORTS_DIR)
    return render_template('index.html', reports=reports)


@app.route('/assess')
def assess_page():
    return render_template('assess.html')


@app.route('/api/assess', methods=['POST'])
def api_assess():
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    target = data.get('target')
    mode = data.get('mode', 'balanced')
    
    if not target:
        return jsonify({'error': 'target is required'}), 400
    
    assessment_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    with assessment_lock:
        assessment_status[assessment_id] = {
            'status': 'running',
            'message': 'Starting assessment...',
            'progress': 0,
            'error': None,
            'report_id': None
        }
    
    thread = threading.Thread(
        target=run_assessment,
        args=(target, mode, assessment_id),
        daemon=True
    )
    thread.start()
    
    return jsonify({
        'assessment_id': assessment_id,
        'status': 'started',
        'message': 'Assessment started'
    })


@app.route('/api/assess/<assessment_id>/status')
def api_assess_status(assessment_id: str):
    with assessment_lock:
        status = assessment_status.get(assessment_id, {
            'status': 'unknown',
            'message': 'Assessment not found'
        })
    return jsonify(status)


def run_assessment(target: str, mode: str, assessment_id: str):
    with LogCapture(assessment_id):
        try:
            with assessment_lock:
                assessment_status[assessment_id]['message'] = 'Connecting to server...'
                assessment_status[assessment_id]['progress'] = 10
                assessment_status[assessment_id]['logs'] = []
            
            from src.core.runner import TestRunner
            from src.core.policy import ScopeConfig, RateLimitConfig, PolicyConfig
            from src.core.reporters.manager import ReportManager
            
            if target.startswith("stdio://"):
                stdio_part = target[8:]
                parts = stdio_part.split("/")
                command = parts[0] if parts else "npx"
                args = []
                
                i = 1
                while i < len(parts):
                    arg = parts[i]
                    if arg.startswith("@") and i + 1 < len(parts):
                        args.append(f"{arg}/{parts[i+1]}")
                        i += 2
                    else:
                        if arg:
                            args.append(arg)
                        i += 1
                
                if args:
                    target = f"stdio://{command}/{'/'.join(args)}"
                else:
                    target = f"stdio://{command}"
            
            scope = ScopeConfig(
                target=target,
                mode=mode,
                allowed_prefixes=["internal://", "file://", "/resources", "/tools/"],
                blocked_paths=[],
                rate_limit=RateLimitConfig(qps=3, burst=5),
                policy=PolicyConfig(
                    dry_run=False,
                    redact_evidence=True,
                    max_payload_kb=256,
                    max_total_requests=1000,
                )
            )
            
            with assessment_lock:
                assessment_status[assessment_id]['message'] = 'Running detectors...'
                assessment_status[assessment_id]['progress'] = 30
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            runner = TestRunner(scope)
            result = loop.run_until_complete(runner.assess())
            
            with assessment_lock:
                assessment_status[assessment_id]['message'] = 'Generating reports...'
                assessment_status[assessment_id]['progress'] = 80
            
            server_name = result.profile.server_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
            report_manager = ReportManager(reports_dir=REPORTS_DIR)
            bundle_dir = report_manager.generate_bundle(result, bundle_name=server_name)
            report_id = bundle_dir.name
            
            with assessment_lock:
                assessment_status[assessment_id]['status'] = 'completed'
                assessment_status[assessment_id]['message'] = 'Assessment completed successfully'
                assessment_status[assessment_id]['progress'] = 100
                assessment_status[assessment_id]['report_id'] = report_id
            
            loop.close()
            
        except Exception as e:
            with assessment_lock:
                assessment_status[assessment_id]['status'] = 'error'
                assessment_status[assessment_id]['message'] = f'Assessment failed: {str(e)}'
                assessment_status[assessment_id]['error'] = traceback.format_exc()
                assessment_status[assessment_id]['progress'] = 0


@app.route('/api/reports')
def api_reports():
    reports = get_all_reports(REPORTS_DIR)
    return jsonify(reports)


@app.route('/report/<report_id>')
def view_report(report_id: str):
    validate_report_id(report_id)
    
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
    validate_report_id(report_id)
    
    report_dir = REPORTS_DIR / report_id
    if not report_dir.exists() or not report_dir.is_dir():
        abort(404)
    
    report_data = load_report_json(report_dir)
    if not report_data:
        abort(404)
    
    return jsonify(report_data)


@app.route('/api/report/<report_id>/sarif')
def api_report_sarif(report_id: str):
    validate_report_id(report_id)
    
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

