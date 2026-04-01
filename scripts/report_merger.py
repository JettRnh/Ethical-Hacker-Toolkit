#!/usr/bin/env python3
"""
Report merger utility for Ethical Hacker Toolkit
Combine multiple reports into a single comprehensive report
Author: Jet
GitHub: https://github.com/JettRnh
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import REPORT_DIR
from core.logger import log

def get_report_files():
    """Get all report files from reports directory"""
    reports = []
    
    for ext in ['*.txt', '*.json', '*.html']:
        for f in REPORT_DIR.glob(ext):
            reports.append(f)
    
    return sorted(reports, key=lambda x: x.stat().st_mtime)

def merge_txt_reports(reports, output_file):
    """Merge text reports into single file"""
    with open(output_file, 'w') as out:
        out.write("=" * 70 + "\n")
        out.write("ETHICAL HACKER TOOLKIT - COMPREHENSIVE REPORT\n")
        out.write("=" * 70 + "\n")
        out.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write("=" * 70 + "\n\n")
        
        for report in reports:
            out.write(f"\n{'=' * 70}\n")
            out.write(f"Source: {report.name}\n")
            out.write(f"Date: {datetime.fromtimestamp(report.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}\n")
            out.write(f"{'=' * 70}\n\n")
            
            with open(report, 'r') as f:
                out.write(f.read())
            out.write("\n\n")

def merge_json_reports(reports, output_file):
    """Merge JSON reports into single JSON array"""
    all_data = []
    
    for report in reports:
        try:
            with open(report, 'r') as f:
                data = json.load(f)
                data['source_file'] = report.name
                all_data.append(data)
        except json.JSONDecodeError:
            log.error(f"Invalid JSON in {report.name}")
    
    with open(output_file, 'w') as out:
        json.dump({
            'merged_at': datetime.now().isoformat(),
            'report_count': len(all_data),
            'reports': all_data
        }, out, indent=2)

def merge_html_reports(reports, output_file):
    """Merge HTML reports into single HTML document"""
    with open(output_file, 'w') as out:
        out.write("""<!DOCTYPE html>
<html>
<head>
    <title>EHT - Comprehensive Report</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            margin: 40px;
        }
        h1 {
            color: #00ff00;
            border-bottom: 2px solid #00ff00;
            padding-bottom: 10px;
        }
        .report-section {
            background: #111;
            margin: 20px 0;
            padding: 20px;
            border-left: 4px solid #00ff00;
        }
        .report-header {
            background: #1a1a1a;
            padding: 10px;
            margin-bottom: 20px;
        }
        hr {
            border-color: #00ff00;
        }
        .footer {
            margin-top: 30px;
            padding: 10px;
            background: #1a1a1a;
            text-align: center;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <h1>Ethical Hacker Toolkit - Comprehensive Report</h1>
    <div class="report-header">
        Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """<br>
        Total Reports: """ + str(len(reports)) + """
    </div>
""")
        
        for i, report in enumerate(reports, 1):
            out.write(f"""
    <div class="report-section">
        <h3>Report {i}: {report.name}</h3>
        <small>{datetime.fromtimestamp(report.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}</small>
        <hr>
""")
            with open(report, 'r') as f:
                content = f.read()
                # Extract body content if it's an HTML report
                if '<body' in content:
                    import re
                    body_match = re.search(r'<body[^>]*>(.*?)</body>', content, re.DOTALL)
                    if body_match:
                        content = body_match.group(1)
                out.write(content)
            out.write("""
    </div>
""")
        
        out.write("""
    <div class="footer">
        Ethical Hacker Toolkit | Author: Jet | GitHub: https://github.com/JettRnh
    </div>
</body>
</html>""")

def main():
    """Main merger function"""
    print("\nEthical Hacker Toolkit - Report Merger")
    print("=======================================")
    print()
    
    reports = get_report_files()
    
    if not reports:
        print("No reports found in reports directory.")
        return
    
    print(f"Found {len(reports)} reports:")
    for i, report in enumerate(reports, 1):
        size = report.stat().st_size / 1024
        print(f"  {i}. {report.name} ({size:.1f} KB)")
    
    print()
    print("Output formats:")
    print("  1. Text (merged.txt)")
    print("  2. JSON (merged.json)")
    print("  3. HTML (merged.html)")
    print("  4. All formats")
    print()
    
    choice = input("Select output format [1-4]: ").strip()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if choice in ['1', '4']:
        output = REPORT_DIR / f"merged_{timestamp}.txt"
        merge_txt_reports(reports, output)
        print(f"Created: {output}")
    
    if choice in ['2', '4']:
        output = REPORT_DIR / f"merged_{timestamp}.json"
        merge_json_reports(reports, output)
        print(f"Created: {output}")
    
    if choice in ['3', '4']:
        output = REPORT_DIR / f"merged_{timestamp}.html"
        merge_html_reports(reports, output)
        print(f"Created: {output}")
    
    print("\nMerge completed.")

if __name__ == "__main__":
    main()
