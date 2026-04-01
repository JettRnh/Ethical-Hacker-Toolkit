#!/usr/bin/env python3
"""
Report generator module for Ethical Hacker Toolkit
Author: Jet
GitHub: https://github.com/JettRnh
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from config.settings import REPORT_DIR

class Reporter:
    """Generate reports in multiple formats"""
    
    def __init__(self, tool_name, output_format='txt'):
        self.tool_name = tool_name
        self.output_format = output_format
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.data = {
            "tool": tool_name,
            "timestamp": datetime.now().isoformat(),
            "results": []
        }
    
    def add_result(self, result):
        """Add a result to the report"""
        self.data["results"].append(result)
    
    def add_results(self, results):
        """Add multiple results to the report"""
        self.data["results"].extend(results)
    
    def clear(self):
        """Clear all results"""
        self.data["results"] = []
    
    def to_dict(self):
        """Convert report to dictionary"""
        return self.data
    
    def to_json(self):
        """Convert report to JSON string"""
        return json.dumps(self.data, indent=2, default=str)
    
    def to_text(self):
        """Convert report to text format"""
        lines = []
        lines.append("=" * 60)
        lines.append(f"ETHICAL HACKER TOOLKIT - {self.tool_name.upper()} REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {self.data['timestamp']}")
        lines.append("=" * 60)
        lines.append("")
        
        for i, result in enumerate(self.data['results'], 1):
            lines.append(f"[{i}] {result}")
            lines.append("-" * 40)
        
        lines.append("")
        lines.append(f"Total Results: {len(self.data['results'])}")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def to_html(self):
        """Convert report to HTML format"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>EHT Report - {self.tool_name}</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            margin: 40px;
        }}
        h1 {{
            color: #00ff00;
            border-bottom: 2px solid #00ff00;
            padding-bottom: 10px;
        }}
        .header {{
            background: #1a1a1a;
            padding: 15px;
            border-left: 4px solid #00ff00;
            margin-bottom: 20px;
        }}
        .result {{
            background: #111;
            padding: 10px;
            margin: 10px 0;
            border-left: 3px solid #00ff00;
            font-family: monospace;
        }}
        .footer {{
            margin-top: 30px;
            padding: 10px;
            background: #1a1a1a;
            text-align: center;
            font-size: 12px;
        }}
        .count {{
            color: #ffff00;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <h1>🔍 EHT - {self.tool_name.upper()} Report</h1>
    <div class="header">
        <strong>Timestamp:</strong> {self.data['timestamp']}<br>
        <strong>Total Results:</strong> <span class="count">{len(self.data['results'])}</span>
    </div>
"""
        
        for result in self.data['results']:
            html += f'    <div class="result">▶ {result}</div>\n'
        
        html += f"""
    <div class="footer">
        Ethical Hacker Toolkit | Author: Jet | GitHub: https://github.com/JettRnh
    </div>
</body>
</html>"""
        return html
    
    def save_txt(self):
        """Save as text file"""
        filename = f"{self.tool_name}_{self.timestamp}.txt"
        filepath = REPORT_DIR / filename
        
        with open(filepath, 'w') as f:
            f.write(self.to_text())
        
        return filepath
    
    def save_json(self):
        """Save as JSON file"""
        filename = f"{self.tool_name}_{self.timestamp}.json"
        filepath = REPORT_DIR / filename
        
        with open(filepath, 'w') as f:
            f.write(self.to_json())
        
        return filepath
    
    def save_html(self):
        """Save as HTML file"""
        filename = f"{self.tool_name}_{self.timestamp}.html"
        filepath = REPORT_DIR / filename
        
        with open(filepath, 'w') as f:
            f.write(self.to_html())
        
        return filepath
    
    def save(self, format=None):
        """Save report in specified format"""
        fmt = format or self.output_format
        
        if fmt == 'txt':
            return self.save_txt()
        elif fmt == 'json':
            return self.save_json()
        elif fmt == 'html':
            return self.save_html()
        else:
            raise ValueError(f"Unknown format: {fmt}")
    
    def print_report(self):
        """Print report to console"""
        print(self.to_text())
