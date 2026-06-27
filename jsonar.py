#!/usr/bin/env python3
"""
WSS JSON Analyzer - Extract and format information from JSON files
by nu11secur1ty
"""

import json
import requests
import sys
import os
from datetime import datetime

# Terminal colors (optional)
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def create_report_filename():
    """Create unique filename for the report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"wss_report_{timestamp}.txt"

def save_report(filename, content):
    """Save content to file"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"\n✅ {Colors.GREEN}Report saved to: {Colors.BOLD}{filename}{Colors.END}")

def format_plugins_list(data):
    """Format plugins list in table format"""
    output = []
    output.append("\n" + "="*60)
    output.append("📦 INSTALLED PLUGINS")
    output.append("="*60)
    
    plugins = {}
    for key, value in data.items():
        # If value is a list, take the first element as plugin name
        if isinstance(value, list) and value:
            plugin_name = value[0]
            if plugin_name not in plugins:
                plugins[plugin_name] = []
            plugins[plugin_name].append(key)
    
    # Sort by plugin name
    for plugin_name, tables in sorted(plugins.items()):
        output.append(f"\n📌 {Colors.BOLD}{plugin_name}{Colors.END}")
        output.append(f"   Tables ({len(tables)}):")
        for table in sorted(tables):
            output.append(f"   └── {table}")
    
    return "\n".join(output)

def format_detailed_list(data):
    """Format detailed list of all elements"""
    output = []
    output.append("\n" + "="*60)
    output.append("📋 DETAILED LIST OF ALL ELEMENTS")
    output.append("="*60)
    
    for key, value in sorted(data.items()):
        output.append(f"\n📦 {Colors.BLUE}{key}{Colors.END}")
        if isinstance(value, list):
            for item in value:
                output.append(f"   └── {item}")
        else:
            output.append(f"   └── {value}")
    
    return "\n".join(output)

def format_plugins_by_category(data):
    """Group plugins by category"""
    output = []
    output.append("\n" + "="*60)
    output.append("📊 PLUGINS BY CATEGORY")
    output.append("="*60)
    
    categories = {
        "🔒 Security": ["botbanish", "firewall", "security"],
        "📋 Forms": ["formglut", "simple-form", "wordform", "eforms"],
        "🛒 E-Commerce": ["woocommerce", "wpboutik", "coupomated", "advanced-emailing"],
        "📊 Analytics": ["analytics", "insights", "bubo"],
        "💾 Backup": ["backup", "green-backup"],
        "👥 CRM/Clients": ["crm", "ni-crm", "lead"],
        "📚 LMS/Learning": ["solidie", "lesson", "knowledgebase"],
        "👔 HR/Recruitment": ["prosolution", "recruitment"],
        "🔧 Tools": ["toolkit", "editor", "manager"],
        "📱 Integrations": ["bankid", "coinscribble", "connect"],
    }
    
    categorized = {}
    categorized["Others"] = []
    
    for plugin_name in set([v[0] if isinstance(v, list) and v else v for v in data.values()]):
        if not isinstance(plugin_name, str):
            continue
        found = False
        for category, keywords in categories.items():
            if any(keyword in plugin_name.lower() for keyword in keywords):
                if category not in categorized:
                    categorized[category] = []
                categorized[category].append(plugin_name)
                found = True
                break
        if not found:
            categorized["Others"].append(plugin_name)
    
    for category, plugins in sorted(categorized.items()):
        if plugins:
            output.append(f"\n{category} ({len(plugins)}):")
            for plugin in sorted(plugins):
                output.append(f"   ├── {plugin}")
    
    return "\n".join(output)

def main():
    print(f"\n{Colors.BOLD}🔍 WSS JSON Analyzer{Colors.END}")
    print("="*60)
    print("Enter JSON file URL (or press Enter to use default):")
    print("Default: https://so-cyber.com/wp-content/uploads/wpo/wpo-plugins-tables-list.json\n")
    
    url = input("URL: ").strip()
    if not url:
        url = "https://so-cyber.com/wp-content/uploads/wpo/wpo-plugins-tables-list.json"
        print(f"ℹ️  Using: {url}")
    
    print("\n⏳ Fetching data...")
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Create report content
            report_content = []
            report_content.append("="*80)
            report_content.append(f"📄 WSS SCANNER - REPORT FROM {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
            report_content.append(f"🔗 Source: {url}")
            report_content.append("="*80)
            
            # Add different sections
            report_content.append(format_plugins_list(data))
            report_content.append(format_plugins_by_category(data))
            report_content.append(format_detailed_list(data))
            
            # Statistics
            total_plugins = len(set([v[0] if isinstance(v, list) and v else v for v in data.values() if v]))
            total_tables = len(data)
            report_content.append("\n" + "="*60)
            report_content.append("📊 STATISTICS")
            report_content.append("="*60)
            report_content.append(f"├── Total tables: {total_tables}")
            report_content.append(f"└── Unique plugins: {total_plugins}")
            
            # Save to file
            report_content_str = "\n".join(report_content)
            
            # Display in terminal
            print(report_content_str)
            
            # Save to file
            filename = create_report_filename()
            save_report(filename, report_content_str)
            
            # Display file content
            print(f"\n📄 Report content ({filename}):")
            print("-"*60)
            with open(filename, 'r', encoding='utf-8') as f:
                print(f.read())
            
        else:
            error_msg = f"❌ Error: HTTP {response.status_code} - {response.reason}"
            print(error_msg)
            
            # Save error to file
            filename = create_report_filename()
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"ERROR FETCHING DATA\n")
                f.write(f"URL: {url}\n")
                f.write(f"Status: {response.status_code}\n")
                f.write(f"Reason: {response.reason}\n")
            print(f"⚠️  Error saved to: {filename}")
            
    except requests.exceptions.Timeout:
        print("❌ Error: Request timeout. The site is not responding.")
    except requests.exceptions.ConnectionError:
        print("❌ Error: No connection to the server.")
    except json.JSONDecodeError:
        print("❌ Error: The received data is not valid JSON.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(0)
