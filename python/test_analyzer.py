#!/usr/bin/env python3
"""
Test script for the enhanced email HTML analyzer
"""

import sys
import os
from email_html_analyzer import EmailHTMLAnalyzer

def test_email_analysis():
    """Test the email analyzer with sample files"""
    analyzer = EmailHTMLAnalyzer()
    
    # Test files
    test_files = [
        '../test_phishing_email.eml',
        '../test_safe_email.eml'
    ]
    
    for file_path in test_files:
        if not os.path.exists(file_path):
            print(f"⚠️  File not found: {file_path}")
            continue
            
        print(f"\n{'='*80}")
        print(f"TESTING: {os.path.basename(file_path)}")
        print(f"{'='*80}")
        
        # Analyze the email
        results = analyzer.analyze_email_file(file_path)
        
        if not results['success']:
            print(f"❌ Analysis failed: {results['error']}")
            continue
        
        # Generate and display report
        report = analyzer.format_analysis_report(results)
        print(report)
        
        # Summary
        print(f"\n{'='*40}")
        print("SUMMARY:")
        print(f"Status: {results['overall_status']}")
        print(f"Threat Score: {results['threat_score']}/100")
        print(f"HTML Segments: {len(results['html_segments'])}")
        print(f"Total Threats: {len(results['threats_found'])}")
        print(f"{'='*40}")

if __name__ == "__main__":
    test_email_analysis()