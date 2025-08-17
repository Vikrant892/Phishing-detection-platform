#!/usr/bin/env python3
"""
Command-line tool for processing and displaying database statistics
"""

import sys
import os
from datetime import datetime
from database_schema import db_manager
from email_html_analyzer import EmailHTMLAnalyzer

def print_separator(title="", length=80):
    """Print a separator line with optional title"""
    if title:
        title_formatted = f" {title} "
        padding = (length - len(title_formatted)) // 2
        print("=" * padding + title_formatted + "=" * (length - padding - len(title_formatted)))
    else:
        print("=" * length)

def display_threat_statistics():
    """Display threat occurrence statistics"""
    print_separator("THREAT OCCURRENCE STATISTICS")
    
    try:
        threat_stats = db_manager.get_threat_statistics()
        
        if not threat_stats:
            print("No threat statistics available in database.")
            return
        
        print(f"{'Category':<25} {'Pattern':<40} {'Count':<8} {'Last Detected'}")
        print("-" * 80)
        
        for stat in threat_stats:
            category = stat['threat_category'].replace('_', ' ').title()
            pattern = stat['threat_pattern'][:38] + "..." if len(stat['threat_pattern']) > 38 else stat['threat_pattern']
            count = stat['occurrence_count']
            last_detected = stat['last_detected'].strftime('%Y-%m-%d %H:%M') if stat['last_detected'] else 'Unknown'
            
            print(f"{category:<25} {pattern:<40} {count:<8} {last_detected}")
        
        print(f"\nTotal unique threat patterns: {len(threat_stats)}")
        print(f"Total threat occurrences: {sum(stat['occurrence_count'] for stat in threat_stats)}")
        
    except Exception as e:
        print(f"Error retrieving threat statistics: {e}")

def display_failure_statistics():
    """Display analysis failure statistics"""
    print_separator("ANALYSIS FAILURE STATISTICS")
    
    try:
        failure_stats = db_manager.get_failure_statistics()
        
        if not failure_stats:
            print("No failure statistics available in database.")
            return
        
        print(f"{'Failure Type':<30} {'Count':<8} {'Last Occurrence'}")
        print("-" * 55)
        
        for stat in failure_stats:
            failure_type = stat['failure_type'].replace('_', ' ').title()
            count = stat['occurrence_count']
            last_occurrence = stat['last_occurrence'].strftime('%Y-%m-%d %H:%M') if stat['last_occurrence'] else 'Unknown'
            
            print(f"{failure_type:<30} {count:<8} {last_occurrence}")
        
        print(f"\nTotal failure types: {len(failure_stats)}")
        print(f"Total failures: {sum(stat['occurrence_count'] for stat in failure_stats)}")
        
    except Exception as e:
        print(f"Error retrieving failure statistics: {e}")

def display_dashboard_statistics():
    """Display comprehensive dashboard statistics"""
    print_separator("DASHBOARD STATISTICS")
    
    try:
        stats = db_manager.get_dashboard_stats()
        
        print(f"Total Analyses: {stats['total_analyses']}")
        print(f"Average Threat Score: {stats['avg_threat_score']}")
        print(f"High-Risk Quarantined: {stats['quarantined_count']}")
        print()
        
        print("Risk Distribution:")
        for risk_level, count in stats['risk_distribution'].items():
            percentage = (count / stats['total_analyses'] * 100) if stats['total_analyses'] > 0 else 0
            print(f"  {risk_level}: {count} ({percentage:.1f}%)")
        
        print("\nRecent Analyses:")
        if stats['recent_analyses']:
            for analysis in stats['recent_analyses'][:5]:
                date_str = analysis['created_at'].strftime('%Y-%m-%d %H:%M') if hasattr(analysis['created_at'], 'strftime') else str(analysis['created_at'])
                print(f"  {date_str} - {analysis['email_subject']} (Score: {analysis['threat_score']}, Level: {analysis['threat_level']})")
        else:
            print("  No recent analyses available")
        
    except Exception as e:
        print(f"Error retrieving dashboard statistics: {e}")

def test_enhanced_analyzer():
    """Test the enhanced analyzer with sample files"""
    print_separator("ENHANCED ANALYZER TEST")
    
    analyzer = EmailHTMLAnalyzer()
    
    test_files = [
        '../test_phishing_email.eml',
        '../test_safe_email.eml',
        '../test_enhanced_phishing_email.eml'
    ]
    
    for file_path in test_files:
        if not os.path.exists(file_path):
            print(f"⚠️  File not found: {file_path}")
            continue
        
        print(f"\nTesting: {os.path.basename(file_path)}")
        print("-" * 40)
        
        try:
            results = analyzer.analyze_email_file(file_path)
            
            if results['success']:
                print(f"Status: {results['overall_status']}")
                print(f"Threat Score: {results['threat_score']}/100")
                print(f"HTML Segments: {len(results['html_segments'])}")
                print(f"Total Threats: {len(results['threats_found'])}")
                
                # Show header analysis
                if 'headers' in results:
                    suspicious_headers = [h for h, data in results['headers'].items() if data.get('is_suspicious')]
                    if suspicious_headers:
                        print(f"Suspicious Headers: {len(suspicious_headers)}")
                        for header in suspicious_headers[:3]:  # Show first 3
                            threats = results['headers'][header].get('threat_patterns', [])
                            if threats:
                                print(f"  {header}: {threats[0]}")
                
                # Save to database
                try:
                    analysis_id = f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    db_data = {
                        'analysis_id': analysis_id,
                        'filename': os.path.basename(file_path),
                        'subject': results['email_info']['subject'],
                        'sender': results['email_info']['sender'],
                        'recipient': results['email_info']['recipient'],
                        'email_date': results['email_info']['date'],
                        'threat_score': results['threat_score'],
                        'threat_level': 'HIGH' if results['threat_score'] >= 70 else 
                                       'MEDIUM' if results['threat_score'] >= 40 else 'LOW',
                        'overall_status': results['overall_status'],
                        'analysis_type': 'enhanced_html_test',
                        'total_segments': len(results['html_segments']),
                        'total_threats': len(results['threats_found']),
                        'headers': results.get('headers', {}),
                        'html_segments': results['html_segments']
                    }
                    
                    db_manager.save_email_analysis(db_data)
                    print(f"✅ Saved to database with ID: {analysis_id}")
                    
                except Exception as db_e:
                    print(f"⚠️  Database save failed: {db_e}")
                
            else:
                print(f"❌ Analysis failed: {results['error']}")
                
        except Exception as e:
            print(f"❌ Test failed: {e}")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python database_stats_tool.py <command>")
        print("\nCommands:")
        print("  threats    - Display threat occurrence statistics")
        print("  failures   - Display analysis failure statistics")
        print("  dashboard  - Display dashboard statistics")
        print("  test       - Test enhanced analyzer and save to database")
        print("  all        - Display all statistics")
        return
    
    command = sys.argv[1].lower()
    
    try:
        if command == "threats":
            display_threat_statistics()
        elif command == "failures":
            display_failure_statistics()
        elif command == "dashboard":
            display_dashboard_statistics()
        elif command == "test":
            test_enhanced_analyzer()
        elif command == "all":
            display_dashboard_statistics()
            print()
            display_threat_statistics()
            print()
            display_failure_statistics()
        else:
            print(f"Unknown command: {command}")
            print("Use 'python database_stats_tool.py' for usage information.")
    
    except Exception as e:
        print(f"Error executing command '{command}': {e}")

if __name__ == "__main__":
    main()