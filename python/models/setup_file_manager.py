"""
Setup File Manager - Handle various setup file formats for threat detection rules
"""

import os
import pandas as pd
import json
import csv
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

class SetupFileManager:
    """Manager for setup files containing threat detection rules"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.supported_formats = ['.csv', '.xlsx', '.xls', '.json', '.txt']
        self.required_columns = ['start_segment', 'end_segment', 'phrase']
        
    def load_setup_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Load setup file and return standardized rule format"""
        try:
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Setup file not found: {filepath}")
            
            file_extension = Path(filepath).suffix.lower()
            
            if file_extension not in self.supported_formats:
                raise ValueError(f"Unsupported file format: {file_extension}")
            
            if file_extension == '.csv':
                return self._load_csv_file(filepath)
            elif file_extension in ['.xlsx', '.xls']:
                return self._load_excel_file(filepath)
            elif file_extension == '.json':
                return self._load_json_file(filepath)
            elif file_extension == '.txt':
                return self._load_text_file(filepath)
            else:
                raise ValueError(f"Unsupported format: {file_extension}")
                
        except Exception as e:
            self.logger.error(f"Setup file loading error: {str(e)}")
            raise
    
    def _load_csv_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Load CSV setup file"""
        try:
            rules = []
            
            with open(filepath, 'r', encoding='utf-8', newline='') as csvfile:
                # Try to detect delimiter
                sample = csvfile.read(1024)
                csvfile.seek(0)
                
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample).delimiter
                
                reader = csv.DictReader(csvfile, delimiter=delimiter)
                
                # Normalize column names
                fieldnames = [col.lower().strip().replace(' ', '_') for col in reader.fieldnames]
                reader.fieldnames = fieldnames
                
                for row_num, row in enumerate(reader, start=2):
                    try:
                        rule = self._parse_rule_row(row, row_num)
                        if rule:
                            rules.append(rule)
                    except Exception as e:
                        self.logger.warning(f"Skipping row {row_num}: {str(e)}")
            
            self.logger.info(f"Loaded {len(rules)} rules from CSV file")
            return rules
            
        except Exception as e:
            self.logger.error(f"CSV loading error: {str(e)}")
            raise
    
    def _load_excel_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Load Excel setup file"""
        try:
            rules = []
            
            # Read Excel file
            df = pd.read_excel(filepath)
            
            # Normalize column names
            df.columns = [col.lower().strip().replace(' ', '_') for col in df.columns]
            
            for index, row in df.iterrows():
                try:
                    rule_dict = row.to_dict()
                    rule = self._parse_rule_row(rule_dict, index + 2)
                    if rule:
                        rules.append(rule)
                except Exception as e:
                    self.logger.warning(f"Skipping row {index + 2}: {str(e)}")
            
            self.logger.info(f"Loaded {len(rules)} rules from Excel file")
            return rules
            
        except Exception as e:
            self.logger.error(f"Excel loading error: {str(e)}")
            raise
    
    def _load_json_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Load JSON setup file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as jsonfile:
                data = json.load(jsonfile)
            
            rules = []
            
            if isinstance(data, list):
                for i, item in enumerate(data):
                    try:
                        rule = self._parse_rule_row(item, i + 1)
                        if rule:
                            rules.append(rule)
                    except Exception as e:
                        self.logger.warning(f"Skipping item {i + 1}: {str(e)}")
            
            elif isinstance(data, dict):
                if 'rules' in data:
                    for i, item in enumerate(data['rules']):
                        try:
                            rule = self._parse_rule_row(item, i + 1)
                            if rule:
                                rules.append(rule)
                        except Exception as e:
                            self.logger.warning(f"Skipping rule {i + 1}: {str(e)}")
                else:
                    # Treat the entire dict as a single rule
                    rule = self._parse_rule_row(data, 1)
                    if rule:
                        rules.append(rule)
            
            self.logger.info(f"Loaded {len(rules)} rules from JSON file")
            return rules
            
        except Exception as e:
            self.logger.error(f"JSON loading error: {str(e)}")
            raise
    
    def _load_text_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Load text setup file with simple format"""
        try:
            rules = []
            
            with open(filepath, 'r', encoding='utf-8') as txtfile:
                lines = txtfile.readlines()
            
            current_rule = {}
            line_num = 0
            
            for line in lines:
                line_num += 1
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.lower().strip()
                    value = value.strip()
                    
                    if key in ['start', 'start_segment']:
                        current_rule['start_segment'] = value
                    elif key in ['end', 'end_segment']:
                        current_rule['end_segment'] = value
                    elif key in ['phrase', 'pattern', 'search']:
                        current_rule['phrase'] = value
                    elif key in ['type', 'rule_type']:
                        current_rule['type'] = value
                    elif key in ['severity', 'level']:
                        current_rule['severity'] = value
                    elif key in ['name', 'rule_name']:
                        current_rule['name'] = value
                
                elif line == '---' or line == '***':
                    # Rule separator
                    if current_rule and 'phrase' in current_rule:
                        rule = self._parse_rule_row(current_rule, line_num)
                        if rule:
                            rules.append(rule)
                    current_rule = {}
            
            # Add last rule if exists
            if current_rule and 'phrase' in current_rule:
                rule = self._parse_rule_row(current_rule, line_num)
                if rule:
                    rules.append(rule)
            
            self.logger.info(f"Loaded {len(rules)} rules from text file")
            return rules
            
        except Exception as e:
            self.logger.error(f"Text loading error: {str(e)}")
            raise
    
    def _parse_rule_row(self, row_data: Dict[str, Any], row_num: int) -> Optional[Dict[str, Any]]:
        """Parse individual rule row and validate"""
        try:
            rule = {
                'name': '',
                'start_segment': '<body',
                'end_segment': '</body>',
                'phrase': '',
                'type': 'single_line',
                'severity': 'medium',
                'is_active': True,
                'source_row': row_num
            }
            
            # Map common column variations
            column_mapping = {
                'start': 'start_segment',
                'start_tag': 'start_segment',
                'begin': 'start_segment',
                'end': 'end_segment',
                'end_tag': 'end_segment',
                'finish': 'end_segment',
                'search': 'phrase',
                'pattern': 'phrase',
                'keyword': 'phrase',
                'text': 'phrase',
                'rule_type': 'type',
                'segment_type': 'type',
                'priority': 'severity',
                'level': 'severity',
                'risk': 'severity',
                'rule_name': 'name',
                'description': 'name'
            }
            
            # Process row data
            for key, value in row_data.items():
                if pd.isna(value) or value == '':
                    continue
                
                key = str(key).lower().strip()
                value = str(value).strip()
                
                # Direct mapping
                if key in rule:
                    rule[key] = value
                # Indirect mapping
                elif key in column_mapping:
                    rule[column_mapping[key]] = value
            
            # Validate required fields
            if not rule['phrase']:
                self.logger.warning(f"Row {row_num}: Missing phrase/pattern")
                return None
            
            # Validate and normalize values
            rule = self._validate_and_normalize_rule(rule)
            
            return rule
            
        except Exception as e:
            self.logger.error(f"Rule parsing error at row {row_num}: {str(e)}")
            return None
    
    def _validate_and_normalize_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize rule values"""
        
        # Normalize rule type
        valid_types = ['single_line', 'multi_line', 'regex', 'html_segment']
        if rule['type'] not in valid_types:
            type_mapping = {
                'single': 'single_line',
                'multiline': 'multi_line',
                'multiple': 'multi_line',
                'regexp': 'regex',
                'regular': 'regex',
                'html': 'html_segment',
                'segment': 'html_segment'
            }
            rule['type'] = type_mapping.get(rule['type'].lower(), 'single_line')
        
        # Normalize severity
        valid_severities = ['low', 'medium', 'high', 'critical']
        if rule['severity'] not in valid_severities:
            severity_mapping = {
                '1': 'low',
                '2': 'medium',
                '3': 'high',
                '4': 'critical',
                'info': 'low',
                'warning': 'medium',
                'error': 'high',
                'fatal': 'critical',
                'minor': 'low',
                'major': 'high',
                'severe': 'critical'
            }
            rule['severity'] = severity_mapping.get(rule['severity'].lower(), 'medium')
        
        # Set default start/end segments based on type
        if not rule['start_segment']:
            if rule['type'] == 'html_segment':
                rule['start_segment'] = '<body'
            else:
                rule['start_segment'] = '<body'
        
        if not rule['end_segment']:
            if rule['type'] == 'html_segment':
                rule['end_segment'] = '</body>'
            else:
                rule['end_segment'] = '</body>'
        
        # Generate name if not provided
        if not rule['name']:
            phrase_preview = rule['phrase'][:30] + '...' if len(rule['phrase']) > 30 else rule['phrase']
            rule['name'] = f"{rule['type']}_{rule['severity']}_{phrase_preview}"
        
        return rule
    
    def save_rules_to_file(self, rules: List[Dict[str, Any]], filepath: str, 
                          format_type: str = None) -> bool:
        """Save rules to file in specified format"""
        try:
            if format_type is None:
                format_type = Path(filepath).suffix.lower()
            
            if format_type == '.csv':
                return self._save_csv_file(rules, filepath)
            elif format_type in ['.xlsx', '.xls']:
                return self._save_excel_file(rules, filepath)
            elif format_type == '.json':
                return self._save_json_file(rules, filepath)
            elif format_type == '.txt':
                return self._save_text_file(rules, filepath)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
                
        except Exception as e:
            self.logger.error(f"Rule saving error: {str(e)}")
            return False
    
    def _save_csv_file(self, rules: List[Dict[str, Any]], filepath: str) -> bool:
        """Save rules to CSV file"""
        try:
            fieldnames = ['name', 'start_segment', 'end_segment', 'phrase', 'type', 'severity', 'is_active']
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for rule in rules:
                    row = {field: rule.get(field, '') for field in fieldnames}
                    writer.writerow(row)
            
            self.logger.info(f"Saved {len(rules)} rules to CSV file: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"CSV saving error: {str(e)}")
            return False
    
    def _save_excel_file(self, rules: List[Dict[str, Any]], filepath: str) -> bool:
        """Save rules to Excel file"""
        try:
            df = pd.DataFrame(rules)
            
            # Reorder columns
            column_order = ['name', 'start_segment', 'end_segment', 'phrase', 'type', 'severity', 'is_active']
            existing_columns = [col for col in column_order if col in df.columns]
            other_columns = [col for col in df.columns if col not in column_order]
            
            df = df[existing_columns + other_columns]
            
            with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='ThreatRules', index=False)
            
            self.logger.info(f"Saved {len(rules)} rules to Excel file: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Excel saving error: {str(e)}")
            return False
    
    def _save_json_file(self, rules: List[Dict[str, Any]], filepath: str) -> bool:
        """Save rules to JSON file"""
        try:
            data = {
                'metadata': {
                    'version': '1.0',
                    'created_at': pd.Timestamp.now().isoformat(),
                    'rule_count': len(rules)
                },
                'rules': rules
            }
            
            with open(filepath, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Saved {len(rules)} rules to JSON file: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"JSON saving error: {str(e)}")
            return False
    
    def _save_text_file(self, rules: List[Dict[str, Any]], filepath: str) -> bool:
        """Save rules to text file"""
        try:
            with open(filepath, 'w', encoding='utf-8') as txtfile:
                txtfile.write("# Phishing Detection Rules\n")
                txtfile.write(f"# Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                txtfile.write(f"# Rules: {len(rules)}\n\n")
                
                for i, rule in enumerate(rules, 1):
                    txtfile.write(f"# Rule {i}\n")
                    txtfile.write(f"name: {rule.get('name', '')}\n")
                    txtfile.write(f"start_segment: {rule.get('start_segment', '')}\n")
                    txtfile.write(f"end_segment: {rule.get('end_segment', '')}\n")
                    txtfile.write(f"phrase: {rule.get('phrase', '')}\n")
                    txtfile.write(f"type: {rule.get('type', '')}\n")
                    txtfile.write(f"severity: {rule.get('severity', '')}\n")
                    txtfile.write(f"is_active: {rule.get('is_active', True)}\n")
                    txtfile.write("---\n\n")
            
            self.logger.info(f"Saved {len(rules)} rules to text file: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Text saving error: {str(e)}")
            return False
    
    def validate_setup_file(self, filepath: str) -> Dict[str, Any]:
        """Validate setup file and return validation results"""
        try:
            validation_result = {
                'is_valid': False,
                'errors': [],
                'warnings': [],
                'rule_count': 0,
                'file_format': Path(filepath).suffix.lower(),
                'file_size': os.path.getsize(filepath)
            }
            
            # Check file existence
            if not os.path.exists(filepath):
                validation_result['errors'].append(f"File not found: {filepath}")
                return validation_result
            
            # Check file format
            if validation_result['file_format'] not in self.supported_formats:
                validation_result['errors'].append(f"Unsupported format: {validation_result['file_format']}")
                return validation_result
            
            # Try to load rules
            try:
                rules = self.load_setup_file(filepath)
                validation_result['rule_count'] = len(rules)
                
                if len(rules) == 0:
                    validation_result['warnings'].append("No valid rules found in file")
                
                # Validate individual rules
                valid_rules = 0
                for i, rule in enumerate(rules, 1):
                    if not rule.get('phrase'):
                        validation_result['errors'].append(f"Rule {i}: Missing phrase/pattern")
                    else:
                        valid_rules += 1
                
                validation_result['valid_rules'] = valid_rules
                
                if len(validation_result['errors']) == 0:
                    validation_result['is_valid'] = True
                
            except Exception as e:
                validation_result['errors'].append(f"Failed to parse file: {str(e)}")
            
            return validation_result
            
        except Exception as e:
            self.logger.error(f"Validation error: {str(e)}")
            return {
                'is_valid': False,
                'errors': [f"Validation failed: {str(e)}"],
                'warnings': [],
                'rule_count': 0
            }
    
    def convert_file_format(self, input_filepath: str, output_filepath: str) -> bool:
        """Convert setup file from one format to another"""
        try:
            # Load rules from input file
            rules = self.load_setup_file(input_filepath)
            
            # Save rules to output file
            success = self.save_rules_to_file(rules, output_filepath)
            
            if success:
                self.logger.info(f"Converted {input_filepath} to {output_filepath}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Format conversion error: {str(e)}")
            return False
    
    def get_sample_rules(self) -> List[Dict[str, Any]]:
        """Get sample rules for testing and demonstration"""
        return [
            {
                'name': 'Urgent Action Required',
                'start_segment': '<body',
                'end_segment': '</body>',
                'phrase': 'urgent[ly]?\\s*(?:action|response|attention)',
                'type': 'regex',
                'severity': 'medium',
                'is_active': True
            },
            {
                'name': 'Account Suspension Warning',
                'start_segment': '<body',
                'end_segment': '</body>',
                'phrase': 'suspended.*account',
                'type': 'regex',
                'severity': 'high',
                'is_active': True
            },
            {
                'name': 'Click Here to Verify',
                'start_segment': '<body',
                'end_segment': '</body>',
                'phrase': 'click here to verify',
                'type': 'single_line',
                'severity': 'high',
                'is_active': True
            },
            {
                'name': 'Cross-tenant ID Check',
                'start_segment': 'x-ms-exchange-crosstenant-id',
                'end_segment': '\n',
                'phrase': 'XFCjGeORft8x7Ol',
                'type': 'single_line',
                'severity': 'critical',
                'is_active': True
            }
        ]
