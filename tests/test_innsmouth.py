#!/usr/bin/env python3
"""
Innsmouth NIDS - Tests
Validates detection rules and analysis scripts.
"""

import unittest
import os
import sys
import tempfile
import json
from pathlib import Path


class TestInnsmouthRules(unittest.TestCase):
    """Test validation for Suricata rules."""
    
    def setUp(self):
        """Setup test environment."""
        self.rules_dir = Path(__file__).parent.parent / "rules"
    
    def test_rules_files_exist(self):
        """Test that all rule files exist."""
        expected_rules = [
            "port_scan.rules",
            "plaintext_creds.rules", 
            "anomaly_detection.rules"
        ]
        
        for rule_file in expected_rules:
            rule_path = self.rules_dir / rule_file
            self.assertTrue(rule_path.exists(), f"Rule file missing: {rule_file}")
    
    def test_suricata_syntax(self):
        """Test basic Suricata rule syntax."""
        # Basic syntax validation
        rule_files = list(self.rules_dir.glob("*.rules"))
        
        for rule_file in rule_files:
            with open(rule_file, 'r') as f:
                content = f.read()
                
                # Check for alert keyword
                self.assertIn("alert", content, f"No alerts in {rule_file}")
                
                # Check for msg keyword
                self.assertIn("msg:", content, f"No messages in {rule_file}")
                
                # Check for sid
                self.assertIn("sid:", content, f"No SID in {rule_file}")
    
    def test_sid_uniqueness(self):
        """Test that SIDs are unique across rules."""
        sids = []
        
        for rule_file in self.rules_dir.glob("*.rules"):
            with open(rule_file, 'r') as f:
                for line in f:
                    if "sid:" in line:
                        # Extract SID number
                        import re
                        match = re.search(r'sid:(\d+)', line)
                        if match:
                            sids.append((rule_file.name, match.group(1)))
        
        # Check for duplicates
        sid_dict = {}
        for filename, sid in sids:
            if sid in sid_dict:
                self.fail(f"Duplicate SID {sid} in {filename} and {sid_dict[sid]}")
            sid_dict[sid] = filename


class TestInnsmouthScripts(unittest.TestCase):
    """Test analysis scripts."""
    
    def setUp(self):
        """Setup test environment."""
        self.scripts_dir = Path(__file__).parent.parent / "scripts"
    
    def test_scripts_exist(self):
        """Test that all scripts exist."""
        expected_scripts = [
            "analyze_pcap.py",
            "detect_scans.py"
        ]
        
        for script in expected_scripts:
            script_path = self.scripts_dir / script
            self.assertTrue(script_path.exists(), f"Script missing: {script}")
    
    def test_scripts_executable(self):
        """Test that scripts have execute permission or are valid Python."""
        for script in self.scripts_dir.glob("*.py"):
            # Check it's valid Python syntax
            with open(script, 'r') as f:
                code = f.read()
                try:
                    compile(code, script.name, 'exec')
                except SyntaxError as e:
                    self.fail(f"Syntax error in {script}: {e}")
    
    def test_analyze_pcap_imports(self):
        """Test that analyze_pcap.py has required imports."""
        script_path = self.scripts_dir / "analyze_pcap.py"
        
        with open(script_path, 'r') as f:
            content = f.read()
        
        # Check for required imports
        self.assertIn("import", content)
        self.assertIn("argparse", content)
        self.assertIn("json", content)


class TestDocumentation(unittest.TestCase):
    """Test documentation files."""
    
    def test_readme_exists(self):
        """Test that README.md exists."""
        readme_path = Path(__file__).parent.parent / "README.md"
        self.assertTrue(readme_path.exists())
    
    def test_setup_docs_exist(self):
        """Test that setup documentation exists."""
        docs_path = Path(__file__).parent.parent / "docs" / "SETUP.md"
        self.assertTrue(docs_path.exists())


class TestInnsmouthConfig(unittest.TestCase):
    """Test configuration files."""
    
    def test_config_structure(self):
        """Test project structure."""
        project_root = Path(__file__).parent.parent
        
        required_dirs = [
            "rules",
            "scripts", 
            "docs",
            "tests",
            "configs"
        ]
        
        for dir_name in required_dirs:
            dir_path = project_root / dir_name
            self.assertTrue(dir_path.exists(), f"Missing directory: {dir_name}")
    
    def test_readme_has_sections(self):
        """Test that README has required sections."""
        readme_path = Path(__file__).parent.parent / "README.md"
        
        with open(readme_path, 'r') as f:
            content = f.read()
        
        required_sections = [
            "Instalación",
            "Reglas",
            "Análisis"
        ]
        
        # Check English fallbacks too
        optional_sections = [
            "Installation",
            "Rules",
            "Analysis",
            "Setup"
        ]
        
        found = False
        for section in required_sections + optional_sections:
            if section in content:
                found = True
                break
        
        self.assertTrue(found, "README missing required sections")


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
