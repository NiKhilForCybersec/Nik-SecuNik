
#!/usr/bin/env python3
"""
Download and update detection rules from various sources
"""

import os
import json
import requests
import zipfile
import tarfile
import shutil
from pathlib import Path
from typing import Dict, List
import yaml
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rule sources
RULE_SOURCES = {
    "yara": {
        "repositories": [
            {
                "name": "Yara-Rules/rules",
                "url": "https://github.com/Yara-Rules/rules/archive/master.zip",
                "type": "zip",
                "path_in_archive": "rules-master"
            },
            {
                "name": "InQuest/awesome-yara",
                "url": "https://github.com/InQuest/awesome-yara/archive/main.zip",
                "type": "zip",
                "path_in_archive": "awesome-yara-main"
            }
        ]
    },
    "sigma": {
        "repositories": [
            {
                "name": "SigmaHQ/sigma",
                "url": "https://github.com/SigmaHQ/sigma/archive/master.zip",
                "type": "zip",
                "path_in_archive": "sigma-master/rules"
            }
        ]
    }
}

class RuleDownloader:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(exist_ok=True)
        self.temp_dir = Path("temp_rules")
        self.temp_dir.mkdir(exist_ok=True)
        
    def download_file(self, url: str, filename: str) -> Path:
        """Download a file from URL"""
        filepath = self.temp_dir / filename
        logger.info(f"Downloading {url}...")
        
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                
        logger.info(f"Downloaded to {filepath}")
        return filepath
        
    def extract_archive(self, filepath: Path, extract_to: Path) -> None:
        """Extract zip or tar archive"""
        logger.info(f"Extracting {filepath}...")
        
        if filepath.suffix == '.zip':
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif filepath.suffix in ['.tar', '.gz', '.tgz']:
            with tarfile.open(filepath, 'r:*') as tar_ref:
                tar_ref.extractall(extract_to)
        else:
            raise ValueError(f"Unknown archive format: {filepath.suffix}")
            
    def organize_yara_rules(self, source_dir: Path) -> Dict[str, List[str]]:
        """Organize YARA rules by category"""
        categories = {
            "malware": [],
            "exploits": [],
            "suspicious": [],
            "webshells": [],
            "crypto": [],
            "email": [],
            "mobile": []
        }
        
        for yar_file in source_dir.rglob("*.yar"):
            content = yar_file.read_text(errors='ignore').lower()
            
            # Categorize based on content
            if any(word in content for word in ["malware", "trojan", "virus", "ransomware"]):
                categories["malware"].append(str(yar_file))
            elif any(word in content for word in ["exploit", "vulnerability", "cve"]):
                categories["exploits"].append(str(yar_file))
            elif any(word in content for word in ["webshell", "backdoor", "c99", "wso"]):
                categories["webshells"].append(str(yar_file))
            elif any(word in content for word in ["suspicious", "anomaly", "heuristic"]):
                categories["suspicious"].append(str(yar_file))
            else:
                categories["suspicious"].append(str(yar_file))
                
        return categories
        
    def organize_sigma_rules(self, source_dir: Path) -> Dict[str, List[str]]:
        """Organize Sigma rules by platform"""
        categories = {
            "windows": [],
            "linux": [],
            "network": [],
            "cloud": [],
            "web": []
        }
        
        for yml_file in source_dir.rglob("*.yml"):
            try:
                with open(yml_file, 'r') as f:
                    rule = yaml.safe_load(f)
                    
                if not rule:
                    continue
                    
                # Categorize based on logsource
                logsource = rule.get('logsource', {})
                product = logsource.get('product', '').lower()
                category = logsource.get('category', '').lower()
                
                if product == 'windows' or 'windows' in category:
                    categories["windows"].append(str(yml_file))
                elif product == 'linux' or 'linux' in category:
                    categories["linux"].append(str(yml_file))
                elif product in ['zeek', 'suricata'] or 'network' in category:
                    categories["network"].append(str(yml_file))
                elif product in ['aws', 'azure', 'gcp'] or 'cloud' in category:
                    categories["cloud"].append(str(yml_file))
                elif product in ['apache', 'nginx'] or 'web' in category:
                    categories["web"].append(str(yml_file))
                else:
                    categories["linux"].append(str(yml_file))
                    
            except Exception as e:
                logger.warning(f"Error parsing {yml_file}: {e}")
                
        return categories
        
    def download_rules(self):
        """Download and organize all rules"""
        logger.info("Starting rule download...")
        
        # Download YARA rules
        yara_dir = self.rules_dir / "yara"
        yara_dir.mkdir(exist_ok=True)
        
        for repo in RULE_SOURCES["yara"]["repositories"]:
            try:
                # Download
                filename = f"{repo['name'].replace('/', '_')}.zip"
                filepath = self.download_file(repo["url"], filename)
                
                # Extract
                extract_dir = self.temp_dir / "extract"
                extract_dir.mkdir(exist_ok=True)
                self.extract_archive(filepath, extract_dir)
                
                # Find rules
                source_dir = extract_dir / repo["path_in_archive"]
                if source_dir.exists():
                    categories = self.organize_yara_rules(source_dir)
                    
                    # Copy rules to appropriate directories
                    for category, files in categories.items():
                        cat_dir = yara_dir / category
                        cat_dir.mkdir(exist_ok=True)
                        
                        for rule_file in files[:10]:  # Limit rules per category
                            shutil.copy2(rule_file, cat_dir)
                            
                # Cleanup
                shutil.rmtree(extract_dir)
                filepath.unlink()
                
            except Exception as e:
                logger.error(f"Error downloading {repo['name']}: {e}")
                
        # Download Sigma rules
        sigma_dir = self.rules_dir / "sigma"
        sigma_dir.mkdir(exist_ok=True)
        
        for repo in RULE_SOURCES["sigma"]["repositories"]:
            try:
                # Download
                filename = f"{repo['name'].replace('/', '_')}.zip"
                filepath = self.download_file(repo["url"], filename)
                
                # Extract
                extract_dir = self.temp_dir / "extract"
                extract_dir.mkdir(exist_ok=True)
                self.extract_archive(filepath, extract_dir)
                
                # Find rules
                source_dir = extract_dir / repo["path_in_archive"]
                if source_dir.exists():
                    categories = self.organize_sigma_rules(source_dir)
                    
                    # Copy rules to appropriate directories
                    for category, files in categories.items():
                        cat_dir = sigma_dir / category
                        cat_dir.mkdir(exist_ok=True)
                        
                        for rule_file in files[:20]:  # Limit rules per category
                            shutil.copy2(rule_file, cat_dir)
                            
                # Cleanup
                shutil.rmtree(extract_dir)
                filepath.unlink()
                
            except Exception as e:
                logger.error(f"Error downloading {repo['name']}: {e}")
                
        # Create rule index
        self.create_rule_index()
        
        # Cleanup temp directory
        shutil.rmtree(self.temp_dir)
        
        logger.info("Rule download complete!")
        
    def create_rule_index(self):
        """Create an index of all downloaded rules"""
        index = {
            "yara": {},
            "sigma": {},
            "custom": {}
        }
        
        # Index YARA rules
        yara_dir = self.rules_dir / "yara"
        for category_dir in yara_dir.iterdir():
            if category_dir.is_dir():
                index["yara"][category_dir.name] = [
                    f.name for f in category_dir.glob("*.yar")
                ]
                
        # Index Sigma rules
        sigma_dir = self.rules_dir / "sigma"
        for category_dir in sigma_dir.iterdir():
            if category_dir.is_dir():
                index["sigma"][category_dir.name] = [
                    f.name for f in category_dir.glob("*.yml")
                ]
                
        # Save index
        index_file = self.rules_dir / "index.json"
        with open(index_file, 'w') as f:
            json.dump(index, f, indent=2)
            
        logger.info(f"Created rule index at {index_file}")
        

if __name__ == "__main__":
    downloader = RuleDownloader()
    downloader.download_rules()
