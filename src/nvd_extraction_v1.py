#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NVD Vulnerability Extractor

This script extracts critical CVE (Common Vulnerabilities and Exposures) data from the
National Vulnerability Database (NVD) API. It focuses on vulnerabilities with network
attack vectors and provides filtering to identify issues affecting Linux, Windows,
and externally facing APIs.

The script extracts data for the past 360 days, processes it into several formats,
and saves the results in CSV and JSON formats in an organized directory structure.

Author: Nic Cravino
Date: February 27, 2025
License: Apache License 2.0
Repository: https://github.com/spidernic/NVD-Extractor
"""

import requests
import csv
import json
from datetime import datetime, timedelta, timezone
import time
import os
import io
import sys

# Read configuration from environment variables with defaults
CVE_AGE_DAYS = int(os.environ.get("CVE_AGE_DAYS", "360"))
ATTACK_VECTOR_FILTER = os.environ.get("ATTACK_VECTOR", "NETWORK").upper()
SEVERITY_FILTER = os.environ.get("SEVERITY", "CRITICAL").upper()
OUTPUT_FORMAT = os.environ.get("OUTPUT_FORMAT", "both").lower()
WRITE_CSV = OUTPUT_FORMAT in ("csv", "both")
WRITE_JSON = OUTPUT_FORMAT in ("json", "both")

# Create a custom stdout capture class to save console output for the report
class OutputCapture:
    def __init__(self):
        self.log = []
        self.original_stdout = sys.stdout
        self.capture_enabled = True
    
    def write(self, text):
        # Write to original stdout
        self.original_stdout.write(text)
        # Also capture the output
        if self.capture_enabled:
            self.log.append(text)
    
    def flush(self):
        self.original_stdout.flush()
    
    def get_log(self):
        return ''.join(self.log)

# Enable output capturing
output_capturer = OutputCapture()
sys.stdout = output_capturer

# Create output directory and datestamp for output files
output_dir = os.path.join(os.getcwd(), "output")
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

data_stamp = datetime.now().strftime("%Y-%m-%d")
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Create subfolders for CSV and JSON outputs
csv_output_dir = os.path.join(output_dir, "CSV")
if not os.path.exists(csv_output_dir):
    os.makedirs(csv_output_dir)

json_output_dir = os.path.join(output_dir, "JSON")
if not os.path.exists(json_output_dir):
    os.makedirs(json_output_dir)

# Create reports directory
reports_dir = os.path.join(output_dir, "reports")
if not os.path.exists(reports_dir):
    os.makedirs(reports_dir)

# Create llm directory for LLM-optimized outputs
llm_output_dir = os.path.join(output_dir, "LLM")
if not os.path.exists(llm_output_dir):
    os.makedirs(llm_output_dir)

# Calculate date range based on configured age
end_date = datetime.now(timezone.utc)
start_date = end_date - timedelta(days=CVE_AGE_DAYS)

# Define date ranges for three 120-day periods (NVD API has a 120-day limit per request)
date_ranges = [
    (start_date, start_date + timedelta(days=120)),
    (start_date + timedelta(days=120), start_date + timedelta(days=240)),
    (start_date + timedelta(days=240), end_date)
]

# Initialize a list to store the CVE data
cve_list = []

# Loop through each 120-day period
for period_start, period_end in date_ranges:
    # Format the dates for the API request
    start_date_str = period_start.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end_date_str = period_end.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    print(f"Fetching data from {period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}")
    
    # Set up the API request parameters
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_date_str,
        "pubEndDate": end_date_str,
        "cvssV3Severity": SEVERITY_FILTER,  # Severity filter from configuration
        "resultsPerPage": 2000,         # Maximum allowed by the API
        "startIndex": 0                 # Start at the beginning
    }
    
    # Process all pages of results
    while True:
        try:
            # Make the API request
            response = requests.get(base_url, params=params)
            
            # Check if the request was successful
            if response.status_code == 200:
                data = response.json()
                
                # Process each CVE in the results
                for cve in data.get("vulnerabilities", []):
                    cve_data = cve.get("cve", {})
                    
                    # Extract the metrics
                    metrics = cve_data.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if "cvssMetricV31" in metrics else {}
                    
                    # Filter CVEs by the chosen attack vector
                    if cvss_data.get("attackVector") == ATTACK_VECTOR_FILTER:
                        # Extract basic CVE information
                        cve_id = cve_data.get("id", "N/A")
                        
                        # Extract English description, or use "No description available" if not found
                        description = "No description available"
                        for desc in cve_data.get("descriptions", []):
                            if desc.get("lang") == "en":
                                description = desc.get("value", "No description available")
                                break
                        
                        # Extract CVSS score
                        cvss_score = cvss_data.get("baseScore", "N/A")
                        
                        # Extract CVSS vector components for detailed analysis
                        attack_vector = cvss_data.get("attackVector", "N/A")
                        attack_complexity = cvss_data.get("attackComplexity", "N/A")
                        privileges_required = cvss_data.get("privilegesRequired", "N/A")
                        user_interaction = cvss_data.get("userInteraction", "N/A")
                        scope = cvss_data.get("scope", "N/A")
                        
                        # Extract CWE (Common Weakness Enumeration) information
                        cwe_info = []
                        for weakness in cve_data.get("weaknesses", []):
                            for desc in weakness.get("description", []):
                                cwe_info.append(desc.get("value", ""))
                        cwe_info_str = "; ".join(cwe_info) if cwe_info else "N/A"
                        
                        # Extract reference tags to identify related information types
                        ref_tags = []
                        for ref in cve_data.get("references", []):
                            ref_tags.extend(ref.get("tags", []))
                        ref_tags_str = "; ".join(set(ref_tags)) if ref_tags else "N/A"
                        
                        # Extract CPE (Common Platform Enumeration) information for affected products
                        cpe_uris = []
                        affects_linux = "No"
                        affects_windows = "No"
                        
                        # Traverse the configuration tree to find all CPE matches
                        for config in cve_data.get("configurations", []):
                            for node in config.get("nodes", []):
                                for match in node.get("cpeMatch", []):
                                    # Get the CPE criteria (previously incorrectly using cpe23Uri)
                                    cpe_uri = match.get("criteria", "")
                                    
                                    if cpe_uri:
                                        cpe_uris.append(cpe_uri)
                                        
                                        # Check if the CPE affects Linux or Windows
                                        if "linux" in cpe_uri.lower():
                                            affects_linux = "Yes"
                                        if "windows" in cpe_uri.lower():
                                            affects_windows = "Yes"
                        
                        # Join the CPE URIs into a string, or use "N/A" if none
                        affected_cpes = "; ".join(cpe_uris) if cpe_uris else "N/A"
                        
                        # Determine if the CVE is likely to affect externally facing APIs
                        # Criteria: Network attack vector, no privileges required, and either
                        # no user interaction or related to input validation
                        likely_external_api = "No"
                        if (attack_vector == "NETWORK" and 
                            privileges_required == "NONE" and 
                            (user_interaction == "NONE" or "CWE-20" in cwe_info_str)):
                            likely_external_api = "Yes"
                        
                        # Create a dictionary for this CVE
                        cve_dict = {
                            "CVE ID": cve_id,
                            "Description": description,
                            "CVSS Score": cvss_score,
                            "Attack Vector": attack_vector,
                            "Attack Complexity": attack_complexity,
                            "Privileges Required": privileges_required,
                            "User Interaction": user_interaction,
                            "Scope": scope,
                            "CWE Information": cwe_info_str,
                            "Reference Tags": ref_tags_str,
                            "Affects Linux": affects_linux,
                            "Affects Windows": affects_windows,
                            "Likely External API": likely_external_api,
                            "Affected CPEs": affected_cpes
                        }
                        
                        # Add the CVE to the list
                        cve_list.append(cve_dict)
                
                # Check if there are more results to fetch
                total_results = data.get("totalResults", 0)
                start_index = params["startIndex"] + data.get("resultsPerPage", 0)
                
                if start_index >= total_results:
                    # No more results to fetch for this period
                    break
                
                # Update startIndex for the next page
                params["startIndex"] = start_index
                
                # Add a delay to respect API rate limits
                time.sleep(1)
            else:
                # Handle error
                print(f"Error: {response.status_code}")
                print(response.text)
                break
                
        except Exception as e:
            print(f"An error occurred: {e}")
            break
    
    print(f"Completed fetching data for period. Found {len(cve_list)} matching CVEs so far.")
    
    # Add a delay between period requests to avoid hitting rate limits
    time.sleep(5)

# Print summary of results
print(f"Total filtered CVEs with CRITICAL severity and Network attack vector: {len(cve_list)}")

# Define the column headers for all CSV files
fieldnames = [
    "CVE ID", "Description", "CVSS Score", 
    "Attack Vector", "Attack Complexity", "Privileges Required", "User Interaction", "Scope",
    "CWE Information", "Reference Tags", "Affects Linux", "Affects Windows", "Likely External API", "Affected CPEs"
]

# Write critical_cves to CSV if enabled
if WRITE_CSV:
    with open(os.path.join(csv_output_dir, f"critical_cves_{data_stamp}.csv"), "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(cve_list)
    print("Saved to critical_cves CSV")

# Write critical_cves to JSON if enabled
if WRITE_JSON:
    with open(os.path.join(json_output_dir, f"critical_cves_{data_stamp}.json"), "w", encoding="utf-8") as jsonfile:
        json.dump(cve_list, jsonfile, indent=4, ensure_ascii=False)
    print("Saved to critical_cves JSON")

# Create filtered output for Linux, Windows, and External API vulnerabilities
filtered_cves = []
for cve in cve_list:
    # Include if it affects Linux, Windows, or is likely an external API vulnerability
    if (cve["Affects Linux"] == "Yes" or 
        cve["Affects Windows"] == "Yes" or 
        cve["Likely External API"] == "Yes"):
        filtered_cves.append(cve)

print(f"Found {len(filtered_cves)} vulnerabilities matching filtering criteria (Linux, Windows, or External APIs)")

# Write filtered_cves to CSV if enabled
if WRITE_CSV:
    with open(os.path.join(csv_output_dir, f"filtered_cves_{data_stamp}.csv"), "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(filtered_cves)
    print("Saved to filtered_cves CSV")

# Write filtered_cves to JSON if enabled
if WRITE_JSON:
    with open(os.path.join(json_output_dir, f"filtered_cves_{data_stamp}.json"), "w", encoding="utf-8") as jsonfile:
        json.dump(filtered_cves, jsonfile, indent=4, ensure_ascii=False)
    print("Saved to filtered_cves JSON")

# Create individual filtered files for each category
linux_cves = [cve for cve in cve_list if cve["Affects Linux"] == "Yes"]
windows_cves = [cve for cve in cve_list if cve["Affects Windows"] == "Yes"]
api_cves = [cve for cve in cve_list if cve["Likely External API"] == "Yes"]

# Write Linux vulnerabilities to CSV if enabled
if WRITE_CSV:
    with open(os.path.join(csv_output_dir, f"linux_cves_{data_stamp}.csv"), "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(linux_cves)
    print(f"Saved {len(linux_cves)} Linux vulnerabilities to linux_cves CSV")

# Write Windows vulnerabilities to CSV if enabled
if WRITE_CSV:
    with open(os.path.join(csv_output_dir, f"windows_cves_{data_stamp}.csv"), "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(windows_cves)
    print(f"Saved {len(windows_cves)} Windows vulnerabilities to windows_cves CSV")

# Write External API vulnerabilities to CSV if enabled
if WRITE_CSV:
    with open(os.path.join(csv_output_dir, f"api_cves_{data_stamp}.csv"), "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(api_cves)
    print(f"Saved {len(api_cves)} External API vulnerabilities to api_cves CSV")

# Print final summary of vulnerability counts
print("\nSummary of vulnerability counts:")
print(f"Total critical vulnerabilities with network attack vector: {len(cve_list)}")
print(f"Affecting Linux: {len(linux_cves)}")
print(f"Affecting Windows: {len(windows_cves)}")
print(f"Likely affecting External APIs: {len(api_cves)}")
print(f"Combined filtered set (any of the above): {len(filtered_cves)}")

# Create LLM-optimized JSON outputs
print("\nGenerating LLM-optimized JSON files...")

# Function to convert a CVE to an LLM-optimized format
def create_llm_optimized_cve(cve):
    """
    Create a simplified version of the CVE dict with the most important fields
    optimized for LLM context windows
    """
    return {
        "id": cve["CVE ID"],
        "description": cve["Description"],
        "score": cve["CVSS Score"],
        "attack_vector": cve["Attack Vector"],
        "attack_complexity": cve["Attack Complexity"],
        "privileges_required": cve["Privileges Required"],
        "user_interaction": cve["User Interaction"],
        "cwe": cve["CWE Information"],
        "affects_linux": cve["Affects Linux"] == "Yes",
        "affects_windows": cve["Affects Windows"] == "Yes",
        "likely_external_api": cve["Likely External API"] == "Yes"
    }

# Process each category of vulnerabilities for LLM optimization
for category, cve_list_subset, description in [
    ("critical", cve_list, "All critical vulnerabilities with network attack vector"),
    ("filtered", filtered_cves, "Combined set of vulnerabilities affecting Linux, Windows, or external APIs"),
    ("linux", linux_cves, "Vulnerabilities specifically affecting Linux systems"),
    ("windows", windows_cves, "Vulnerabilities specifically affecting Windows systems"),
    ("api", api_cves, "Vulnerabilities likely to affect externally facing APIs")
]:
    # Skip if empty to avoid creating empty files
    if not cve_list_subset:
        continue
        
    # Create LLM-optimized version of the data
    llm_optimized_cves = [create_llm_optimized_cve(cve) for cve in cve_list_subset]
    
    # Sort by CVSS score (highest first) to prioritize most severe vulnerabilities
    llm_optimized_cves.sort(key=lambda x: float(x["score"]), reverse=True)
    
    # Create a context wrapper for the data
    llm_context = {
        "data_type": "NVD CVE Vulnerabilities",
        "category": category,
        "description": description,
        "date_range": f"Last 360 days as of {data_stamp}",
        "count": len(llm_optimized_cves),
        "vulnerabilities": llm_optimized_cves
    }
    
    # Save to a JSON file with both compact and readable versions if enabled
    if WRITE_JSON:
        llm_file_path = os.path.join(llm_output_dir, f"{category}_cves_llm_{data_stamp}.json")
        with open(llm_file_path, "w", encoding="utf-8") as jsonfile:
            json.dump(llm_context, jsonfile, indent=2, ensure_ascii=False)

        # Create a prompt-ready version with Markdown formatting
        prompt_file_path = os.path.join(llm_output_dir, f"{category}_cves_prompt_{data_stamp}.md")
        with open(prompt_file_path, "w", encoding="utf-8") as promptfile:
            promptfile.write(f"""# {category.title()} CVE Vulnerabilities Data

## Description
{description} from the past 360 days (as of {data_stamp}).

## Vulnerabilities Count
{len(llm_optimized_cves)} vulnerabilities found

## JSON Data for LLM Context
```json
{json.dumps(llm_optimized_cves[:50] if len(llm_optimized_cves) > 50 else llm_optimized_cves, indent=2, ensure_ascii=False)}
```

{f"Note: Only showing the first 50 of {len(llm_optimized_cves)} vulnerabilities to fit within context limits. Vulnerabilities are sorted by CVSS score (highest first)." if len(llm_optimized_cves) > 50 else ""}

## Example Prompt:
```
Analyze these vulnerability details and identify patterns, trends, or notable security concerns:

[Insert the JSON data above here]

Based on this data, what are the most significant security risks and what mitigation strategies would you recommend?
```
""")

print(f"LLM-optimized outputs saved to {llm_output_dir}/")

# Create Markdown report file
print("\nGenerating Markdown report...")

# Disable further capturing to avoid recursive output
output_capturer.capture_enabled = False

# Generate the report content
report_content = f"""# NVD Vulnerability Extraction Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Execution Summary

```
{output_capturer.get_log()}
```

## Results Summary

| Category | Count |
|----------|-------|
| Critical CVEs with Network Attack Vector | {len(cve_list)} |
| Affecting Linux | {len(linux_cves)} |
| Affecting Windows | {len(windows_cves)} |
| Likely Affecting External APIs | {len(api_cves)} |
| Combined Filtered Set | {len(filtered_cves)} |

## Output Files

| File | Description |
|------|-------------|
| `output/CSV/critical_cves_{data_stamp}.csv` | All critical vulnerabilities with network attack vector |
| `output/JSON/critical_cves_{data_stamp}.json` | Same as above, in JSON format |
| `output/CSV/filtered_cves_{data_stamp}.csv` | Combined set of vulnerabilities affecting Linux, Windows, or external APIs |
| `output/JSON/filtered_cves_{data_stamp}.json` | Same as above, in JSON format |
| `output/CSV/linux_cves_{data_stamp}.csv` | Vulnerabilities specifically affecting Linux systems |
| `output/CSV/windows_cves_{data_stamp}.csv` | Vulnerabilities specifically affecting Windows systems |
| `output/CSV/api_cves_{data_stamp}.csv` | Vulnerabilities likely to affect externally facing APIs |

## Analysis

- **Linux Vulnerabilities:** {len(linux_cves)} critical CVEs with network attack vector affecting Linux systems.
- **Windows Vulnerabilities:** {len(windows_cves)} critical CVEs with network attack vector affecting Windows systems.
- **External API Vulnerabilities:** {len(api_cves)} critical CVEs likely to affect externally facing APIs.

This report was generated automatically by the NVD Vulnerability Extractor.
"""

# Save the report to a Markdown file with timestamp
report_file_path = os.path.join(reports_dir, f"nvd_extraction_report_{timestamp}.md")
with open(report_file_path, "w", encoding="utf-8") as report_file:
    report_file.write(report_content)

print(f"Markdown report saved to: {report_file_path}")

# Reset stdout to the original
sys.stdout = output_capturer.original_stdout