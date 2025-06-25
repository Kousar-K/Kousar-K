# 🛡️ IOC Aggregator Script using APIs

A Python-based tool that automates the enrichment and classification of Indicators of Compromise (IOCs) using public threat intelligence APIs.

## 🔍 About the Project

This script supports cybersecurity operations by:
- Aggregating IOC data (IPs, domains, URLs, and file hashes)
- Enriching them with real-time intelligence using multiple APIs
- Exporting categorized and formatted results into CSV reports

## 🚀 Features

- ✅ Supports IPs, URLs, Domains, and Hashes
- ✅ Integrates APIs: VirusTotal, Shodan, ipwhois, URLScan
- ✅ Outputs enriched data with tags like reputation, location, and threat category
- ✅ Exports structured CSV for use in security reports or SIEM tools

## 🧰 Tech Stack

- **Language**: Python  
- **Libraries**: `requests`, `csv`, `json`, `os`, `datetime`  
- **APIs Used**:
  - [VirusTotal](https://www.virustotal.com/)
  - [Shodan](https://www.shodan.io/)
  - [ipwhois.io](https://ipwhois.io/)
  - [urlscan.io](https://urlscan.io/)

## 🧪 Sample Output

| IOC Type | Value              | Source     | Country | Threat Level | Description      |
|----------|--------------------|------------|---------|---------------|------------------|
| IP       | 192.0.2.1          | Shodan     | US      | High          | Malware host     |
| Domain   | example.com        | VirusTotal | US      | Medium        | Phishing suspect |

## 📂 Folder Structure


