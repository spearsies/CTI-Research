# Usage Examples

The following examples demonstrate how the **Threat Intelligence Aggregator** can be applied in real-world scenarios.  
They are organized by role to show practical value across different security functions.

---

## 👨‍💻 SOC Analysts

### Daily Threat Intelligence Brief
```python
from threat_intel_aggregator import ThreatIntelAggregator
from datetime import datetime

aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=30)
aggregator.deduplicate()

date_str = datetime.now().strftime('%Y-%m-%d')
aggregator.export_html(f'daily_threat_brief_{date_str}.html')
aggregator.export_json(f'daily_threat_brief_{date_str}.json')

print(f"Daily brief generated with {len(results)} threat intelligence items")
```

### Incident Response
```python
aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=30)

incident_keywords = ['ransomware', 'lockbit', 'phishing']
related = aggregator.filter_by_keywords(incident_keywords)

aggregator.results = related
aggregator.export_html('incident_threat_intel.html')
```

---

## 🕵️ Threat Intelligence Analysts

### Weekly Intelligence Report
```python
aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=100)
aggregator.deduplicate()

aggregator.export_html('weekly_intel_report.html')
aggregator.export_csv('weekly_intel_data.csv')

cve_items = aggregator.filter_by_cve()
print(f"This week's CVEs: {len(cve_items)}")
```

### CVE-Focused Intelligence
```python
aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=25)

cve_items = aggregator.filter_by_cve()
print(f"Found {len(cve_items)} items with CVE IDs")

aggregator.results = cve_items
aggregator.export_csv('cve_threats.csv')
```

---

## 🔬 Security Researchers

### Trend Analysis
```python
import os
from datetime import datetime
from threat_intel_aggregator import ThreatIntelAggregator

aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=50)

timestamp = datetime.now().strftime('%Y%m%d')
aggregator.export_json(f'data/threat_intel_{timestamp}.json')
```

---

## 📑 Compliance Teams

### Regulatory Reporting
```python
aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=50)

gov_sources = [item for item in aggregator.results
               if item.source in ['CISA', 'US-CERT ICS', 'CISA KEV']]

aggregator.results = gov_sources
aggregator.export_csv('compliance_threat_report.csv')
```

---

## ⚙️ Advanced Features

### Keyword-Based Threat Hunting
```python
aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=20)

keywords = ['ransomware', 'apt', 'zero-day', 'backdoor', 'supply chain']
filtered = aggregator.filter_by_keywords(keywords)

aggregator.results = filtered
aggregator.export_html('priority_threats.html')
```

### Automated Morning Briefing
```python
import schedule, time
from threat_intel_aggregator import ThreatIntelAggregator

def morning_briefing():
    aggregator = ThreatIntelAggregator()
    results = aggregator.scrape_all(items_per_source=15)
    aggregator.deduplicate()

    priority_keywords = ['critical', 'emergency', 'zero-day', 'ransomware', 'apt']
    priority_items = aggregator.filter_by_keywords(priority_keywords)

    aggregator.export_html('morning_briefing.html')

    if priority_items:
        aggregator.results = priority_items
        aggregator.export_html('high_priority_threats.html')
        print(f"⚠️  {len(priority_items)} high-priority threats identified!")

    aggregator.print_summary()

schedule.every().day.at("07:00").do(morning_briefing)
```

---

## 🔌 SIEM Integration

### JSON Export
```python
aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=50)
aggregator.deduplicate()

aggregator.export_json('siem_threat_feed.json')
```

### IOC Extraction
```python
import json

with open('siem_threat_feed.json', 'r') as f:
    data = json.load(f)

iocs = []
for item in data['threat_intelligence']:
    if item['indicators']:
        iocs.extend(item['indicators'])

print(f"Extracted {len(set(iocs))} unique indicators of compromise")
```

---

## 🏛️ Government Source Scraping

### CISA Intelligence
```python
aggregator = ThreatIntelAggregator()

cisa_advisories = aggregator.scrape_cisa_advisories(limit=50)
cisa_kev = aggregator.scrape_cisa_kev(limit=100)

aggregator.results = cisa_advisories + cisa_kev
aggregator.export_html('cisa_intelligence.html')
aggregator.export_json('cisa_intelligence.json')
```

---

This `/docs/USAGE_EXAMPLES.md` file keeps all your **detailed code snippets organized by role**, making it easy for technical peers to explore while keeping your main README concise and recruiter‑friendly.

---
