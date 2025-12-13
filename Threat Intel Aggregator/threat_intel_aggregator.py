"""
Threat Intelligence Feed Aggregator
Author: cyb3rlop3
Description: Aggregates threat intelligence from multiple security feeds for SOC analysts and security researchers
Use Cases: Threat intelligence gathering, security monitoring, SOC operations, vulnerability tracking
"""

import requests
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urljoin
import time
import re
from dataclasses import dataclass, asdict
from html.parser import HTMLParser

@dataclass
class ThreatIntelItem:
    """Data class for normalized threat intelligence items"""
    title: str
    url: str
    source: str
    published_date: str
    category: str
    description: str = ""
    severity: str = ""
    indicators: List[str] = None
    cve_ids: List[str] = None

    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []
        if self.cve_ids is None:
            self.cve_ids = []


class ThreatIntelAggregator:
    """
    Main aggregator class for collecting threat intelligence from multiple sources.
    """

    def __init__(self, timeout: int = 30, user_agent: str = None):
        """
        Initialize the threat intelligence aggregator.

        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
        """
        self.timeout = timeout
        self.user_agent = user_agent or "ThreatIntelAggregator/1.0 (Security Research Tool)"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self.results: List[ThreatIntelItem] = []
        self.stats = {
            'sources_scraped': 0,
            'items_collected': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }

    def extract_cve_ids(self, text: str) -> List[str]:
        """
        Extract CVE IDs from text.

        Args:
            text: Text to search for CVE IDs

        Returns:
            List of CVE IDs found
        """
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return list(set(re.findall(cve_pattern, text, re.IGNORECASE)))

    def fetch_rss_feed(self, url: str, source_name: str) -> List[ThreatIntelItem]:
        """
        Fetch and parse an RSS feed.

        Args:
            url: RSS feed URL
            source_name: Name of the source

        Returns:
            List of threat intelligence items
        """
        items = []
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()

            root = ET.fromstring(response.content)

            # Handle both RSS 2.0 and Atom feeds
            if root.tag == 'rss':
                channel = root.find('channel')
                entries = channel.findall('item')

                for entry in entries:
                    title = entry.find('title').text if entry.find('title') is not None else ""
                    link = entry.find('link').text if entry.find('link') is not None else ""
                    pub_date = entry.find('pubDate').text if entry.find('pubDate') is not None else ""
                    description = entry.find('description').text if entry.find('description') is not None else ""
                    category = entry.find('category').text if entry.find('category') is not None else "General"

                    # Extract CVE IDs
                    cve_ids = self.extract_cve_ids(f"{title} {description}")

                    item = ThreatIntelItem(
                        title=title.strip(),
                        url=link.strip(),
                        source=source_name,
                        published_date=pub_date,
                        category=category,
                        description=description.strip() if description else "",
                        cve_ids=cve_ids
                    )
                    items.append(item)

            elif root.tag.endswith('feed'):  # Atom feed
                entries = root.findall('.//{http://www.w3.org/2005/Atom}entry')

                for entry in entries:
                    title_elem = entry.find('{http://www.w3.org/2005/Atom}title')
                    link_elem = entry.find('{http://www.w3.org/2005/Atom}link')
                    updated_elem = entry.find('{http://www.w3.org/2005/Atom}updated')
                    summary_elem = entry.find('{http://www.w3.org/2005/Atom}summary')

                    title = title_elem.text if title_elem is not None else ""
                    link = link_elem.get('href') if link_elem is not None else ""
                    pub_date = updated_elem.text if updated_elem is not None else ""
                    description = summary_elem.text if summary_elem is not None else ""

                    cve_ids = self.extract_cve_ids(f"{title} {description}")

                    item = ThreatIntelItem(
                        title=title.strip(),
                        url=link.strip(),
                        source=source_name,
                        published_date=pub_date,
                        category="General",
                        description=description.strip() if description else "",
                        cve_ids=cve_ids
                    )
                    items.append(item)

            self.stats['sources_scraped'] += 1
            self.stats['items_collected'] += len(items)
            print(f"[+] Fetched {len(items)} items from {source_name}")

        except Exception as e:
            print(f"[-] Error fetching {source_name}: {e}")
            self.stats['errors'] += 1

        return items

    def scrape_hacker_news(self, limit: int = 20) -> List[ThreatIntelItem]:
        """
        Scrape The Hacker News RSS feed.

        Args:
            limit: Maximum number of items to retrieve

        Returns:
            List of threat intelligence items
        """
        print("\n[*] Scraping The Hacker News...")
        rss_url = "https://feeds.feedburner.com/TheHackersNews"
        items = self.fetch_rss_feed(rss_url, "The Hacker News")
        return items[:limit] if items else []

    def scrape_cisa_advisories(self, limit: int = 20) -> List[ThreatIntelItem]:
        """
        Fetch CISA cybersecurity advisories via their RSS feed.

        Args:
            limit: Maximum number of items to retrieve

        Returns:
            List of threat intelligence items
        """
        print("\n[*] Scraping CISA Advisories...")
        rss_url = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
        items = self.fetch_rss_feed(rss_url, "CISA")
        return items[:limit] if items else []

    def scrape_sans_isc(self, limit: int = 20) -> List[ThreatIntelItem]:
        """
        Scrape SANS Internet Storm Center RSS feed.

        Args:
            limit: Maximum number of items to retrieve

        Returns:
            List of threat intelligence items
        """
        print("\n[*] Scraping SANS Internet Storm Center...")
        rss_url = "https://isc.sans.edu/rssfeed.xml"
        items = self.fetch_rss_feed(rss_url, "SANS ISC")
        return items[:limit] if items else []

    def scrape_us_cert(self, limit: int = 20) -> List[ThreatIntelItem]:
        """
        Scrape US-CERT Current Activity feed.

        Args:
            limit: Maximum number of items to retrieve

        Returns:
            List of threat intelligence items
        """
        print("\n[*] Scraping US-CERT Current Activity...")
        rss_url = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
        items = self.fetch_rss_feed(rss_url, "US-CERT ICS")
        return items[:limit] if items else []

    def scrape_alienvault_otx(self, limit: int = 20) -> List[ThreatIntelItem]:
        """
        Note: AlienVault OTX requires API key for full access.
        This scrapes public pulses feed.

        Args:
            limit: Maximum number of items to retrieve

        Returns:
            List of threat intelligence items
        """
        print("\n[*] Scraping AlienVault OTX (requires API key for full access)...")
        # Public timeline - limited info without API key
        print("  [i] Note: Full OTX access requires API key. Visit: https://otx.alienvault.com/api")
        return []

    def scrape_openphish(self, limit: int = 20) -> List[ThreatIntelItem]:
        """
        Scrape OpenPhish feed (public feed available).

        Args:
            limit: Maximum number of items to retrieve

        Returns:
            List of threat intelligence items
        """
        print("\n[*] Scraping OpenPhish...")
        items = []
        try:
            url = "https://openphish.com/feed.txt"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()

            urls = response.text.strip().split('\n')[:limit]

            for phishing_url in urls:
                if phishing_url.strip():
                    item = ThreatIntelItem(
                        title=f"Phishing URL detected",
                        url=phishing_url.strip(),
                        source="OpenPhish",
                        published_date=datetime.now().isoformat(),
                        category="Phishing",
                        description=f"Reported phishing site: {phishing_url.strip()}",
                        indicators=[phishing_url.strip()]
                    )
                    items.append(item)

            self.stats['sources_scraped'] += 1
            self.stats['items_collected'] += len(items)
            print(f"[+] Fetched {len(items)} phishing URLs from OpenPhish")

        except Exception as e:
            print(f"[-] Error fetching OpenPhish: {e}")
            self.stats['errors'] += 1

        return items

    def scrape_cisa_kev(self, limit: int = 50) -> List[ThreatIntelItem]:
        """
        Scrape CISA Known Exploited Vulnerabilities catalog.

        Args:
            limit: Maximum number of items to retrieve

        Returns:
            List of threat intelligence items
        """
        print("\n[*] Scraping CISA Known Exploited Vulnerabilities...")
        items = []
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])[:limit]

            for vuln in vulnerabilities:
                item = ThreatIntelItem(
                    title=f"{vuln.get('cveID', 'N/A')}: {vuln.get('vulnerabilityName', 'N/A')}",
                    url=f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID', '')}",
                    source="CISA KEV",
                    published_date=vuln.get('dateAdded', ''),
                    category="Known Exploited Vulnerability",
                    description=vuln.get('shortDescription', ''),
                    severity="High",
                    cve_ids=[vuln.get('cveID', '')],
                    indicators=[vuln.get('vendorProject', ''), vuln.get('product', '')]
                )
                items.append(item)

            self.stats['sources_scraped'] += 1
            self.stats['items_collected'] += len(items)
            print(f"[+] Fetched {len(items)} known exploited vulnerabilities from CISA KEV")

        except Exception as e:
            print(f"[-] Error fetching CISA KEV: {e}")
            self.stats['errors'] += 1

        return items

    def scrape_all(self, items_per_source: int = 20) -> List[ThreatIntelItem]:
        """
        Scrape all configured threat intelligence sources.

        Args:
            items_per_source: Maximum items to retrieve per source

        Returns:
            Combined list of all threat intelligence items
        """
        self.stats['start_time'] = datetime.now().isoformat()
        print("="*80)
        print("THREAT INTELLIGENCE AGGREGATOR")
        print("="*80)

        all_items = []

        # Scrape each source
        all_items.extend(self.scrape_hacker_news(items_per_source))
        time.sleep(1)  # Rate limiting

        all_items.extend(self.scrape_cisa_advisories(items_per_source))
        time.sleep(1)

        all_items.extend(self.scrape_sans_isc(items_per_source))
        time.sleep(1)

        all_items.extend(self.scrape_us_cert(items_per_source))
        time.sleep(1)

        all_items.extend(self.scrape_openphish(items_per_source))
        time.sleep(1)

        all_items.extend(self.scrape_cisa_kev(items_per_source))
        time.sleep(1)

        # Note about API-based sources
        print("\n[i] API-Based Sources (Require API Keys):")
        print("  - AlienVault OTX: https://otx.alienvault.com/api")
        print("  - GreyNoise: https://www.greynoise.io/")
        print("  - abuse.ch: https://urlhaus.abuse.ch/api/")

        self.results = all_items
        self.stats['end_time'] = datetime.now().isoformat()

        return all_items

    def deduplicate(self) -> List[ThreatIntelItem]:
        """
        Remove duplicate items based on URL.

        Returns:
            Deduplicated list of items
        """
        seen_urls = set()
        unique_items = []

        for item in self.results:
            if item.url not in seen_urls:
                seen_urls.add(item.url)
                unique_items.append(item)

        duplicates_removed = len(self.results) - len(unique_items)
        if duplicates_removed > 0:
            print(f"\n[*] Removed {duplicates_removed} duplicate items")

        self.results = unique_items
        return unique_items

    def filter_by_keywords(self, keywords: List[str]) -> List[ThreatIntelItem]:
        """
        Filter results by keywords in title or description.

        Args:
            keywords: List of keywords to search for

        Returns:
            Filtered list of items
        """
        filtered = []
        keywords_lower = [k.lower() for k in keywords]

        for item in self.results:
            text = f"{item.title} {item.description}".lower()
            if any(keyword in text for keyword in keywords_lower):
                filtered.append(item)

        return filtered

    def filter_by_cve(self) -> List[ThreatIntelItem]:
        """
        Filter results to only items containing CVE IDs.

        Returns:
            Filtered list of items with CVEs
        """
        return [item for item in self.results if item.cve_ids]

    def export_json(self, filename: str):
        """
        Export results to JSON file.

        Args:
            filename: Output filename
        """
        output = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_items': len(self.results),
                'statistics': self.stats
            },
            'threat_intelligence': [asdict(item) for item in self.results]
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"\n[+] JSON report saved to: {filename}")

    def export_csv(self, filename: str):
        """
        Export results to CSV file.

        Args:
            filename: Output filename
        """
        if not self.results:
            print("No results to export")
            return

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['title', 'url', 'source', 'published_date', 'category',
                         'description', 'severity', 'cve_ids']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for item in self.results:
                row = asdict(item)
                row['cve_ids'] = ', '.join(row['cve_ids']) if row['cve_ids'] else ''
                row['indicators'] = ', '.join(row['indicators']) if row['indicators'] else ''
                writer.writerow({k: row[k] for k in fieldnames})

        print(f"[+] CSV report saved to: {filename}")

    def export_html(self, filename: str):
        """
        Export results to HTML file.

        Args:
            filename: Output filename
        """
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Threat Intelligence Report - {date}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background-color: #1a1a2e; color: white; padding: 20px; border-radius: 5px; }}
        .stats {{ background-color: #16213e; color: white; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .item {{ background-color: white; margin: 15px 0; padding: 15px; border-left: 4px solid #0066cc; border-radius: 3px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .item h3 {{ margin-top: 0; color: #1a1a2e; }}
        .source {{ display: inline-block; background-color: #0066cc; color: white; padding: 3px 10px; border-radius: 3px; font-size: 12px; margin-right: 10px; }}
        .category {{ display: inline-block; background-color: #00cc66; color: white; padding: 3px 10px; border-radius: 3px; font-size: 12px; }}
        .cve {{ display: inline-block; background-color: #cc0000; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; margin: 2px; }}
        .date {{ color: #666; font-size: 14px; }}
        .description {{ color: #444; margin-top: 10px; line-height: 1.6; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .severity-high {{ border-left-color: #cc0000; }}
        .severity-medium {{ border-left-color: #ff9900; }}
        .severity-low {{ border-left-color: #00cc66; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Threat Intelligence Report</h1>
        <p>Generated: {date}</p>
    </div>

    <div class="stats">
        <h2>📊 Statistics</h2>
        <p><strong>Total Items:</strong> {total_items}</p>
        <p><strong>Sources Scraped:</strong> {sources_scraped}</p>
        <p><strong>Items with CVEs:</strong> {items_with_cves}</p>
        <p><strong>Errors:</strong> {errors}</p>
    </div>

    <div class="items">
        {items_html}
    </div>
</body>
</html>
"""

        items_html = ""
        for item in self.results:
            severity_class = f"severity-{item.severity.lower()}" if item.severity else ""
            cve_badges = " ".join([f'<span class="cve">{cve}</span>' for cve in item.cve_ids]) if item.cve_ids else ""

            items_html += f"""
    <div class="item {severity_class}">
        <h3><a href="{item.url}" target="_blank">{item.title}</a></h3>
        <div>
            <span class="source">{item.source}</span>
            <span class="category">{item.category}</span>
            {cve_badges}
        </div>
        <p class="date">📅 {item.published_date}</p>
        <p class="description">{item.description}</p>
    </div>
"""

        items_with_cves = len([item for item in self.results if item.cve_ids])

        html_content = html_template.format(
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_items=len(self.results),
            sources_scraped=self.stats['sources_scraped'],
            items_with_cves=items_with_cves,
            errors=self.stats['errors'],
            items_html=items_html
        )

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"[+] HTML report saved to: {filename}")

    def print_summary(self):
        """Print a summary of collected intelligence."""
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        print(f"Total items collected: {len(self.results)}")
        print(f"Sources scraped: {self.stats['sources_scraped']}")
        print(f"Errors encountered: {self.stats['errors']}")

        # Count items by source
        source_counts = {}
        for item in self.results:
            source_counts[item.source] = source_counts.get(item.source, 0) + 1

        print("\nItems by source:")
        for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {source}: {count}")

        # Count CVEs
        total_cves = sum(len(item.cve_ids) for item in self.results)
        items_with_cves = len([item for item in self.results if item.cve_ids])
        print(f"\nCVE Statistics:")
        print(f"  Items with CVEs: {items_with_cves}")
        print(f"  Total CVE IDs: {total_cves}")

        print("="*80)


def main():
    """
    Main function demonstrating usage of the Threat Intelligence Aggregator.
    """
    # Initialize aggregator
    aggregator = ThreatIntelAggregator()

    # Scrape all sources
    results = aggregator.scrape_all(items_per_source=15)

    # Deduplicate results
    aggregator.deduplicate()

    # Print summary
    aggregator.print_summary()

    # Export results in multiple formats
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    aggregator.export_json(f'threat_intel_{timestamp}.json')
    aggregator.export_csv(f'threat_intel_{timestamp}.csv')
    aggregator.export_html(f'threat_intel_{timestamp}.html')

    print(f"\n[+] Threat intelligence aggregation complete!")
    print(f"[*] Check the generated files for detailed reports")

    # Example: Filter for specific keywords
    print("\n" + "="*80)
    print("EXAMPLE: Filtering for ransomware-related threats")
    print("="*80)
    ransomware_items = aggregator.filter_by_keywords(['ransomware', 'malware', 'backdoor'])
    print(f"Found {len(ransomware_items)} ransomware-related items")

    # Show first 5
    for item in ransomware_items[:5]:
        print(f"\n  - {item.title}")
        print(f"  Source: {item.source} | Date: {item.published_date}")
        print(f"  {item.url}")


if __name__ == '__main__':
    main()
