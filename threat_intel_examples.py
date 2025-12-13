"""
Threat Intelligence Aggregator - Usage Examples
Author: cyb3rlop3
Description: Practical examples for using the threat intelligence aggregator
"""

from threat_intel_aggregator import ThreatIntelAggregator
from datetime import datetime
import json


def example_basic_usage():
    """Example 1: Basic threat intelligence collection"""
    print("="*80)
    print("EXAMPLE 1: Basic Threat Intelligence Collection")
    print("="*80)

    aggregator = ThreatIntelAggregator()
    results = aggregator.scrape_all(items_per_source=10)
    aggregator.deduplicate()

    print(f"\nCollected {len(results)} unique threat intelligence items")

    aggregator.export_json('basic_threat_intel.json')
    aggregator.export_html('basic_threat_intel.html')

    print("\n✅ Basic collection complete!")


def example_cve_hunting():
    """Example 2: Hunt for CVEs and vulnerabilities"""
    print("\n" + "="*80)
    print("EXAMPLE 2: CVE Hunting")
    print("="*80)

    aggregator = ThreatIntelAggregator()

    # Focus on vulnerability sources
    print("\n[*] Collecting vulnerability intelligence...")
    cisa_kev = aggregator.scrape_cisa_kev(limit=50)
    cisa_advisories = aggregator.scrape_cisa_advisories(limit=30)
    hacker_news = aggregator.scrape_hacker_news(limit=20)

    aggregator.results = cisa_kev + cisa_advisories + hacker_news
    aggregator.deduplicate()

    # Filter for CVE items
    cve_items = aggregator.filter_by_cve()

    print(f"\n[+] Found {len(cve_items)} items containing CVE IDs")

    # Extract all unique CVEs
    all_cves = set()
    for item in cve_items:
        all_cves.update(item.cve_ids)

    print(f"[+] Total unique CVEs: {len(all_cves)}")
    print("\nRecent CVEs:")
    for cve in sorted(all_cves)[:15]:
        print(f"  • {cve}")

    # Export CVE-focused report
    aggregator.results = cve_items
    aggregator.export_html('cve_report.html')
    aggregator.export_csv('cve_list.csv')

    print("\n✅ CVE hunting complete!")


def example_keyword_filtering():
    """Example 3: Keyword-based threat hunting"""
    print("\n" + "="*80)
    print("EXAMPLE 3: Keyword-Based Threat Hunting")
    print("="*80)

    aggregator = ThreatIntelAggregator()
    results = aggregator.scrape_all(items_per_source=20)
    aggregator.deduplicate()

    # Define threat keywords
    threat_keywords = {
        'ransomware': ['ransomware', 'lockbit', 'ryuk', 'conti'],
        'apt': ['apt', 'advanced persistent', 'nation-state', 'state-sponsored'],
        'phishing': ['phishing', 'spoofing', 'credential harvesting'],
        'malware': ['malware', 'trojan', 'backdoor', 'rat'],
        'zero-day': ['zero-day', '0-day', 'zero day']
    }

    print("\n[*] Hunting for specific threat types...\n")

    for threat_type, keywords in threat_keywords.items():
        matches = aggregator.filter_by_keywords(keywords)
        print(f"[{threat_type.upper()}] Found {len(matches)} related items")

        if matches:
            # Show top 3 items
            for item in matches[:3]:
                print(f"  • {item.title[:80]}...")

    # Export high-priority threats
    priority_keywords = ['zero-day', 'critical', 'ransomware', 'apt']
    priority_items = aggregator.filter_by_keywords(priority_keywords)

    if priority_items:
        aggregator.results = priority_items
        aggregator.export_html('priority_threats.html')
        print(f"\n[!] Exported {len(priority_items)} high-priority threats")

    print("\n✅ Keyword hunting complete!")


def example_daily_briefing():
    """Example 4: Generate daily security briefing"""
    print("\n" + "="*80)
    print("EXAMPLE 4: Daily Security Briefing")
    print("="*80)

    aggregator = ThreatIntelAggregator()

    print("\n[*] Collecting intelligence for daily briefing...")
    results = aggregator.scrape_all(items_per_source=15)
    aggregator.deduplicate()

    # Generate timestamped report
    date_str = datetime.now().strftime('%Y-%m-%d')
    aggregator.export_html(f'daily_briefing_{date_str}.html')
    aggregator.export_json(f'daily_briefing_{date_str}.json')

    # Print summary
    aggregator.print_summary()

    # Highlight critical items
    critical_keywords = ['critical', 'emergency', 'zero-day', 'actively exploited']
    critical_items = aggregator.filter_by_keywords(critical_keywords)

    if critical_items:
        print(f"\n⚠️  CRITICAL ALERTS: {len(critical_items)} items require immediate attention")
        for item in critical_items[:5]:
            print(f"\n  [{item.source}] {item.title}")
            print(f"  🔗 {item.url}")
            if item.cve_ids:
                print(f"  CVEs: {', '.join(item.cve_ids)}")

    print("\n✅ Daily briefing generated!")


def example_source_specific():
    """Example 5: Scrape specific sources only"""
    print("\n" + "="*80)
    print("EXAMPLE 5: Source-Specific Intelligence Gathering")
    print("="*80)

    aggregator = ThreatIntelAggregator()

    # Option 1: Government sources only
    print("\n[*] Collecting from government sources (CISA, US-CERT)...")
    cisa_advisories = aggregator.scrape_cisa_advisories(limit=25)
    cisa_kev = aggregator.scrape_cisa_kev(limit=50)
    us_cert = aggregator.scrape_us_cert(limit=20)

    aggregator.results = cisa_advisories + cisa_kev + us_cert
    aggregator.export_html('government_intel.html')

    print(f"[+] Collected {len(aggregator.results)} items from government sources")

    # Option 2: News sources only
    print("\n[*] Collecting from news sources...")
    aggregator_news = ThreatIntelAggregator()
    hacker_news = aggregator_news.scrape_hacker_news(limit=30)
    sans = aggregator_news.scrape_sans_isc(limit=25)

    aggregator_news.results = hacker_news + sans
    aggregator_news.export_html('news_intel.html')

    print(f"[+] Collected {len(aggregator_news.results)} items from news sources")

    # Option 3: Phishing intelligence only
    print("\n[*] Collecting phishing intelligence...")
    aggregator_phish = ThreatIntelAggregator()
    phishing = aggregator_phish.scrape_openphish(limit=100)

    aggregator_phish.results = phishing
    aggregator_phish.export_csv('phishing_urls.csv')

    print(f"[+] Collected {len(phishing)} phishing URLs")

    print("\n✅ Source-specific collection complete!")


def example_siem_integration():
    """Example 6: Format data for SIEM integration"""
    print("\n" + "="*80)
    print("EXAMPLE 6: SIEM Integration Preparation")
    print("="*80)

    aggregator = ThreatIntelAggregator()
    results = aggregator.scrape_all(items_per_source=30)
    aggregator.deduplicate()

    # Export structured JSON for SIEM
    aggregator.export_json('siem_feed.json')

    # Load and process for SIEM
    with open('siem_feed.json', 'r') as f:
        data = json.load(f)

    # Extract IOCs (Indicators of Compromise)
    iocs = {
        'urls': set(),
        'domains': set(),
        'cves': set()
    }

    for item in data['threat_intelligence']:
        # Extract URLs
        if item.get('url'):
            iocs['urls'].add(item['url'])

        # Extract indicators
        if item.get('indicators'):
            for indicator in item['indicators']:
                if indicator:
                    iocs['domains'].add(indicator)

        # Extract CVEs
        if item.get('cve_ids'):
            iocs['cves'].update(item['cve_ids'])

    print(f"\n[+] Extracted IOCs for SIEM:")
    print(f"  • URLs: {len(iocs['urls'])}")
    print(f"  • Domains/IPs: {len(iocs['domains'])}")
    print(f"  • CVEs: {len(iocs['cves'])}")

    # Write IOC lists for import
    with open('ioc_urls.txt', 'w') as f:
        for url in sorted(iocs['urls']):
            f.write(f"{url}\n")

    with open('ioc_cves.txt', 'w') as f:
        for cve in sorted(iocs['cves']):
            f.write(f"{cve}\n")

    print("\n[+] IOC lists exported:")
    print("  • ioc_urls.txt")
    print("  • ioc_cves.txt")
    print("  • siem_feed.json")

    print("\n✅ SIEM integration prep complete!")


def example_threat_analytics():
    """Example 7: Perform basic threat analytics"""
    print("\n" + "="*80)
    print("EXAMPLE 7: Threat Analytics and Statistics")
    print("="*80)

    aggregator = ThreatIntelAggregator()
    results = aggregator.scrape_all(items_per_source=25)
    aggregator.deduplicate()

    print("\n[*] Analyzing threat intelligence data...\n")

    # Analyze by source
    source_stats = {}
    for item in aggregator.results:
        source_stats[item.source] = source_stats.get(item.source, 0) + 1

    print("📊 Items by Source:")
    for source, count in sorted(source_stats.items(), key=lambda x: x[1], reverse=True):
        bar = '█' * (count // 2)
        print(f"  {source:25s} {count:3d} {bar}")

    # Analyze by category
    category_stats = {}
    for item in aggregator.results:
        category_stats[item.category] = category_stats.get(item.category, 0) + 1

    print("\n📊 Items by Category:")
    for category, count in sorted(category_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {category:30s} {count:3d}")

    # CVE statistics
    total_cves = sum(len(item.cve_ids) for item in aggregator.results)
    items_with_cves = len([item for item in aggregator.results if item.cve_ids])

    print(f"\n📊 CVE Statistics:")
    print(f"  Items with CVEs: {items_with_cves}")
    print(f"  Total CVE IDs: {total_cves}")

    # Most common CVE prefixes (year-based)
    cve_years = {}
    for item in aggregator.results:
        for cve in item.cve_ids:
            year = cve.split('-')[1] if '-' in cve else 'Unknown'
            cve_years[year] = cve_years.get(year, 0) + 1

    print(f"\n📊 CVEs by Year:")
    for year, count in sorted(cve_years.items(), reverse=True)[:5]:
        print(f"  {year}: {count}")

    print("\n✅ Threat analytics complete!")


def main():
    """Run all examples"""
    print("\n" + "="*80)
    print("THREAT INTELLIGENCE AGGREGATOR - USAGE EXAMPLES")
    print("="*80)
    print("\nSelect an example to run:")
    print("  1. Basic Usage")
    print("  2. CVE Hunting")
    print("  3. Keyword Filtering")
    print("  4. Daily Briefing")
    print("  5. Source-Specific Collection")
    print("  6. SIEM Integration")
    print("  7. Threat Analytics")
    print("  8. Run All Examples")

    try:
        choice = input("\nEnter choice (1-8): ").strip()

        examples = {
            '1': example_basic_usage,
            '2': example_cve_hunting,
            '3': example_keyword_filtering,
            '4': example_daily_briefing,
            '5': example_source_specific,
            '6': example_siem_integration,
            '7': example_threat_analytics
        }

        if choice == '8':
            # Run all examples
            for func in examples.values():
                func()
                print("\n" + "-"*80)
        elif choice in examples:
            examples[choice]()
        else:
            print("Invalid choice. Running basic usage example...")
            example_basic_usage()

    except KeyboardInterrupt:
        print("\n\nExecution cancelled by user.")
    except Exception as e:
        print(f"\nError: {e}")

    print("\n" + "="*80)
    print("Examples complete! Check the generated files for results.")
    print("="*80)


if __name__ == '__main__':
    main()
