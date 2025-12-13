---

## 🌐 Connection Errors
**Symptoms:** Script hangs or fails to retrieve data.  
**Fixes:**
```python
# Increase timeout for slow connections
aggregator = ThreatIntelAggregator(timeout=60)
```
- Verify internet connection.  
- Check if feed URLs are still active.  

---

## ⏱️ Rate Limiting
**Symptoms:** Feeds return fewer items or block requests.  
**Fixes:**
```python
import time
time.sleep(5)  # Wait 5 seconds between operations
```
- Respect provider rate limits.  
- Use API keys for high‑volume sources when available.  

---

## 🔒 SSL Errors
**Symptoms:** SSL certificate warnings or failed connections.  
**Fixes:**
- The tool handles common SSL issues gracefully.  
- If persistent, verify system SSL libraries are up to date.  

---

## 📭 Empty Results
**Symptoms:** No items collected from a source.  
**Fixes:**
- Confirm internet connectivity.  
- Check if the feed is still active.  
- Some feeds require API keys for full access.  
- Retry after a short delay to avoid temporary outages.  

---

## 💾 Memory Usage
**Symptoms:** High memory consumption during large scrapes.  
**Fixes:**
- Reduce `items_per_source` parameter.  
- Export results incrementally instead of in one large batch.  

---

## 🛡️ Security Considerations
- Tool only reads public threat intelligence feeds.  
- No authentication required for public sources.  
- Use for authorized defensive operations only.  
- Store reports securely — they may contain sensitive indicators.  

---

## 📌 Best Practices
- Run scheduled jobs during off‑peak hours.  
- Validate intelligence before acting on it.  
- Keep Python updated (3.7+ recommended).  
- Respect feed providers’ usage policies.  

---

This `/docs/TROUBLESHOOTING.md` file shows recruiters that you approach problems **systematically and ethically**, while giving peers practical fixes.

---
