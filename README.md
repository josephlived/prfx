# Prefix Workbench

A Streamlit app for validating whether an IP prefix's registered owner matches an accepted parent company or one of its subsidiaries. It layers cheap deterministic checks (name / alias / known-address match, data-center list, accepted-domain crawl) before escalating to a Brave Search API lookup, and finally to WHOIS/RDAP as a fallback.

## Two Modes

### Standard Validator
Takes a spreadsheet or pasted table whose first four columns map to:

| Col | Meaning |
|-----|---------|
| A | Analyst decision (`TRUE` / `FALSE` — optional, used only to flag mismatches) |
| B | Prefix / IP (used for the WHOIS fallback) |
| C | Raw company name (often the RIR OrgName, possibly with noise) |
| D | Raw address |

For each row the engine runs this pipeline, stopping at the first hit:

1. **Exact known-address match** against the pasted address book (`Company \| Address \| URL`).
2. **Private address** + exact company name → TRUE.
3. **Known data-center address** (hard-coded list in `validator.py`) + exact company name → TRUE.
4. **Coarse location match** (same state/country) against address-book entries for the matched company.
5. **Accepted-domain crawl** — fetches `/`, `/contact`, `/locations`, etc. on each accepted domain and checks for the address (Playwright if installed, HTTP fallback otherwise).
6. **Live search** via the Brave Search API, restricted to accepted domains. Uses snippet match when an accepted domain is configured, else fetches the page and looks for the normalized address.
7. **WHOIS / RDAP** (only when the company name or address is blank / unusable) — compares OrgName, NetName, and associated domains to the accepted catalog.

### WHOIS-Only Prefix Validator
Paste prefixes/IPs, one per line. Runs RDAP lookups and compares OrgName / NetName / linked domains against the accepted catalog. TRUE only for exact or alias-matched OrgName / NetName; very-close matches are emitted as **To Review**.

## Output Columns

| Col | Meaning |
|-----|---------|
| E | Verdict — `TRUE` / `FALSE` |
| F | Reason with (optional) source URL |
| G | Matched subsidiary (canonical name) |
| H | Confidence — `High` / `Medium` / `To Review` |

The Excel export adds an **Audit Trail** sheet with the 10-step per-row audit and the live-search debug log.

## Inputs (Sidebar)

| Field | Format |
|-------|--------|
| Parent Company | Free text |
| Accepted Subsidiaries | One per line, or upload `.txt` / `.csv` / `.xlsx` (first column) |
| Alias / DBA Overrides | `Alias => Canonical Name` (also accepts `->`, `|`, `=`) |
| Accepted Domains | One per line, optionally `domain.com | Company Name` |
| Brave Search API Key | Optional; enables step 6. Can also be set via `BRAVE_SEARCH_API_KEY`. |
| Known Address Evidence | `Company | Address | URL` per line (URL optional) |

## Run

```bash
pip install -r requirements.txt
# Optional: enables JS-rendered domain crawl. Without it, HTTP fallback is used.
playwright install chromium
streamlit run app.py
```

`ipwhois` is an optional runtime dependency; if it is missing, WHOIS-dependent paths stay FALSE but all other checks still work.

## File Map

| File | Role |
|------|------|
| `app.py` | Streamlit UI, file parsing, Excel export |
| `validator.py` | Pipeline orchestration (`validate_standard_rows`, `validate_whois_only_prefixes`), known data-center list |
| `matching.py` | Company/address normalization, alias parsing, fuzzy scoring, coarse location match |
| `domain_crawler.py` | Accepted-domain crawl (Playwright preferred, HTTP fallback) |
| `live_search.py` | Brave Search API client, snippet/page address matching, on-disk cache |
| `whois_lookup.py` | RDAP via `ipwhois`, OrgName / NetName / domain extraction, cache |
| `models.py` | Dataclasses: `CompanyCatalog`, `InputRow`, `ValidationResult`, `WhoisRecord`, `WhoisOnlyResult`, `AddressEvidence` |
| `requirements.txt` | Python dependencies |

## Caches

WHOIS, domain-crawl, and live-search results are cached on disk under `cache/`. Each cache has its own **Clear** button in the sidebar.

## Notes

- Normalization lower-cases, strips punctuation, and expands common address abbreviations (`st`→`street`, `se`→`southeast`, `cir`→`circle`, `united states`→`us`, etc.).
- Company matching accepts exact matches, alias-table hits, acronym matches, suffix-stripped matches, and a rapidfuzz score ≥ 97.
- The engine never upgrades a FALSE to TRUE on weak evidence: a domain or live-search address hit without an accepted company-name match comes back as **To Review** with `Verdict: FALSE`.
