from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any, Iterable, List, Optional, Tuple
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from matching import normalize_address, normalize_company_name, normalize_domain


USER_AGENT = "PrefixWorkbench/1.0 (+https://local.app)"
SEARCH_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"


def _url_matches_accepted_domains(url: str, accepted_domains: Iterable[str]) -> bool:
    accepted = [normalize_domain(domain) for domain in accepted_domains if normalize_domain(domain)]
    if not accepted:
        return True
    hostname = normalize_domain(urlparse(url).netloc)
    if not hostname:
        return False
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in accepted)


class BraveSearchClient:
    def __init__(self, api_key: str = "", cache_dir: str | Path = "cache") -> None:
        self.api_key = api_key.strip()
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / "search_cache.json"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def engine_label(self) -> str:
        return "Brave Search API" if self.is_configured() else "Disabled"

    def validate_key(self) -> Tuple[bool, str]:
        if not self.is_configured():
            return False, "No Brave Search API key is configured."
        _, error = self._search("assurant office locations")
        if error:
            return False, error
        return True, "Brave Search API key is working."

    def _load_cache(self) -> dict[str, Any]:
        if not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_cache(self, cache_data: dict[str, Any]) -> None:
        self.cache_path.write_text(json.dumps(cache_data, indent=2, ensure_ascii=True), encoding="utf-8")

    def cache_stats(self) -> dict[str, Any]:
        cache = self._load_cache()
        return {
            "entries": len(cache),
            "path": str(self.cache_path),
        }

    def clear_cache(self) -> None:
        if self.cache_path.exists():
            self.cache_path.unlink()

    def _cache_get(self, key: str) -> Optional[dict[str, Any]]:
        cache = self._load_cache()
        value = cache.get(key)
        return value if isinstance(value, dict) else None

    def _cache_put(self, key: str, value: dict[str, Any]) -> None:
        cache = self._load_cache()
        cache[key] = value
        self._save_cache(cache)

    def _search(self, query: str) -> Tuple[List[dict[str, Any]], str]:
        cache_key = f"search::{query}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return list(cached.get("results", [])), str(cached.get("error", ""))
        if not self.is_configured():
            return [], "Brave Search API key is not configured."
        params = urlencode({"q": query, "count": 10})
        request = Request(
            f"{SEARCH_ENDPOINT}?{params}",
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "X-Subscription-Token": self.api_key,
            },
        )
        try:
            with urlopen(request, timeout=18) as response:
                payload = json.loads(response.read().decode("utf-8", errors="ignore"))
        except Exception as exc:
            self._cache_put(cache_key, {"results": [], "error": str(exc)})
            return [], str(exc)
        results = payload.get("web", {}).get("results", []) if isinstance(payload, dict) else []
        normalized_results = []
        for item in results:
            if not isinstance(item, dict):
                continue
            normalized_results.append(
                {
                    "title": str(item.get("title", "")),
                    "description": str(item.get("description", "")),
                    "url": str(item.get("url", "")),
                }
            )
        self._cache_put(cache_key, {"results": normalized_results, "error": ""})
        return normalized_results, ""

    def _fetch_page(self, url: str) -> Tuple[str, str]:
        cache_key = f"page::{url}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return str(cached.get("normalized_text", "")), str(cached.get("error", ""))
        request = Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urlopen(request, timeout=15) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                body = response.read().decode(charset, errors="ignore")
        except Exception as exc:
            self._cache_put(cache_key, {"normalized_text": "", "error": str(exc)})
            return "", str(exc)
        body = re.sub(r"(?is)<script.*?>.*?</script>", " ", body)
        body = re.sub(r"(?is)<style.*?>.*?</style>", " ", body)
        body = re.sub(r"(?s)<[^>]+>", " ", body)
        body = html.unescape(body)
        body = re.sub(r"\s+", " ", body).strip()
        normalized = normalize_address(body)
        self._cache_put(cache_key, {"normalized_text": normalized, "error": ""})
        return normalized, ""

    def _location_tokens(self, address: str) -> Tuple[str, str]:
        normalized = normalize_address(address)
        tokens = normalized.split()
        if not tokens:
            return "", ""
        country = tokens[-1]
        state = ""
        search_tokens = tokens[:-1] if country == "us" else tokens
        for token in reversed(search_tokens):
            if len(token) == 2 and token.isalpha():
                state = token
                break
        return state, country

    def _city_tokens(self, address: str) -> str:
        normalized = normalize_address(address)
        tokens = normalized.split()
        if not tokens:
            return ""
        state_index = -1
        for index in range(len(tokens) - 1, -1, -1):
            token = tokens[index]
            if len(token) == 2 and token.isalpha():
                state_index = index
                break
        if state_index <= 0:
            return ""
        city_tokens: List[str] = []
        for index in range(state_index - 1, -1, -1):
            token = tokens[index]
            if token.isdigit():
                break
            city_tokens.append(token)
            if len(city_tokens) == 2:
                break
        return " ".join(reversed(city_tokens)).strip()

    def _snippet_match_mode(
        self,
        snippet_text: str,
        normalized_address: str,
        company_name: str,
        city: str,
        state: str,
        country: str,
    ) -> str:
        normalized_company = normalize_company_name(company_name)
        if self._addresses_equivalent(snippet_text, normalized_address):
            return "exact_address"
        location_hit = False
        if country == "us":
            if state and f" {state} " in f" {snippet_text} ":
                location_hit = True
        elif country and f" {country} " in f" {snippet_text} ":
            location_hit = True
        if location_hit and city and f" {city} " not in f" {snippet_text} ":
            location_hit = False
        if location_hit and normalized_company:
            return "state_country"
        return ""

    def _addresses_equivalent(self, haystack_text: str, normalized_address: str) -> bool:
        if normalized_address and normalized_address in haystack_text:
            return True
        if normalized_address.endswith(" us"):
            short_address = normalized_address[:-3].strip()
            if short_address and short_address in haystack_text:
                return True
        return False

    def find_address_evidence(
        self,
        company_name: str,
        address: str,
        accepted_domains: Iterable[str],
    ) -> Tuple[Optional[str], str, str, str]:
        accepted_domain_list = [normalize_domain(domain) for domain in accepted_domains if normalize_domain(domain)]
        snippet_trust_enabled = bool(accepted_domain_list)
        normalized_address = normalize_address(address)
        if not normalized_address:
            return None, "", "No usable address was available for live search.", ""
        normalized_company = normalize_company_name(company_name)
        state, country = self._location_tokens(address)
        city = self._city_tokens(address)
        queries = []
        if company_name.strip():
            queries.append(f"\"{company_name}\" \"{address}\"")
            if city and state:
                queries.append(f"\"{company_name}\" \"{city}\" \"{state}\"")
        queries.append(f"\"{address}\"")
        seen_urls = set()
        last_error = ""
        debug_lines: List[str] = []
        for query in queries:
            results, error = self._search(query)
            if error:
                last_error = error
                debug_lines.append(f"query={query} error={error}")
                continue
            debug_lines.append(f"query={query} results={len(results)}")
            for item in results:
                url = str(item.get("url", "")).strip()
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                snippet_text = normalize_address(f"{item.get('title', '')} {item.get('description', '')}")
                debug_lines.append(f"url={url} snippet={snippet_text[:220]}")
                if not _url_matches_accepted_domains(url, accepted_domain_list):
                    debug_lines.append(f"skipped_non_accepted_domain={url}")
                    continue
                if snippet_trust_enabled:
                    snippet_mode = self._snippet_match_mode(
                        snippet_text,
                        normalized_address,
                        company_name,
                        city,
                        state,
                        country,
                    )
                    if snippet_mode:
                        debug_lines.append(f"snippet_match={snippet_mode} url={url}")
                        return url, snippet_mode, "", "\n".join(debug_lines)
                normalized_page, fetch_error = self._fetch_page(url)
                if fetch_error:
                    snippet_mode = self._snippet_match_mode(
                        snippet_text,
                        normalized_address,
                        company_name,
                        city,
                        state,
                        country,
                    )
                    if snippet_mode:
                        debug_lines.append(f"snippet_match_after_fetch_error={snippet_mode} url={url}")
                        return url, snippet_mode, "", "\n".join(debug_lines)
                    last_error = fetch_error
                    debug_lines.append(f"fetch_error={url} error={fetch_error}")
                    continue
                if self._addresses_equivalent(normalized_page, normalized_address):
                    debug_lines.append(f"page_match=exact_address url={url}")
                    return url, "exact_address", "", "\n".join(debug_lines)
                location_hit = False
                if country == "us":
                    if state and f" {state} " in f" {normalized_page} ":
                        location_hit = True
                elif country and f" {country} " in f" {normalized_page} ":
                    location_hit = True
                if location_hit and city and f" {city} " not in f" {normalized_page} ":
                    location_hit = False
                if location_hit and normalized_company:
                    debug_lines.append(f"page_match=state_country url={url}")
                    return url, "state_country", "", "\n".join(debug_lines)
                snippet_mode = self._snippet_match_mode(
                    snippet_text,
                    normalized_address,
                    company_name,
                    city,
                    state,
                    country,
                )
                if snippet_mode:
                    debug_lines.append(f"snippet_match_post_page={snippet_mode} url={url}")
                    return url, snippet_mode, "", "\n".join(debug_lines)
        return None, "", last_error or "Live search did not find address or location evidence on the searched pages.", "\n".join(debug_lines)
