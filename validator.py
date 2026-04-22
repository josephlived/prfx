from __future__ import annotations

from typing import Callable, Iterable, List, Optional

import pandas as pd

from matching import (
    classify_company_match,
    clean_company_name,
    coarse_location_match,
    find_address_match,
    is_private_address,
    is_usable_address,
    normalize_address,
    normalize_company_name,
    parse_address_evidence,
    parse_alias_lines,
    parse_company_lines,
    parse_domain_lines,
)
from models import CompanyCatalog, InputRow, ValidationResult, WhoisOnlyResult
from domain_crawler import DomainEvidenceClient
from live_search import BraveSearchClient
from whois_lookup import WhoisLookupClient


KNOWN_DATA_CENTER_ADDRESSES = {
    normalize_address(value)
    for value in [
        "268 Bush St San Francisco, CA 94104 US",
        "2701 W 15th St PMB 236 Plano, TX 75075 US",
        "5000 Walzem Rd. San Antonio, TX 78218 US",
        "34 St Martin Drive Marlborough, MA 01752 US",
        "1649 Frankford Rd. West, Carrollton, TX, 75007, United States",
        "21711 Filigree Court Ashburn, VA 20147 US",
        "1950 N Stemmons Freeway, Dallas, TX, 75207, United States",
        "3030 Corvin Dr Santa Clara, CA 95051 US",
        "401 N Broad St Philadelphia PA 19106 US",
        "777 Central Boulevard, Carlstadt, NJ, USA",
        "350 East Cermak Chicago, IL",
        "20 Black Fan Road, Welwyn Garden City, Hertfordshire, UK",
        "11 Great Oaks Blvd San Jose CA 95119 US",
        "3800 N Central Ave Phoenix, Arizona",
        "15 Shattuck Road Andover, MA 01810 US",
        "21110 Ridgetop Cir Sterling, VA",
        "2323 Bryan Floor 26 Dallas, TX",
        "Toyosu 6-2-15, Koto-ku Tokyo, 135-0061 JP",
        "DC 2 Nodia Net Magic Data Centre H 223 Sector 63 Gautam Budh Nagar Nodia 201301 Noida Uttar Pradesh",
        "1/18 STT Global DataCentres India Private Limited TCL VSB Ultadanga CIT Scheme VII M Kolkata 700054 Kolkata West Bengal",
        "6431 Longhorn Drive Irving TX 75063 US",
        "1033 Jefferson St NW Atlanta GA 30318 US",
        "350 East Cermak Chicago IL 60610 US",
        "56 Marietta St NW Atlanta GA 30303 US",
        "11650 Great Oaks Way Alpharetta GA 30022-2408 US",
        "12098 Sunrise Valley Dr Reston VA US",
        "26A Ayer Rajah Crescent, Singapore 139963",
        "2805 Diehl Rd Aurora IL 60502 US",
        "9333 Grand Ave Franklin Park IL 60131 US",
        "6327 NE Evergreen Pkwy - Bldg C, Hillsboro, OR",
        "14100 Park Vista Boulevard, Fort Worth, TX",
        "2681 Kelvin Ave Irvine CA",
        "6000 Technology Blvd Sandston VA",
        "One Federal Street Boston MA",
        "8025 I.H. 35 North Austin TX",
        "800 N Central Ave Phoenix, Arizona",
        "50 East Cermak Chicago, IL",
        "950 N Stemmons Freeway, Dallas, TX, 75207, United States",
        "711 N Edgewood Ave, Wood Dale, IL, United States",
        "1905 Lunt Avenue, Elk Grove Village, IL, USA",
        "2-2-43, Higashi-Shinagawa, 140-0002 (T1 Building), Tokyo, Japan",
    ]
}


def build_catalog(
    parent_company: str,
    subsidiaries_text: str,
    aliases_text: str,
    addresses_text: str,
    accepted_domains_text: str,
) -> CompanyCatalog:
    accepted_entities = []
    if parent_company.strip():
        accepted_entities.append(parent_company.strip())
    accepted_entities.extend(parse_company_lines(subsidiaries_text))
    deduped = []
    seen = set()
    for entity in accepted_entities:
        key = normalize_company_name(entity)
        if key and key not in seen:
            seen.add(key)
            deduped.append(entity)
    return CompanyCatalog(
        parent_company=parent_company.strip(),
        accepted_entities=deduped,
        aliases=parse_alias_lines(aliases_text),
        known_addresses=parse_address_evidence(addresses_text),
        accepted_domains=parse_domain_lines(accepted_domains_text),
    )


def dataframe_to_rows(df: pd.DataFrame) -> List[InputRow]:
    working = df.copy()
    working = working.iloc[:, :4]
    while working.shape[1] < 4:
        working[working.shape[1]] = ""
    working.columns = ["A", "B", "C", "D"]
    rows: List[InputRow] = []
    for index, row in enumerate(working.itertuples(index=False), start=1):
        rows.append(
            InputRow(
                row_number=index,
                analyst_decision=str(row.A).strip().upper(),
                prefix=str(row.B).strip(),
                raw_company_name=str(row.C).strip() if pd.notna(row.C) else "",
                raw_address=str(row.D).strip() if pd.notna(row.D) else "",
            )
        )
    return rows


def _format_reason(base: str, source_url: str = "") -> str:
    if source_url:
        return f"{base} Source: {source_url}"
    return base


def _match_from_candidates(catalog: CompanyCatalog, values: Iterable[str]) -> tuple[str, str, int]:
    best_name = ""
    best_kind = "none"
    best_score = 0
    for value in values:
        matched, kind, score = classify_company_match(value, catalog)
        if score > best_score:
            best_name, best_kind, best_score = matched, kind, score
        if kind == "exact" and score == 100:
            break
    return best_name, best_kind, best_score


def _run_whois_match(prefix: str, catalog: CompanyCatalog, whois_client: WhoisLookupClient) -> tuple[str, str, int, str, str, str, str, str]:
    if not prefix.strip():
        return "", "none", 0, "", "", "", "", "No prefix was available for WHOIS."
    record = whois_client.lookup(prefix)
    org_display = "; ".join(record.org_names)
    net_display = record.net_name
    domain_display = ", ".join(record.domains)
    registry_display = record.registry
    if record.error:
        return "", "none", 0, org_display, net_display, domain_display, registry_display, f"WHOIS lookup failed: {record.error}"
    matched_name, kind, score = _match_from_candidates(catalog, [*record.org_names, record.net_name])
    if kind == "exact":
        match_type = "whois_orgname_exact" if matched_name and any(
            normalize_company_name(name) == normalize_company_name(matched_name) or
            normalize_company_name(name) in catalog.aliases
            for name in record.org_names
        ) else "whois_netname_exact"
        return matched_name, match_type, score, org_display, net_display, domain_display, registry_display, ""
    matching_domains = sorted(set(record.domains).intersection(catalog.accepted_domains))
    if matching_domains:
        return "", "whois_domain_exact", 100, org_display, net_display, ", ".join(matching_domains), registry_display, ""
    if score >= 97 and matched_name:
        return matched_name, "whois_close_not_exact", score, org_display, net_display, domain_display, registry_display, ""
    return "", "no_match", score, org_display, net_display, domain_display, registry_display, ""


def validate_standard_rows(
    rows: List[InputRow],
    catalog: CompanyCatalog,
    whois_client: WhoisLookupClient,
    domain_client: Optional[DomainEvidenceClient] = None,
    search_client: Optional[BraveSearchClient] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> List[ValidationResult]:
    results: List[ValidationResult] = []
    total_rows = len(rows)
    for index, row in enumerate(rows, start=1):
        if progress_callback is not None:
            progress_callback(index - 1, total_rows, f"Preparing row {row.row_number}")
        cleaned_company = clean_company_name(row.raw_company_name)
        cleaned_address = row.raw_address.strip()
        normalized_address = normalize_address(cleaned_address)
        matched_name, name_kind, name_score = classify_company_match(cleaned_company, catalog)
        address_match = find_address_match(cleaned_address, catalog.known_addresses)
        company_specific_entries = [
            entry for entry in catalog.known_addresses if entry.canonical_name == matched_name
        ]
        location_match = coarse_location_match(cleaned_address, company_specific_entries) if company_specific_entries else None

        search_summary = "Checked accepted company list, alias table, known address book, accepted-domain crawl, private/data-center rules, and WHOIS fallback where allowed."
        search_returned = "No qualifying evidence found."
        matched_subsidiary = ""
        column_e = "FALSE"
        column_f = "FALSE — No connection found with the company or any of its subsidiaries."
        column_g = ""
        column_h = "Medium"
        match_type = "no_match"
        match_score = name_score
        source_url = ""
        review_reason = ""
        whois_orgname = ""
        whois_netname = ""
        whois_domains = ""
        whois_registry = ""
        domain_diagnostics: List[str] = []
        live_search_debug = ""

        if address_match:
            search_returned = f"Exact known address matched {address_match.canonical_name}."
            matched_subsidiary = address_match.canonical_name
            column_g = matched_subsidiary
            source_url = address_match.source_url
            if name_kind == "exact" and matched_name == matched_subsidiary:
                column_e = "TRUE"
                column_f = _format_reason("TRUE — Exact company name + exact address match.", source_url)
                column_h = "High"
                match_type = "direct_exact_name_exact_address"
                match_score = 100
            elif name_kind == "inexact" and matched_name == matched_subsidiary:
                column_e = "TRUE"
                column_f = _format_reason("TRUE — Inexact name + exact address match.", source_url)
                column_h = "Medium"
                match_type = "direct_inexact_name_exact_address"
                match_score = name_score
            else:
                column_e = "TRUE"
                column_f = _format_reason(
                    f"TRUE — Address matched accepted subsidiary {matched_subsidiary}.",
                    source_url,
                )
                column_h = "Medium"
                match_type = "cross_subsidiary_address"
                match_score = max(name_score, 100 if matched_subsidiary else 0)
        elif is_private_address(cleaned_address):
            search_returned = "Address was classified as Private Address."
            if name_kind == "exact":
                matched_subsidiary = matched_name
                column_e = "TRUE"
                column_f = "TRUE — Exact company name + private address."
                column_g = matched_name
                column_h = "High"
                match_type = "private_address_exact_name"
                match_score = 100
            elif matched_name:
                matched_subsidiary = matched_name
                column_e = "FALSE"
                column_f = "FALSE — Inexact name + private address."
                column_g = matched_name
                column_h = "Medium"
                match_type = "private_address_inexact_name"
                match_score = name_score
        elif normalized_address in KNOWN_DATA_CENTER_ADDRESSES and name_kind == "exact":
            search_returned = "Address matched the known data-center list."
            matched_subsidiary = matched_name
            column_e = "TRUE"
            column_f = "TRUE — Exact company name + known data center address."
            column_g = matched_name
            column_h = "High"
            match_type = "datacenter_exact_name"
            match_score = 100
        elif is_usable_address(cleaned_address) and location_match:
            search_returned = f"Location-level evidence matched {location_match.canonical_name}."
            matched_subsidiary = location_match.canonical_name
            column_g = matched_subsidiary
            source_url = location_match.source_url
            if name_kind == "exact" and matched_name == matched_subsidiary:
                column_e = "TRUE"
                column_f = _format_reason("TRUE — Exact company name + state / country match.", source_url)
                column_h = "Medium"
                match_type = "exact_name_state_country_only"
                match_score = 100
            elif matched_name:
                column_e = "FALSE"
                column_f = "FALSE — Inexact name + state / country match only."
                column_h = "Medium"
                match_type = "inexact_name_state_country_only"
                match_score = name_score
        elif is_usable_address(cleaned_address) and domain_client is not None and catalog.accepted_domains:
            domain_diagnostics = domain_client.diagnose_domains(catalog.accepted_domains[:5])
            crawl_url = domain_client.find_address_evidence(catalog.accepted_domains, cleaned_address)
            if crawl_url:
                search_returned = f"Exact address was found on accepted domain evidence page {crawl_url}."
                source_url = crawl_url
                if name_kind == "exact" and matched_name:
                    matched_subsidiary = matched_name
                    column_e = "TRUE"
                    column_f = _format_reason("TRUE — Exact company name + exact address match.", source_url)
                    column_g = matched_name
                    column_h = "High"
                    match_type = "domain_exact_name_exact_address"
                    match_score = 100
                elif name_kind == "inexact" and matched_name:
                    matched_subsidiary = matched_name
                    column_e = "TRUE"
                    column_f = _format_reason("TRUE — Inexact name + exact address match.", source_url)
                    column_g = matched_name
                    column_h = "Medium"
                    match_type = "domain_inexact_name_exact_address"
                    match_score = name_score
                else:
                    column_e = "FALSE"
                    column_f = _format_reason(
                        "To Review — Exact address was found on an accepted domain, but the company name did not match an accepted entity. Verdict: FALSE.",
                        source_url,
                    )
                    column_h = "To Review"
                    match_type = "domain_address_name_unmatched"
                    review_reason = "Accepted-domain address evidence exists without accepted company-name match."
                    match_score = 100
            else:
                if domain_diagnostics:
                    search_returned = f"Accepted-domain crawl could not confirm the address. Diagnostic: {domain_diagnostics[0]}"
                if search_client is not None and search_client.is_configured() and cleaned_company and is_usable_address(cleaned_address):
                    live_search_url, live_search_mode, live_search_error, live_search_debug = search_client.find_address_evidence(
                        cleaned_company or matched_name,
                        cleaned_address,
                        catalog.accepted_domains,
                    )
                    if live_search_url:
                        search_returned = f"Live search found exact address evidence at {live_search_url}."
                        source_url = live_search_url
                        if live_search_mode == "exact_address":
                            if name_kind == "exact" and matched_name:
                                matched_subsidiary = matched_name
                                column_e = "TRUE"
                                column_f = _format_reason("TRUE — Exact company name + exact address match.", source_url)
                                column_g = matched_name
                                column_h = "High"
                                match_type = "search_exact_name_exact_address"
                                match_score = 100
                            elif name_kind == "inexact" and matched_name:
                                matched_subsidiary = matched_name
                                column_e = "TRUE"
                                column_f = _format_reason("TRUE — Inexact name + exact address match.", source_url)
                                column_g = matched_name
                                column_h = "Medium"
                                match_type = "search_inexact_name_exact_address"
                                match_score = name_score
                            else:
                                column_e = "FALSE"
                                column_f = _format_reason(
                                    "To Review — Live search found exact address evidence, but the company name did not match an accepted entity. Verdict: FALSE.",
                                    source_url,
                                )
                                column_h = "To Review"
                                match_type = "search_address_name_unmatched"
                                review_reason = "Live-search address evidence exists without accepted company-name match."
                                match_score = 100
                        elif live_search_mode == "state_country" and name_kind == "exact" and matched_name:
                            matched_subsidiary = matched_name
                            column_e = "TRUE"
                            column_f = _format_reason("TRUE — Exact company name + state / country match.", source_url)
                            column_g = matched_name
                            column_h = "Medium"
                            match_type = "search_exact_name_state_country"
                            match_score = 100
                    elif live_search_error:
                        search_returned = f"Live search could not confirm the address. Diagnostic: {live_search_error}"
        elif cleaned_company and is_usable_address(cleaned_address) and search_client is not None and search_client.is_configured():
            live_search_url, live_search_mode, live_search_error, live_search_debug = search_client.find_address_evidence(
                cleaned_company or matched_name,
                cleaned_address,
                catalog.accepted_domains,
            )
            if live_search_url:
                search_returned = f"Live search found exact address evidence at {live_search_url}."
                source_url = live_search_url
                if live_search_mode == "exact_address":
                    if name_kind == "exact" and matched_name:
                        matched_subsidiary = matched_name
                        column_e = "TRUE"
                        column_f = _format_reason("TRUE — Exact company name + exact address match.", source_url)
                        column_g = matched_name
                        column_h = "High"
                        match_type = "search_exact_name_exact_address"
                        match_score = 100
                    elif name_kind == "inexact" and matched_name:
                        matched_subsidiary = matched_name
                        column_e = "TRUE"
                        column_f = _format_reason("TRUE — Inexact name + exact address match.", source_url)
                        column_g = matched_name
                        column_h = "Medium"
                        match_type = "search_inexact_name_exact_address"
                        match_score = name_score
                    else:
                        column_e = "FALSE"
                        column_f = _format_reason(
                            "To Review — Live search found exact address evidence, but the company name did not match an accepted entity. Verdict: FALSE.",
                            source_url,
                        )
                        column_h = "To Review"
                        match_type = "search_address_name_unmatched"
                        review_reason = "Live-search address evidence exists without accepted company-name match."
                        match_score = 100
                elif live_search_mode == "state_country" and name_kind == "exact" and matched_name:
                    matched_subsidiary = matched_name
                    column_e = "TRUE"
                    column_f = _format_reason("TRUE — Exact company name + state / country match.", source_url)
                    column_g = matched_name
                    column_h = "Medium"
                    match_type = "search_exact_name_state_country"
                    match_score = 100
            elif live_search_error:
                search_returned = f"Live search could not confirm the address. Diagnostic: {live_search_error}"
        elif not is_usable_address(cleaned_address) or not cleaned_company:
            whois_name, whois_type, whois_score, whois_orgname, whois_netname, whois_domains, whois_registry, whois_error = _run_whois_match(
                row.prefix,
                catalog,
                whois_client,
            )
            search_summary = "WHOIS/RDAP fallback using OrgName and NetName only."
            if whois_error:
                search_returned = whois_error
                column_e = "FALSE"
                column_f = "FALSE — No connection found with the company or any of its subsidiaries."
                match_type = "no_match"
            elif whois_type in {"whois_orgname_exact", "whois_netname_exact"}:
                matched_subsidiary = whois_name
                column_e = "TRUE"
                column_g = whois_name
                column_h = "Medium"
                column_f = (
                    "TRUE — WHOIS OrgName matched accepted subsidiary."
                    if whois_type == "whois_orgname_exact"
                    else "TRUE — WHOIS NetName matched accepted subsidiary."
                )
                match_type = whois_type
                match_score = whois_score
                search_returned = f"WHOIS matched accepted subsidiary {whois_name}."
            elif whois_type == "whois_close_not_exact":
                matched_subsidiary = whois_name
                column_e = "FALSE"
                column_f = "To Review — WHOIS entity name was very close to accepted subsidiary but not exact. Verdict: FALSE."
                column_g = whois_name
                column_h = "To Review"
                match_type = whois_type
                match_score = whois_score
                review_reason = "WHOIS very close but not exact."
                search_returned = f"WHOIS was very close to accepted subsidiary {whois_name}, but not exact."
            elif whois_type == "whois_domain_exact":
                column_e = "FALSE"
                column_f = "To Review — WHOIS domain matched an accepted domain, but the entity name was not exact. Verdict: FALSE."
                column_h = "To Review"
                match_type = whois_type
                match_score = whois_score
                review_reason = "WHOIS domain matched accepted domain without exact entity name."
                search_returned = f"WHOIS exposed accepted domain(s): {whois_domains}."
            else:
                search_returned = "WHOIS resolved the prefix, but OrgName and NetName did not match an accepted company."
        elif not is_usable_address(cleaned_address):
            search_returned = "Address was blank or not usable."

        mismatch = row.analyst_decision in {"TRUE", "FALSE"} and row.analyst_decision != column_e
        audit_steps = [
            f"1. Row number: {row.row_number}",
            f"2. Company name extracted: {cleaned_company or '[blank/unusable]'}",
            f"3. Address found in the row: {cleaned_address or '[blank]'}",
            f"4. What the engine searched: {search_summary}",
            f"5. What the search returned: {search_returned}{f' Registry: {whois_registry}.' if whois_registry else ''}",
            f"6. Which subsidiary matched: {matched_subsidiary or 'No accepted subsidiary matched.'}",
            f"7. Verdict: {column_e}",
            f"8. Column F output: {column_f}",
            f"9. Column G output: {column_g or '[blank]'}",
            f"10. Column H output: {column_h}",
        ]
        if live_search_debug:
            audit_steps.append(f"Live Search Debug:\n{live_search_debug}")
        results.append(
            ValidationResult(
                row_number=row.row_number,
                column_a=row.analyst_decision,
                column_b=row.prefix,
                column_c=row.raw_company_name,
                column_d=row.raw_address,
                column_e=column_e,
                column_f=column_f,
                column_g=column_g,
                column_h=column_h,
                flag_mismatch=mismatch,
                cleaned_company_name=cleaned_company,
                cleaned_address=cleaned_address,
                matched_subsidiary=matched_subsidiary,
                match_type=match_type,
                match_score=match_score,
                whois_orgname=whois_orgname,
                whois_netname=whois_netname,
                whois_domains=whois_domains,
                whois_registry=whois_registry,
                source_url=source_url,
                review_reason=review_reason,
                live_search_debug=live_search_debug,
                audit_steps=audit_steps,
            )
        )
        if progress_callback is not None:
            progress_callback(index, total_rows, f"Completed row {row.row_number}")
    return results


def validate_whois_only_prefixes(
    prefixes: List[str],
    catalog: CompanyCatalog,
    whois_client: WhoisLookupClient,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> List[WhoisOnlyResult]:
    results: List[WhoisOnlyResult] = []
    total_prefixes = len(prefixes)
    for index, prefix in enumerate(prefixes, start=1):
        if progress_callback is not None:
            progress_callback(index - 1, total_prefixes, f"Looking up {prefix}")
        matched_name, match_type, score, org_names, net_name, whois_domains, registry_name, whois_error = _run_whois_match(prefix, catalog, whois_client)
        verdict = "FALSE"
        reason = "FALSE — WHOIS resolved the prefix, but no accepted company or subsidiary matched OrgName or NetName."
        confidence = "Medium"
        review_reason = ""
        if whois_error:
            reason = f"FALSE — {whois_error}"
        elif match_type in {"whois_orgname_exact", "whois_netname_exact"}:
            verdict = "TRUE"
            confidence = "Medium"
            reason = (
                "TRUE — WHOIS OrgName matched accepted subsidiary."
                if match_type == "whois_orgname_exact"
                else "TRUE — WHOIS NetName matched accepted subsidiary."
            )
        elif match_type == "whois_close_not_exact":
            verdict = "FALSE"
            confidence = "To Review"
            review_reason = "WHOIS very close but not exact."
            reason = "To Review — WHOIS entity name was very close to accepted subsidiary but not exact. Verdict: FALSE."
        elif match_type == "whois_domain_exact":
            verdict = "FALSE"
            confidence = "To Review"
            review_reason = "WHOIS domain matched accepted domain without exact entity name."
            reason = "To Review — WHOIS domain matched an accepted domain, but the entity name was not exact. Verdict: FALSE."
        results.append(
            WhoisOnlyResult(
                input_prefix=prefix,
                whois_orgname=org_names,
                whois_netname=net_name,
                whois_domains=whois_domains,
                whois_registry=registry_name,
                matched_subsidiary=matched_name,
                match_type=match_type,
                match_score=score,
                verdict=verdict,
                reason=reason,
                confidence=confidence,
                review_reason=review_reason,
            )
        )
        if progress_callback is not None:
            progress_callback(index, total_prefixes, f"Completed {prefix}")
    return results
