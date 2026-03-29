import argparse
import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_REPORTS_DIR = BASE_DIR / "openvas_reports"
DEFAULT_OUTPUT_DIR = BASE_DIR / "openvas_aggregated_results"


def first_text(element: Optional[ET.Element], path: str, default: str = "") -> str:
    if element is None:
        return default
    value = element.findtext(path)
    return clean_text(value) if value else default


def clean_text(value: Optional[str]) -> str:
    if not value:
        return ""
    return " ".join(value.split())


def parse_iso8601(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def format_iso8601(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_slug(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "_" for char in value).strip("_")


def parse_refs(result: ET.Element, ref_type: str) -> List[str]:
    values = []
    for ref in result.findall("nvt/refs/ref"):
        if (ref.get("type") or "").lower() == ref_type.lower():
            ref_id = clean_text(ref.get("id"))
            if ref_id:
                values.append(ref_id)
    return sorted(set(values))


def parse_tags(tags_text: str) -> Dict[str, str]:
    tags = {}
    if not tags_text:
        return tags

    for part in tags_text.split("|"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip()] = clean_text(value)
    return tags


def extract_host_text(result: ET.Element) -> str:
    host = result.find("host")
    if host is None:
        return ""
    text = "".join(host.itertext())
    return clean_text(text)


def result_signature(result: ET.Element) -> Tuple[str, str, str]:
    nvt = result.find("nvt")
    nvt_oid = nvt.get("oid", "") if nvt is not None else ""
    name = first_text(result, "name")
    port = first_text(result, "port")
    return (nvt_oid, name, port)


def parse_report(xml_file: Path) -> Dict:
    root = ET.parse(xml_file).getroot()
    report_wrapper = root.find("./report")
    report = root.find("./report/report")

    if report_wrapper is None or report is None:
        raise RuntimeError(f"Unexpected XML structure in {xml_file}")

    report_id = report_wrapper.get("id", xml_file.stem)
    report_time = parse_iso8601(first_text(report_wrapper, "creation_time"))
    task_name = first_text(report_wrapper, "task/name")

    parsed_results = []
    for result in report.findall("./results/result"):
        signature = result_signature(result)
        tags = parse_tags(first_text(result, "nvt/tags"))
        cves = parse_refs(result, "cve")
        urls = parse_refs(result, "url")
        host = extract_host_text(result)

        parsed_results.append(
            {
                "signature": signature,
                "report_id": report_id,
                "report_time": report_time,
                "report_name": first_text(report_wrapper, "name"),
                "task_name": task_name,
                "host": host,
                "port": first_text(result, "port"),
                "threat": first_text(result, "threat"),
                "severity": first_text(result, "severity"),
                "qod": first_text(result, "qod/value"),
                "result_name": first_text(result, "name"),
                "nvt_oid": signature[0],
                "nvt_name": first_text(result, "nvt/name"),
                "nvt_family": first_text(result, "nvt/family"),
                "cvss_base": first_text(result, "nvt/cvss_base"),
                "summary": tags.get("summary", ""),
                "impact": tags.get("impact", ""),
                "affected": tags.get("affected", ""),
                "insight": tags.get("insight", ""),
                "solution_type": tags.get("solution_type", ""),
                "solution": first_text(result, "nvt/solution"),
                "description": first_text(result, "description"),
                "cves": cves,
                "urls": urls,
            }
        )

    return {
        "report_id": report_id,
        "report_time": report_time,
        "report_name": first_text(report_wrapper, "name"),
        "task_name": task_name,
        "results": parsed_results,
    }


def aggregate_reports(report_files: List[Path]) -> Tuple[List[Dict], Dict]:
    reports = [parse_report(path) for path in sorted(report_files)]
    reports.sort(key=lambda item: item["report_time"])

    if not reports:
        raise RuntimeError("No report files were parsed.")

    latest_report = reports[-1]
    latest_report_time = latest_report["report_time"]
    latest_signatures = {item["signature"] for item in latest_report["results"]}

    aggregates: Dict[Tuple[str, str, str], Dict] = {}

    for report in reports:
        for item in report["results"]:
            signature = item["signature"]
            aggregate = aggregates.setdefault(
                signature,
                {
                    "signature": signature,
                    "vulnerability": item["result_name"],
                    "nvt_oid": item["nvt_oid"],
                    "nvt_name": item["nvt_name"],
                    "nvt_family": item["nvt_family"],
                    "port": item["port"],
                    "description": item["description"],
                    "summary": item["summary"],
                    "impact": item["impact"],
                    "affected": item["affected"],
                    "insight": item["insight"],
                    "solution": item["solution"],
                    "solution_type": item["solution_type"],
                    "severity": item["severity"],
                    "threat": item["threat"],
                    "cvss_base": item["cvss_base"],
                    "qod": item["qod"],
                    "cves": set(),
                    "reference_urls": set(),
                    "report_ids": set(),
                    "task_names": set(),
                    "hosts_seen": set(),
                    "hosts_in_latest_report": set(),
                    "report_names": set(),
                    "first_seen": item["report_time"],
                    "last_seen": item["report_time"],
                    "occurrence_count": 0,
                },
            )

            aggregate["cves"].update(item["cves"])
            aggregate["reference_urls"].update(item["urls"])
            aggregate["report_ids"].add(item["report_id"])
            aggregate["task_names"].add(item["task_name"])
            aggregate["report_names"].add(item["report_name"])
            if item["host"]:
                aggregate["hosts_seen"].add(item["host"])
                if report["report_id"] == latest_report["report_id"]:
                    aggregate["hosts_in_latest_report"].add(item["host"])

            aggregate["first_seen"] = min(aggregate["first_seen"], item["report_time"])
            aggregate["last_seen"] = max(aggregate["last_seen"], item["report_time"])
            aggregate["occurrence_count"] += 1

            if not aggregate["description"] and item["description"]:
                aggregate["description"] = item["description"]
            if not aggregate["solution"] and item["solution"]:
                aggregate["solution"] = item["solution"]
            if not aggregate["summary"] and item["summary"]:
                aggregate["summary"] = item["summary"]
            if not aggregate["impact"] and item["impact"]:
                aggregate["impact"] = item["impact"]
            if not aggregate["affected"] and item["affected"]:
                aggregate["affected"] = item["affected"]
            if not aggregate["insight"] and item["insight"]:
                aggregate["insight"] = item["insight"]

    rows = []
    fixed_count = 0

    for signature, aggregate in sorted(aggregates.items(), key=lambda entry: entry[1]["last_seen"], reverse=True):
        still_present = signature in latest_signatures
        if not still_present:
            fixed_count += 1

        age_end = latest_report_time if still_present else aggregate["last_seen"]
        age_days = (age_end - aggregate["first_seen"]).days

        row = {
            "vulnerability": aggregate["vulnerability"],
            "nvt_oid": aggregate["nvt_oid"],
            "nvt_name": aggregate["nvt_name"],
            "nvt_family": aggregate["nvt_family"],
            "cve": "; ".join(sorted(aggregate["cves"])),
            "severity": aggregate["severity"],
            "threat": aggregate["threat"],
            "cvss_base": aggregate["cvss_base"],
            "qod": aggregate["qod"],
            "port": aggregate["port"],
            "impacted_hosts": "; ".join(sorted(aggregate["hosts_seen"])),
            "impacted_host_count": len(aggregate["hosts_seen"]),
            "currently_impacted_hosts": "; ".join(sorted(aggregate["hosts_in_latest_report"])),
            "currently_impacted_host_count": len(aggregate["hosts_in_latest_report"]),
            "first_seen_date": format_iso8601(aggregate["first_seen"]),
            "last_seen_date": format_iso8601(aggregate["last_seen"]),
            "age_of_vulnerability_days": age_days,
            "fixed": "No" if still_present else "Yes",
            "seen_in_latest_scan": "Yes" if still_present else "No",
            "occurrence_count": aggregate["occurrence_count"],
            "report_count": len(aggregate["report_ids"]),
            "report_ids": "; ".join(sorted(aggregate["report_ids"])),
            "report_names": "; ".join(sorted(filter(None, aggregate["report_names"]))),
            "task_names": "; ".join(sorted(filter(None, aggregate["task_names"]))),
            "summary": aggregate["summary"],
            "description": aggregate["description"],
            "affected": aggregate["affected"],
            "impact": aggregate["impact"],
            "insight": aggregate["insight"],
            "solution": aggregate["solution"],
            "solution_type": aggregate["solution_type"],
            "reference_urls": "; ".join(sorted(aggregate["reference_urls"])),
        }
        rows.append(row)

    summary = {
        "report_count": len(reports),
        "latest_report_id": latest_report["report_id"],
        "latest_report_date": format_iso8601(latest_report_time),
        "unique_vulnerability_count": len(rows),
        "fixed_vulnerability_count": fixed_count,
        "open_vulnerability_count": len(rows) - fixed_count,
    }
    return rows, summary


def write_csv(rows: List[Dict], output_file: Path) -> None:
    if not rows:
        output_file.write_text("", encoding="utf-8")
        return

    with output_file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_json(rows: List[Dict], summary: Dict, output_file: Path) -> None:
    payload = {
        "summary": summary,
        "results": rows,
    }
    output_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Aggregate multiple OpenVAS XML reports into one combined view."
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=DEFAULT_REPORTS_DIR,
        help="Directory containing OpenVAS XML report files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where aggregated output files will be written.",
    )
    args = parser.parse_args()

    reports_dir = args.reports_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    report_files = sorted(reports_dir.glob("*.xml"))
    if not report_files:
        raise RuntimeError(f"No XML files found in {reports_dir}")

    rows, summary = aggregate_reports(report_files)

    csv_file = output_dir / "openvas_aggregated_results.csv"
    json_file = output_dir / "openvas_aggregated_results.json"
    write_csv(rows, csv_file)
    write_json(rows, summary, json_file)

    print(f"Aggregated {len(report_files)} report(s)")
    print(f"Unique vulnerabilities: {summary['unique_vulnerability_count']}")
    print(f"Open vulnerabilities: {summary['open_vulnerability_count']}")
    print(f"Fixed vulnerabilities: {summary['fixed_vulnerability_count']}")
    print(f"CSV: {csv_file}")
    print(f"JSON: {json_file}")


if __name__ == "__main__":
    main()
