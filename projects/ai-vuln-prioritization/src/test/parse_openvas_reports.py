import argparse
import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_REPORTS_DIR = BASE_DIR / "openvas_reports"
DEFAULT_OUTPUT_DIR = BASE_DIR / "openvas_parsed_results"


def first_text(element: Optional[ET.Element], path: str, default: str = "") -> str:
    if element is None:
        return default
    value = element.findtext(path)
    return value.strip() if value else default


def parse_report_xml(xml_file: Path) -> dict:
    root = ET.parse(xml_file).getroot()
    report_wrapper = root.find("./report")
    report = root.find("./report/report")

    if report_wrapper is None or report is None:
        raise RuntimeError(f"Unexpected XML structure in {xml_file}")

    report_id = report_wrapper.get("id", xml_file.stem)
    task_name = first_text(report_wrapper, "./task/name")

    rows = []
    severity_counts: dict[str, int] = {}

    for result in report.findall("./results/result"):
        threat = first_text(result, "threat", "Unknown")
        severity = first_text(result, "severity", "0.0")
        nvt = result.find("nvt")

        row = {
            "report_id": report_id,
            "task_name": task_name,
            "report_name": first_text(report_wrapper, "name"),
            "creation_time": first_text(report_wrapper, "creation_time"),
            "scan_start": first_text(report, "scan_start"),
            "host": first_text(result, "host"),
            "port": first_text(result, "port"),
            "threat": threat,
            "severity": severity,
            "qod": first_text(result, "qod/value"),
            "result_name": first_text(result, "name"),
            "nvt_oid": nvt.get("oid", "") if nvt is not None else "",
            "nvt_name": first_text(result, "nvt/name"),
            "nvt_family": first_text(result, "nvt/family"),
            "cvss_base": first_text(result, "nvt/cvss_base"),
            "solution": first_text(result, "nvt/solution"),
            "description": first_text(result, "description"),
        }

        rows.append(row)
        severity_counts[threat] = severity_counts.get(threat, 0) + 1

    return {
        "report_id": report_id,
        "task_name": task_name,
        "report_name": first_text(report_wrapper, "name"),
        "creation_time": first_text(report_wrapper, "creation_time"),
        "scan_start": first_text(report, "scan_start"),
        "scan_status": first_text(report, "scan_run_status"),
        "host_count": first_text(report, "hosts/count"),
        "vuln_count": first_text(report, "vulns/count"),
        "result_count": len(rows),
        "severity_counts": severity_counts,
        "results": rows,
    }


def write_csv(report_data: dict, output_dir: Path) -> Path:
    output_file = output_dir / f"{report_data['report_id']}.csv"
    rows = report_data["results"]

    if not rows:
        output_file.write_text("", encoding="utf-8")
        return output_file

    with output_file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    return output_file


def write_json(report_data: dict, output_dir: Path) -> Path:
    output_file = output_dir / f"{report_data['report_id']}.json"
    output_file.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    return output_file


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse OpenVAS XML reports into CSV and JSON files."
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=DEFAULT_REPORTS_DIR,
        help="Directory containing exported OpenVAS XML reports.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where parsed CSV and JSON files will be written.",
    )
    args = parser.parse_args()

    reports_dir = args.reports_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    xml_files = sorted(reports_dir.glob("*.xml"))
    if not xml_files:
        raise RuntimeError(f"No XML files found in {reports_dir}")

    for xml_file in xml_files:
        report_data = parse_report_xml(xml_file)
        csv_file = write_csv(report_data, output_dir)
        json_file = write_json(report_data, output_dir)

        print(f"Parsed {xml_file.name}")
        print(f"  Results: {report_data['result_count']}")
        print(f"  CSV: {csv_file}")
        print(f"  JSON: {json_file}")


if __name__ == "__main__":
    main()
