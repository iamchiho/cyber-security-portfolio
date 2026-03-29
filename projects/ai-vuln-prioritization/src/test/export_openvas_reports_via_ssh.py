import os
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path
import pexpect


ENV_FILE = Path(__file__).with_name(".env")


def load_dotenv_file(env_path: Path) -> None:
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def get_required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


load_dotenv_file(ENV_FILE)

SSH_USER = get_required_env("OPENVAS_SSH_USER")
SSH_HOST = get_required_env("OPENVAS_SSH_HOST")
SSH_PASSWORD = get_required_env("OPENVAS_SSH_PASSWORD")

GMP_USERNAME = get_required_env("OPENVAS_GMP_USERNAME")
GMP_PASSWORD = get_required_env("OPENVAS_GMP_PASSWORD")

BASE_DIR = Path(__file__).resolve().parent
OUTDIR = BASE_DIR / "openvas_reports"
OUTDIR.mkdir(exist_ok=True)


def run_remote_gvm(xml_payload: str, timeout: int = 300) -> str:
    """
    Run gvm-cli remotely over SSH and return raw output.
    Handles:
    - SSH password prompt
    - GVM username prompt
    - GVM password prompt
    """
    remote_cmd = f"sudo -n -u _gvm /usr/bin/gvm-cli socket --xml {shlex.quote(xml_payload)}"
    ssh_cmd = f"ssh {SSH_USER}@{SSH_HOST} {shlex.quote(remote_cmd)}"

    child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=timeout)
    output_parts = []

    while True:
        idx = child.expect(
            [
                r"(?i)password:",              # SSH password prompt
                r"Enter username:",
                r"Enter password for .*:",
                pexpect.EOF,
                pexpect.TIMEOUT,
            ]
        )

        output_parts.append(child.before)

        if idx == 0:
            child.sendline(SSH_PASSWORD)
        elif idx == 1:
            child.sendline(GMP_USERNAME)
        elif idx == 2:
            child.sendline(GMP_PASSWORD)
        elif idx == 3:
            break
        elif idx == 4:
            raise TimeoutError("Timed out waiting for remote command output.")

    result = "".join(output_parts)
    if isinstance(child.after, str):
        result += child.after
    return result


def strip_to_xml(raw_text: str, root_tag: str) -> str:
    start = raw_text.find(f"<{root_tag}")
    if start == -1:
        raise RuntimeError(
            f"Could not find <{root_tag}> in output.\n\n"
            f"First 2000 chars:\n{raw_text[:2000]}"
        )
    return raw_text[start:].strip()


def get_reports_list_xml() -> str:
    raw = run_remote_gvm('<get_reports details="0"/>')
    return strip_to_xml(raw, "get_reports_response")


def get_report_metadata(reports_xml: str) -> list[dict[str, str]]:
    root = ET.fromstring(reports_xml)

    reports = []
    for report in root.findall("./report"):
        report_id = report.get("id")
        creation_time = report.findtext("creation_time")
        name = report.findtext("name")
        task_name = report.findtext("task/name")

        if report_id and creation_time:
            reports.append(
                {
                    "id": report_id,
                    "creation_time": creation_time,
                    "name": name or "",
                    "task_name": task_name or "",
                }
            )

    if not reports:
        raise RuntimeError("No reports found in report list XML.")

    reports.sort(key=lambda x: x["creation_time"], reverse=True)
    return reports


def export_full_report_xml(report_id: str) -> str:
    raw = run_remote_gvm(
        (
            f'<get_reports report_id="{report_id}" details="1" '
            f'ignore_pagination="1" filter="first=1 rows=-1"/>'
        ),
        timeout=900,
    )
    return strip_to_xml(raw, "get_reports_response")


def count_report_results(report_xml: str) -> int:
    root = ET.fromstring(report_xml)
    return len(root.findall("./report/report/results/result"))


def main():
    print("Getting report list...")
    reports_xml = get_reports_list_xml()
    reports = get_report_metadata(reports_xml)

    print(f"Found {len(reports)} report(s).")

    for index, report in enumerate(reports, start=1):
        report_id = report["id"]
        print(f"[{index}/{len(reports)}] Exporting report: {report_id}")
        print(f"  Creation time: {report['creation_time']}")
        print(f"  Name: {report['name']}")
        print(f"  Task: {report['task_name']}")

        full_report_xml = export_full_report_xml(report_id)
        result_count = count_report_results(full_report_xml)
        output_file = OUTDIR / f"{report_id}.xml"
        output_file.write_text(full_report_xml, encoding="utf-8")

        print(f"  Result count in XML: {result_count}")
        print(f"Saved full report to: {output_file}")


if __name__ == "__main__":
    main()
