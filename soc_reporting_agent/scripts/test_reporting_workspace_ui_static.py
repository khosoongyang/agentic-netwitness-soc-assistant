from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
app = (ROOT / 'dashboard' / 'app.js').read_text(encoding='utf-8')
css = (ROOT / 'dashboard' / 'style.css').read_text(encoding='utf-8')
editable = (ROOT / 'reporting' / 'editable_reports.py').read_text(encoding='utf-8')

checks = []

def check(name, condition):
    checks.append((name, bool(condition)))

check('reporting workspace has dedicated full-width layout mode', 'reporting-agent-workspace-mode' in app and 'reporting-selected-grid' in app)
check('report review workspace is rendered outside the narrow summary card', 'renderSocReportReviewWorkspace(ticket, { fullWidth: true })' in app)
check('reporting summary card is a mini status summary, not full report grid', 'reporting-output-mini-summary' in app and 'Use the full-width SOC Report Review Workspace' in app)
check('save draft preserves current workspace/editor', 'refreshSelectedTicket(ticketId, { renderAfter: false })' in app and 'You are still in the report editor' in app)
check('save and enable export does not close modal or reroute', 'closeModal();\n    await loadTicket(ticketId);' not in app and 'Edits saved. Word and PDF export are now ready.' in app)
check('reports use one generated files workspace', 'Generated Files' in app and 'generated-files-table' in app and 'return renderSocReportReviewWorkspace(t);' in app)
check('generic export controls were removed', 'data-action="export-report"' not in app)
check('report rows support editing and reviewed exports', 'Open &amp; Edit' in app and 'Export Word' in app and 'Export PDF' in app and 'Save &amp; Enable Export' in app)
check('structured reporting data can be downloaded', 'download-reporting-data' in app and 'downloadReportingDataJson' in app)
check('approve/reject/evidence-gap decisions use refresh without setRoute reroute', 'Staying on the current Agent Workspace' in app and 'await refresh();\n}\n\nasync function decision' in app)
check('UI strips visible html table tags from editable report content', 'stripReportUiMarkup' in app and 'td|tr|th|table' in app)
check('report workspace CSS uses two-column responsive grid', '.soc-report-grid' in css and 'repeat(2,minmax(280px,1fr))' in css)
check('report editor CSS uses professional serif report font', 'Georgia,Cambria,"Times New Roman",serif' in css)
check('DOCX confirmed report exporter applies Georgia font', '_apply_report_font' in editable and 'normal.font.name = "Georgia"' in editable)

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
if failed:
    raise SystemExit(f"Failed checks: {failed}")
print(f"\nPassed {len(checks)} UI/report workspace checks.")
