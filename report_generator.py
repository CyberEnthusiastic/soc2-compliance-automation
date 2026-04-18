"""HTML report generator for SOC 2 Compliance Automation."""
import os
from html import escape


def generate_html(summary: dict, results: list, output_path: str):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    status_color = {"PASS": "#34c759", "FAIL": "#ff3b30", "NO_EVIDENCE": "#8b949e"}

    rows = []
    for i, r in enumerate(sorted(results, key=lambda x: (x.status != "FAIL", x.id))):
        c = status_color.get(r.status, "#888")
        rows.append(f"""
        <div class="ctrl" data-status="{r.status}">
          <div class="fhead" onclick="toggleControl({i})">
            <span class="st" style="background:{c}">{r.status}</span>
            <span class="cid">{escape(r.id)}</span>
            <span class="fname">{escape(r.name)}</span>
            <span class="cat">{escape(r.category)}</span>
            <span class="chev">&#9656;</span>
          </div>
          <div class="fbody" id="fbody-{i}">
            <div class="row"><b>TSC:</b> <code>{escape(r.tsc)}</code> &nbsp; <b>ISO 27001:</b> <code>{escape(' / '.join(r.iso27001))}</code> &nbsp; <b>NIST CSF:</b> <code>{escape(' / '.join(r.nist_csf))}</code></div>
            <div class="row"><b>Description:</b> {escape(r.description)}</div>
            <div class="row"><b>Evidence hash:</b> <code>{escape(r.evidence_hash)}</code></div>
            <div class="row"><b>Evidence preview:</b> <code>{escape(r.evidence_preview)}</code></div>
            {f'<div class="row"><b>Remediation:</b> {escape(r.remediation)}</div>' if r.remediation else ''}
          </div>
        </div>
        """)

    bys = summary["by_status"]
    byc = summary["by_category"]
    cat_rows = []
    for cat, d in byc.items():
        total = sum(d.values())
        score = round((d["PASS"] / total) * 100, 1) if total else 0
        cat_rows.append(f"""
          <div class="card">
            <div class="l">{escape(cat)}</div>
            <div class="n">{score}%</div>
            <div class="sub">{d['PASS']} pass &middot; {d['FAIL']} fail &middot; {d['NO_EVIDENCE']} no-ev</div>
          </div>""")

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>SOC 2 Compliance Report</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#e6edf3; font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif; margin:0; padding:24px; }}
  h1 {{ margin:0 0 8px; }}
  .meta {{ color:#8b949e; margin-bottom:20px; font-size:13px; }}
  .score {{ font-size:48px; font-weight:700; color:#34c759; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin-bottom:24px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:14px; }}
  .card .n {{ font-size:24px; font-weight:700; color:#58a6ff; }}
  .card .l {{ color:#8b949e; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  .card .sub {{ color:#8b949e; font-size:11px; margin-top:4px; }}
  .ctrl {{ background:#161b22; border:1px solid #30363d; border-radius:8px; margin-bottom:8px; }}
  .fhead {{ padding:10px 14px; cursor:pointer; display:grid; grid-template-columns: 110px 70px 1fr 160px 20px; gap:10px; align-items:center; }}
  .fhead:hover {{ background:#1f242c; }}
  .st {{ display:inline-block; color:#fff; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; text-align:center; }}
  .cid {{ color:#58a6ff; font-family: ui-monospace, Menlo, monospace; font-size:12px; }}
  .cat {{ color:#8b949e; font-size:12px; }}
  .fbody {{ display:none; padding:0 14px 14px; border-top:1px solid #30363d; }}
  .fbody.open {{ display:block; }}
  .row {{ margin:6px 0; font-size:13px; }}
  code {{ background:#0d1117; border:1px solid #30363d; padding:1px 6px; border-radius:4px; font-size:12px; word-break:break-all; }}
  .foot {{ color:#8b949e; margin-top:24px; font-size:12px; text-align:center; }}
</style></head><body>
  <h1>SOC 2 Compliance Report</h1>
  <div class="meta">Generated {escape(summary["generated_at"])} &middot; {summary["total_controls"]} controls evaluated</div>
  <div style="display:flex; gap:24px; align-items:center; margin-bottom:24px; flex-wrap:wrap;">
    <div>
      <div class="score">{summary["overall_score"]}%</div>
      <div class="l" style="color:#8b949e; font-size:12px; text-transform:uppercase;">Overall score</div>
    </div>
    <div style="display:flex; gap:12px;">
      <div class="card"><div class="n" style="color:#34c759">{bys.get('PASS',0)}</div><div class="l">Pass</div></div>
      <div class="card"><div class="n" style="color:#ff3b30">{bys.get('FAIL',0)}</div><div class="l">Fail</div></div>
      <div class="card"><div class="n" style="color:#8b949e">{bys.get('NO_EVIDENCE',0)}</div><div class="l">No evidence</div></div>
    </div>
  </div>
  <div class="cards">{''.join(cat_rows)}</div>
  {''.join(rows)}
  <div class="foot">SOC 2 Compliance Automation &middot; CyberEnthusiastic</div>
<script>
  function toggleControl(i){{
    var el = document.getElementById('fbody-'+i);
    if(el) el.classList.toggle('open');
  }}
</script>
</body></html>"""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
