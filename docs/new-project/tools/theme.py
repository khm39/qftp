import html
CSS=r"""
:root{--text:#1b2430;--muted:#5c6b7f;--border:#e3e8ef;--bg:#fff;--soft:#f3f5f9;--page:#e9edf3;--accent:#165e83;--accent-soft:#e3eef4;--warn:#bc4425;--warn-soft:#faeee9;--ok:#2f7d4f;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;--max:960px;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--text:#dde5ee;--muted:#8fa0b5;--border:#2a3543;--bg:#151c26;--soft:#1c2532;--page:#0e131a;--accent:#7cb8d9;--accent-soft:#1b3040;--warn:#e8926f;--warn-soft:#33221b;--ok:#7fc79b}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Hiragino Sans","Yu Gothic","Meiryo",system-ui,sans-serif;font-size:14.5px;line-height:1.85;color:var(--text);background:var(--page);counter-reset:sec}
main{max-width:var(--max);margin:40px auto;padding:48px 56px;background:var(--bg);border:1px solid var(--border);border-radius:14px}
header.doc{border-bottom:1px solid var(--border);padding-bottom:20px;margin-bottom:32px}
header.doc .kind{display:inline-block;font-size:11.5px;font-weight:700;letter-spacing:.12em;color:var(--accent);background:var(--accent-soft);padding:3px 12px;border-radius:999px;margin-bottom:12px}
header.doc h1{margin:0;font-size:28px;line-height:1.35}
header.doc .meta{margin-top:10px;font-size:12px;color:var(--muted)}
nav.toc{font-size:13px;border:1px solid var(--border);background:var(--soft);border-radius:12px;padding:12px 16px;margin-bottom:32px}
nav.toc ol{margin:6px 0 0;padding-left:22px}nav.toc a{color:var(--muted);text-decoration:none}nav.toc a:hover{color:var(--accent)}
@media (min-width:1400px){nav.toc{position:fixed;top:40px;left:max(16px,calc(50% - var(--max)/2 - 260px));width:236px;max-height:calc(100vh - 80px);overflow-y:auto;margin:0;background:transparent;border:none}}
section{margin:0 0 44px;scroll-margin-top:24px}
section>h2{counter-increment:sec;display:flex;gap:12px;align-items:baseline;font-size:20px;margin:0 0 16px;padding-bottom:10px;border-bottom:1px solid var(--border)}
section>h2::before{content:counter(sec);font-family:var(--mono);font-size:12.5px;color:var(--accent);background:var(--accent-soft);border-radius:8px;padding:1px 10px}
h3{font-size:15px;margin:26px 0 8px}
p{margin:0 0 10px}
table{border-collapse:separate;border-spacing:0;width:100%;margin:12px 0;font-size:13px;border:1px solid var(--border);border-radius:10px;overflow:hidden}
th,td{border-bottom:1px solid var(--border);padding:7px 11px;text-align:left;vertical-align:top}th+th,td+td{border-left:1px solid var(--border)}tr:last-child td{border-bottom:none}
th{background:var(--soft);font-weight:600;font-size:12px;color:var(--muted)}
table.prim td:nth-child(3){width:300px}
code{font-family:var(--mono);font-size:12.5px;background:var(--soft);border:1px solid var(--border);padding:0 5px;border-radius:5px}
figure.diagram{margin:14px 0;padding:12px;background:var(--soft);border:1px solid var(--border);border-radius:12px;overflow-x:auto}
figure.diagram svg{display:block;margin:0 auto;max-width:100%;height:auto}
figcaption{font-size:12px;color:var(--muted);text-align:center;margin-top:8px}
td figure.diagram{margin:0;padding:6px;background:transparent;border:none}
.sq-life{stroke:var(--border);stroke-width:1.5;stroke-dasharray:4 4}
.sq-actor{fill:var(--accent-soft);stroke:var(--accent);stroke-width:1.2}
.sq-actor-text{fill:var(--accent);font-size:13px;font-weight:700}
.sq-line{stroke:var(--text);stroke-width:1.4;fill:none}.sq-dash{stroke-dasharray:6 4;stroke:var(--muted)}
.sq-arrowhead{fill:var(--text)}
.sq-text{fill:var(--text);font-size:12px;font-family:var(--mono)}
.sq-note{fill:var(--bg);stroke:var(--border);stroke-width:1}.sq-note-warn{fill:var(--warn-soft);stroke:var(--warn)}
.sq-sep{stroke:var(--border);stroke-dasharray:2 4}.sq-sep-text{fill:var(--muted);font-size:11px}
.bl-box{stroke:var(--border);stroke-width:1.2;fill:var(--bg)}
.bl-hdr{fill:#fde8c7}.bl-body{fill:var(--bg)}.bl-int{fill:#dbeafe}.bl-tag{fill:#fce7f3}.bl-len{fill:#fef3c7}.bl-str{fill:#dcfce7}.bl-disc{fill:#ede9fe}.bl-enum{fill:#e0f2fe}.bl-opt{fill:#fce7f3}.bl-seq{fill:#fef3c7}
@media (prefers-color-scheme:dark){.bl-hdr{fill:#4a3319}.bl-int{fill:#1e3a5f}.bl-tag{fill:#4a1d3a}.bl-len{fill:#4a3a10}.bl-str{fill:#14432a}.bl-disc{fill:#2e2560}.bl-enum{fill:#0f3a52}.bl-opt{fill:#4a1d3a}.bl-seq{fill:#4a3a10}}
.bl-label{fill:var(--text);font-size:12px;font-family:var(--mono);font-weight:600}.bl-size{fill:var(--muted);font-size:10.5px;font-family:var(--mono)}.bl-sub{fill:var(--muted);font-size:10.5px}
.hx-wrap{overflow-x:auto;margin:8px 0}
table.hx{font-family:var(--mono);font-size:12px}table.hx caption{caption-side:top;text-align:left;font-family:inherit;font-size:12.5px;color:var(--muted);padding:6px 4px}
table.hx td.hx-off{color:var(--muted);text-align:right;width:70px}table.hx td.hx-hex{white-space:nowrap;letter-spacing:.02em}
tr.hx-disc td.hx-hex{background:#ede9fe}tr.hx-len td.hx-hex{background:#fef3c7}tr.hx-str td.hx-hex,tr.hx-bytes td.hx-hex{background:#dcfce7}tr.hx-tag td.hx-hex,tr.hx-bool td.hx-hex{background:#fce7f3}tr.hx-enum td.hx-hex{background:#e0f2fe}tr.hx-int td.hx-hex{background:#dbeafe}
@media (prefers-color-scheme:dark){tr.hx-disc td.hx-hex{background:#2e2560}tr.hx-len td.hx-hex{background:#4a3a10}tr.hx-str td.hx-hex,tr.hx-bytes td.hx-hex{background:#14432a}tr.hx-tag td.hx-hex,tr.hx-bool td.hx-hex{background:#4a1d3a}tr.hx-enum td.hx-hex{background:#0f3a52}tr.hx-int td.hx-hex{background:#1e3a5f}}
details.vec{border:1px solid var(--border);border-radius:10px;padding:6px 12px;margin:8px 0;background:var(--bg)}details.vec summary{cursor:pointer;font-size:13px;color:var(--accent)}
.callout{border-left:4px solid var(--accent);background:var(--accent-soft);padding:10px 14px;border-radius:0 10px 10px 0;margin:12px 0}.callout.warn{border-color:var(--warn);background:var(--warn-soft)}
.legend{border:1px solid var(--border);border-radius:10px;padding:10px 14px;background:var(--soft)}.legend ul{margin:6px 0 0;padding-left:20px}
.chip{display:inline-block;font-family:var(--mono);font-size:11px;padding:0 6px;border-radius:5px;border:1px solid var(--border)}.chip-be{background:#fde8c7;color:#7a4a00}.chip-le{background:#dbeafe;color:#1e3a5f}
@media print{body{background:#fff;font-size:10.5pt}main{margin:0;padding:0;border:none;max-width:none}nav.toc{display:none}section{page-break-inside:avoid}details.vec{page-break-inside:avoid}details.vec[open]>summary{font-weight:700}figure.diagram{overflow:visible}}
@media (max-width:720px){main{margin:0;padding:24px 16px;border:none;border-radius:0}}
"""
def esc(x): return html.escape(str(x))
def table(head, rows, cls=""):
    th="".join(f"<th>{h}</th>" for h in head)
    body="".join("<tr>"+"".join(f"<td>{c}</td>" for c in r)+"</tr>" for r in rows)
    return f'<table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>'
def code(s, lang=""):
    return f'<pre class="code"><code>{html.escape(s)}</code></pre>'
def page(title, kind, meta, sections, out):
    toc="<nav class='toc'><b>目次</b><ol>"+"".join(f'<li><a href="#{i}">{t}</a></li>' for i,t,_ in sections)+"</ol></nav>"
    body="".join(f'<section id="{i}"><h2>{t}</h2>{h}</section>' for i,t,h in sections)
    doc=f"""<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title><style>{CSS}
pre.code{{background:var(--soft);border:1px solid var(--border);border-radius:10px;padding:12px 14px;overflow-x:auto;font-family:var(--mono);font-size:12.5px;line-height:1.55;margin:10px 0}}pre.code code{{background:none;border:none;padding:0}}
td.k{{white-space:nowrap}}.tag{{display:inline-block;font-size:11px;padding:0 7px;border-radius:999px;border:1px solid var(--border);background:var(--soft);color:var(--muted);margin-left:4px}}
</style></head><body><main>
<header class="doc"><div class="kind">{html.escape(kind)}</div><h1>{html.escape(title)}</h1><div class="meta">{meta}</div></header>
{toc}{body}</main></body></html>"""
    open(out,"w",encoding="utf-8").write(doc)
    print(out.split("/")[-1], len(doc)//1024, "KiB")
