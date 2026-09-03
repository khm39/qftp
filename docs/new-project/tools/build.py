import re, json, os, sys, html, importlib
SK = "/root/.claude/skills/synced/a3bc8980-9c40-45da-a3f1-c79a0b43a0d6_84a5c1bf-12e3-43dd-b79d-0b7691f78c50/design-doc-writer"
OUT = "/tmp/claude-0/-home-user-qftp/96263040-8562-5047-8304-4e5f08fbf7fd/scratchpad/qftp-design/20-design"
LABELS = {"feature":"機能設計書","screen":"画面設計書","architecture":"アーキテクチャ設計書","sequence":"シーケンス設計書","batch":"バッチ処理設計書","operations":"運用設計書"}
DATE = "2026-09-03"

def load_spec(doc_type):
    secs=[]
    for line in open(f"{SK}/references/{doc_type}.md",encoding="utf-8"):
        m=re.match(r"^## \d+\. (.+?) \(([a-z0-9\-]+)\)\s*$",line)
        if m: secs.append({"id":m.group(2),"name":m.group(1),"fields":[]}); continue
        m=re.match(r"^- (.+?) \(([a-z0-9\-]+)\):",line)
        if m and secs: secs[-1]["fields"].append({"id":m.group(2),"name":m.group(1)})
    return secs

PLACEHOLDERS={"","未定","TBD","-"}
def build(doc_type,title,answers,filename):
    skel=open(f"{SK}/assets/skeleton.html",encoding="utf-8").read()
    secs=load_spec(doc_type)
    parts=[]; meta={}
    used=set()
    for s in secs:
        parts.append(f'<section data-section-id="{s["id"]}">\n  <h2>{html.escape(s["name"])}</h2>')
        for f in s["fields"]:
            key=f"{s['id']}.{f['id']}"; used.add(key)
            v=answers.get(key,"")
            meta[key]=v
            if v.strip() in PLACEHOLDERS:
                body='<div class="field-body empty">未記入</div>'
            elif v.strip()=="N/A":
                body='<div class="field-body empty">N/A</div>'
            else:
                body=f'<div class="field-body">{v}</div>'
            parts.append(f'  <div class="field" data-field-id="{f["id"]}">\n    <h3>{html.escape(f["name"])}</h3>\n    {body}\n  </div>')
        parts.append("</section>")
    unknown=set(answers)-used
    if unknown: print("WARN unknown keys in",filename,unknown,file=sys.stderr)
    metaj={"skillVersion":"1","docType":doc_type,"title":title,"createdAt":DATE,"updatedAt":DATE,"answers":meta}
    mj=json.dumps(metaj,ensure_ascii=False).replace("</script>","<\\/script>")
    out=(skel.replace("<!--TITLE-->",html.escape(title)).replace("<!--DOC-TYPE-->",LABELS[doc_type])
         .replace("<!--META-DATE-->",DATE).replace("<!--META-UPDATED-->",DATE)
         .replace("<!--SECTIONS-->","\n".join(parts)).replace("<!--DOC-META-JSON-->",mj))
    os.makedirs(OUT,exist_ok=True)
    open(f"{OUT}/{filename}","w",encoding="utf-8").write(out)
    filled=sum(1 for k,v in meta.items() if v.strip() not in PLACEHOLDERS)
    print(f"{filename}: {filled}/{len(meta)} fields filled")

if __name__=="__main__":
    sys.path.insert(0,os.path.dirname(__file__))
    for mod in sys.argv[1:]:
        m=importlib.import_module(mod)
        build(m.DOC_TYPE,m.TITLE,m.ANSWERS,m.FILENAME)
