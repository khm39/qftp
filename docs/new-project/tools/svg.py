"""Inline-SVG helpers: sequence diagrams and byte-layout diagrams (theme-aware via CSS classes)."""
import html
def esc(s): return html.escape(str(s))
def tw(s):
    """approximate rendered text width in px for 12px mono/CJK mix"""
    return sum(12.5 if ord(c)>0x2E80 else 7.3 for c in s)

def seq(participants, items, width=None, caption=None):
    n=len(participants); margin=90
    # column spacing wide enough for the widest message label between adjacent participants
    need=220
    for it in items:
        if it[0]=="msg" and it[1]!=it[2]:
            span=abs(it[1]-it[2]); w=max(tw(l) for l in it[3].split("\n"))+30
            need=max(need, w/span)
        if it[0]=="note" and it[1][0]!=it[1][1]:
            span=it[1][1]-it[1][0]; w=max(tw(l) for l in it[2].split("\n"))+40
            need=max(need, w/span)
    colw=int(need)
    right=0
    for it in items:
        if it[0]=="side" and it[1]==n-1:
            right=max(right, max(tw(l) for l in it[2].split("\n"))+40)
        if it[0]=="note" and it[1][0]==it[1][1]==n-1:
            right=max(right, (max(tw(l) for l in it[2].split("\n"))+40)/2)
    left=0
    for it in items:
        if it[0]=="note" and it[1][0]==it[1][1]==0:
            left=max(left, (max(tw(l) for l in it[2].split("\n"))+40)/2)
    xs=[margin+int(left)+i*colw for i in range(n)]
    W=width or (xs[-1]+margin+int(right))
    y=56; out=[]
    body=[]
    for it in items:
        k=it[0]
        if k=="msg":
            _,a,b,text=it[:4]; opt=it[4] if len(it)>4 else {}
            x1,x2=xs[a],xs[b]; dashed=opt.get("dashed"); 
            lines=text.split("\n"); h=14*len(lines)+10
            ty=y+8
            if x1==x2:  # self message
                body.append(f'<path class="sq-line{" sq-dash" if dashed else ""}" d="M{x1},{y+h} h40 v18 h-40" marker-end="url(#sq-arrow)"/>')
                for i,l in enumerate(lines): body.append(f'<text class="sq-text" x="{x1+46}" y="{ty+i*14+6}">{esc(l)}</text>')
                y+=h+26; continue
            mid=(x1+x2)/2; anchor="middle"
            for i,l in enumerate(lines): body.append(f'<text class="sq-text" x="{mid}" y="{ty+i*14}" text-anchor="{anchor}">{esc(l)}</text>')
            ly=y+h
            body.append(f'<line class="sq-line{" sq-dash" if dashed else ""}" x1="{x1}" y1="{ly}" x2="{x2}" y2="{ly}" marker-end="url(#sq-arrow)"/>')
            y+=h+16
        elif k=="note":
            _,span,text=it[:3]; opt=it[3] if len(it)>3 else {}
            a,b=span; lines=text.split("\n"); h=14*len(lines)+14
            tw_=max(tw(l) for l in lines)+24
            if a==b:
                x1=xs[a]-tw_/2; x2=xs[a]+tw_/2
            else:
                x1=xs[a]+18; x2=xs[b]-18
                if x2-x1<tw_:
                    c=(xs[a]+xs[b])/2; x1=c-tw_/2; x2=c+tw_/2
            body.append(f'<rect class="sq-note{" sq-note-warn" if opt.get("warn") else ""}" x="{x1}" y="{y}" width="{x2-x1}" height="{h}" rx="6"/>')
            for i,l in enumerate(lines): body.append(f'<text class="sq-text" x="{(x1+x2)/2}" y="{y+18+i*14}" text-anchor="middle">{esc(l)}</text>')
            y+=h+14
        elif k=="side":  # note beside a participant, left-aligned box
            _,a,text=it[:3]; lines=text.split("\n"); h=14*len(lines)+14; w=max(tw(l) for l in lines)+24
            x1=xs[a]+12
            body.append(f'<rect class="sq-note" x="{x1}" y="{y}" width="{w}" height="{h}" rx="6"/>')
            for i,l in enumerate(lines): body.append(f'<text class="sq-text" x="{x1+10}" y="{y+18+i*14}">{esc(l)}</text>')
            y+=h+14
        elif k=="gap": y+=it[1]
        elif k=="sep":
            _,text=it; body.append(f'<line class="sq-sep" x1="20" y1="{y+8}" x2="{W-20}" y2="{y+8}"/>'); body.append(f'<text class="sq-sep-text" x="{W/2}" y="{y+4}" text-anchor="middle">{esc(text)}</text>'); y+=26
    H=y+20
    out.append(f'<svg class="diagram-svg" viewBox="0 0 {W} {H}" width="{W}" role="img">')
    out.append('<defs><marker id="sq-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="sq-arrowhead"/></marker></defs>')
    for i,p in enumerate(participants):
        out.append(f'<line class="sq-life" x1="{xs[i]}" y1="40" x2="{xs[i]}" y2="{H-10}"/>')
        out.append(f'<rect class="sq-actor" x="{xs[i]-64}" y="8" width="128" height="30" rx="7"/>')
        out.append(f'<text class="sq-actor-text" x="{xs[i]}" y="28" text-anchor="middle">{esc(p)}</text>')
    out+=body; out.append('</svg>')
    svg="".join(out)
    return figure(svg,caption)

def figure(inner,caption=None):
    c=f'<figcaption>{caption}</figcaption>' if caption else ''
    return f'<figure class="diagram">{inner}{c}</figure>'

def bytes_layout(fields, caption=None, scale=None):
    """fields: list of (label, nbytes|None for variable, sublabel, cls). Draw proportional boxes (min 40px, cap 8 bytes at 16px each)."""
    x=10; boxes=[]; H=92
    for label,nb,sub,cls in fields:
        if nb is None: w=110
        else: w=max(44, min(nb,8)*18+ (12 if nb>8 else 0))
        w=max(w, tw(label)+16, tw(sub or "")+14)
        boxes.append((x,w,label,nb,sub,cls)); x+=w+4
    W=x+10
    out=[f'<svg class="diagram-svg" viewBox="0 0 {W} {H}" width="{W}" role="img">']
    for (x0,w,label,nb,sub,cls) in boxes:
        out.append(f'<rect class="bl-box {cls}" x="{x0}" y="26" width="{w}" height="34" rx="5"/>')
        out.append(f'<text class="bl-label" x="{x0+w/2}" y="47" text-anchor="middle">{esc(label)}</text>')
        size = "可変" if nb is None else f"{nb} B"
        out.append(f'<text class="bl-size" x="{x0+w/2}" y="18" text-anchor="middle">{size}</text>')
        if sub: out.append(f'<text class="bl-sub" x="{x0+w/2}" y="78" text-anchor="middle">{esc(sub)}</text>')
    out.append('</svg>')
    return figure("".join(out),caption)

def hexdump(rows, caption=None):
    """rows from wire.Dec: (offset, raw, label, val, kind) -> annotated table."""
    tr=[]
    for off,raw,label,val,kind in rows:
        hx=" ".join(f"{b:02x}" for b in raw)
        if len(raw)>24: hx=" ".join(f"{b:02x}" for b in raw[:24])+" …"
        tr.append(f'<tr class="hx-{kind}"><td class="hx-off">{off}</td><td class="hx-hex">{hx}</td><td class="hx-label">{esc(label)}</td><td class="hx-val">{esc(val)}</td></tr>')
    cap=f'<caption>{caption}</caption>' if caption else ''
    return f'<div class="hx-wrap"><table class="hx">{cap}<thead><tr><th>オフセット</th><th>バイト列(hex)</th><th>フィールド</th><th>値</th></tr></thead><tbody>{"".join(tr)}</tbody></table></div>'
