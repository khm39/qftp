import json, html
from svg import seq, bytes_layout, hexdump, figure, esc
import wire
BASE="/tmp/claude-0/-home-user-qftp/96263040-8562-5047-8304-4e5f08fbf7fd/scratchpad/qftp-design/10-protocol"
VEC={}
for f,kind in [("requests.json","Request"),("responses.json","Response"),("error-codes.json","Response")]:
    for v in json.load(open(f"{BASE}/test-vectors/{f}"))["vectors"]: VEC[v["name"]]=(kind,v)
def dump(name, caption=None):
    kind,v=VEC[name]; vn,val,rows=wire.decode_frame(v["wire_hex"],kind)
    cap=caption or f'ベクタ <code>{name}</code>: {esc(v["description"])}(全 {len(bytes.fromhex(v["wire_hex"]))} バイト)'
    return hexdump(rows,cap)

def table(head, rows, cls=""):
    th="".join(f"<th>{h}</th>" for h in head)
    body="".join("<tr>"+"".join(f"<td>{c}</td>" for c in r)+"</tr>" for r in rows)
    return f'<table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>'
def details(summary, inner):
    return f'<details class="vec"><summary>{summary}</summary>{inner}</details>'

S=[]  # (id, title, html)
def sec(i,t,h): S.append((i,t,h))

# ---------- 0 ----------
sec("about","本書について", f"""
<p>本書は <strong>qftp/1</strong>(QUIC 上のファイル転送プロトコル)を、図と表で読めるように解説したものです。正本は同じディレクトリの Markdown 仕様書(<code>qftp-protocol.md</code>、<code>wire-format.md</code>、<code>error-codes.md</code>、<code>versioning.md</code>)であり、本書と食い違う場合は正本が優先します。本書のバイト列の例はすべて <code>test-vectors/</code> のゴールデンベクタを仕様どおりに復号して機械生成したもので、手書きの転記はありません。</p>
<div class="legend"><b>凡例</b>
<ul><li><span class="chip chip-be">BE</span> ビッグエンディアン、<span class="chip chip-le">LE</span> リトルエンディアン。</li>
<li>図中の <b>C</b> はクライアント、<b>S</b> はサーバです。実線は必ず送られるもの、破線は条件つきです。</li>
<li>「実装定義」はワイヤが規定せず、各実装が自由に決めてよい値です。参照実装の値を参考として示します。</li>
<li>RFC 2119 の <b>MUST</b> / <b>SHOULD</b> / <b>MAY</b> は正本と同じ意味で使います。</li></ul></div>
""")

# ---------- 1 overview ----------
ov=seq(["クライアント","サーバ"],[
 ("note",(0,1),"1 本の QUIC コネクション(UDP、TLS 1.3、ALPN \"qftp/1\")"),
 ("msg",0,1,"ストリーム 0: Request::Ls"),("msg",1,0,"ストリーム 0: Response::DirListing",{"dashed":False}),
 ("msg",0,1,"ストリーム 4: Request::Get"),("msg",1,0,"ストリーム 4: FileReady + 本体 + トレーラ"),
 ("msg",0,1,"ストリーム 8: Request::Put + 本体 + トレーラ"),("msg",1,0,"ストリーム 8: Response::Ok"),
 ("msg",0,1,"ストリーム 12: Request::Quit"),("msg",1,0,"Response::Ok → CONNECTION_CLOSE"),
],caption="図 1. コマンドごとに 1 本の双方向ストリームを使う。ストリームは互いに独立で、順序保証はない")
sec("overview","全体像", f"""
<p>qftp は FTP の「制御接続 + データ接続」を、<strong>1 本の QUIC コネクション</strong>に置き換えます。コマンドもファイル本体も、クライアントが開く双方向ストリームの上を流れます。</p>
{ov}
{table(["層","内容"],[
 ["トランスポート","UDP + QUIC v1(RFC 9000)。TLS 1.3 必須。mTLS は任意(設定時はクライアント証明書を強制)"],
 ["バージョン交渉","ALPN 識別子 <code>qftp/1</code>。不一致は QUIC ハンドシェイク失敗として現れ、プロトコル往復はゼロ"],
 ["ストリーム","クライアント発の双方向ストリーム(ID 0, 4, 8, …)。先頭フレームは必ず <code>Request</code>、続いてサーバの <code>Response</code>(Get は複数)"],
 ["本体","<code>Get</code> / <code>Put</code> のファイル本体は制御フレームの直後、同じストリームに流れる(<a href='#get'>§9</a>、<a href='#put'>§10</a>)"],
 ["接続の終わり","<code>Quit</code> に <code>Ok</code> を返した後、サーバが CONNECTION_CLOSE を送る"],
])}
<p><strong>設計上の要点</strong>: ストリーム間に順序がないため、コネクション状態である cwd(<code>Cd</code>)は「応答を受け取った後に出した要求」にしか保証されません(<a href="#path">§8</a>)。逐次実行しないクライアントは <code>/</code> 始まりの絶対パスを使うべきです。</p>
""")

# ---------- 2 lifecycle ----------
lc=seq(["クライアント","サーバ"],[
 ("msg",0,1,"Initial(SNI, ALPN qftp/1)"),
 ("side",1,"DCID 長 8..=20 か / Initial レート制限 / 接続上限"),
 ("msg",1,0,"Retry(token)",{"dashed":True}),
 ("msg",0,1,"Initial(token)",{"dashed":True}),
 ("side",1,"token 検証(HMAC、有効期限、送信元アドレス)\nSCID = HMAC(seed, client DCID)"),
 ("note",(0,1),"TLS 1.3 ハンドシェイク(1-RTT、またはチケットがあれば 0-RTT 再開)"),
 ("msg",0,1,"[0-RTT early data] Request(許可リストのみ)",{"dashed":True}),
 ("msg",1,0,"HANDSHAKE_DONE"),
 ("side",1,"peer cert → identity 解決 → cwd = home"),
 ("msg",0,1,"Request(1-RTT)"),("msg",1,0,"Response"),
 ("sep","… 任意の数の要求 …"),
 ("msg",0,1,"Request::Quit"),("msg",1,0,"Response::Ok"),("msg",1,0,"CONNECTION_CLOSE"),
],caption="図 2. コネクションのライフサイクル。破線は stateless retry 要求時、または 0-RTT 再開時のみ")
sec("lifecycle","コネクションのライフサイクル", f"""
{lc}
{table(["局面","規定"],[
 ["アドレス検証","サーバは最初の Initial に stateless retry を要求してよい(MAY)。トークンはクライアントに不透明で、形式は実装定義(<a href='#retry'>§13</a>)"],
 ["identity","mTLS 時はハンドシェイク完了時点の peer 証明書から解決する。それ以前は anonymous としてしか実行できない(<a href='#zero-rtt'>§12</a> の identity gate)"],
 ["cwd","接続受理時にユーザのルート。identity が昇格したら昇格後ユーザのルートにリセット。<code>Cd</code> 成功時のみ変化"],
 ["アイドル","参照実装は <code>max_idle_timeout</code> 30 秒、keepalive なし。ブリッジ(WebTransport)のみ 15 秒 keepalive"],
 ["終了","<code>Quit</code> → <code>Ok</code> → サーバから graceful な CONNECTION_CLOSE"],
])}
""")

# ---------- 3 framing ----------
sec("framing","フレーミングとエンディアン", f"""
<p>すべての制御メッセージは<strong>長さプレフィクス付きフレーム</strong>です。</p>
{bytes_layout([("length",4,"u32 BE","bl-hdr"),("payload",None,"length バイト(内部は LE)","bl-body")],caption="図 3. フレーム = 4 バイトの長さ + ペイロード。長さの値は 4 バイト分を含まない")}
<div class="callout warn"><b>相互運用で最も多い間違い</b>: フレーム長プレフィクスだけがビッグエンディアンで、ペイロード内の整数(判別子、長さ、数値フィールド)は<strong>すべてリトルエンディアン</strong>です。</div>
{table(["規則","内容"],[
 ["上限","長さプレフィクスが 16 MiB(<code>0x0100_0000</code>)を超えるフレームは、ペイロードを読まずに拒否する(MUST)。宣言された長さより大きいバッファを確保してはならない"],
 ["消費","受信側は必ず <code>4 + length</code> バイトを消費する。それ以降のバイトは次のフレームか本体ストリーミング層に属する"],
 ["フィールド上限","フレーム上限だけでは個々の文字列や配列は抑えられないため、復号後にフィールド上限(<a href='#limits'>§15</a>)を適用する(SHOULD)"],
 ["切り詰め","ペイロードの途中でフレームが終わる(フィールドが足りない)場合は <code>Malformed</code>"],
])}
""")

# ---------- 4 primitives ----------
prim=table(["型","符号化","図"],[
 ["<code>u8</code> / <code>u16</code> / <code>u32</code> / <code>u64</code>","1 / 2 / 4 / 8 バイト、LE",bytes_layout([("u32",4,"LE","bl-int")])],
 ["<code>bool</code>","1 バイト。<code>0x00</code>=false、<code>0x01</code>=true。それ以外は拒否",bytes_layout([("bool",1,"00 | 01","bl-tag")])],
 ["<code>Option&lt;T&gt;</code>","タグ 1 バイト。<code>0x00</code>=None(後続なし)、<code>0x01</code>=Some + T の符号化。それ以外は拒否",bytes_layout([("tag",1,"00 | 01","bl-tag"),("T",None,"Some のときだけ","bl-body")])],
 ["<code>string</code>","u64 LE のバイト長 n、続いて n バイトの UTF-8(NUL 終端なし)",bytes_layout([("n",8,"u64 LE","bl-len"),("UTF-8",None,"n バイト","bl-str")])],
 ["<code>seq&lt;T&gt;</code>","u64 LE の要素数 n、続いて T の符号化 × n",bytes_layout([("n",8,"u64 LE","bl-len"),("T[0]",None,"","bl-body"),("T[1]",None,"…","bl-body")])],
 ["<code>[u8; N]</code>","長さプレフィクスなしの N バイト",bytes_layout([("bytes",None,"N バイト","bl-str")])],
 ["struct","フィールドを宣言順に連結。区切り・パディング・タグなし",""],
 ["位置依存 enum","判別子 u32 LE(宣言順の 0 始まり)、続いてそのバリアントのフィールド。未知の判別子は復号不能 → <code>Malformed</code>。<code>Request</code> / <code>Response</code> / <code>ErrorDetails</code> が該当",bytes_layout([("disc",4,"u32 LE","bl-disc"),("fields",None,"バリアント依存","bl-body")])],
 ["数値 enum","u32 LE の<strong>値</strong>(位置ではなく割り当て番号)。未知の値は <code>Unknown(n)</code> として保持し、フレームは拒否しない。<code>ErrorCode</code> / <code>FileType</code> / <code>HashAlgorithm</code> / <code>Encoding</code> が該当",bytes_layout([("value",4,"u32 LE","bl-enum")])],
],cls="prim")
sec("primitives","プリミティブ符号化", f"""
<p>ペイロードは以下のプリミティブを<strong>タグも区切りも入れずに連結</strong>したものです。フィールド名はワイヤに載りません(位置依存)。</p>
{prim}
<p><strong>例</strong>: <code>Request::Ls {{ path: "docs", cursor: None }}</code> のフレーム全体を復号すると次のようになります。</p>
{dump("ls")}
<p>2 種類の enum の違いは拡張性に直結します。位置依存 enum に新しいバリアントを足すと旧実装は復号できませんが、数値 enum に新しい値を足しても旧実装は <code>Unknown(n)</code> として読み進められます(<a href="#versioning">§14</a>)。</p>
""")

# ---------- 5 messages ----------
def req_fields(fields):
    return ", ".join(f"<code>{n}</code>" for n,_ in fields) or "<em>(なし)</em>"
REQ_DESC={"Ls":"ディレクトリ一覧(ページネーション対応)","Cd":"cwd を変更","Pwd":"cwd を仮想絶対パスで返す","Get":"ダウンロード(再開・範囲・圧縮)","Put":"アップロード(再開・チェックサム・圧縮)","Mkdir":"ディレクトリ作成","Rmdir":"空ディレクトリ削除","Rm":"ファイル削除","Rename":"改名 / 移動","Chmod":"POSIX 権限ビットの変更","Stat":"メタデータ取得","Quota":"使用量と上限","Quit":"切断要求"}
REQ_RESP={"Ls":"DirListing","Cd":"Ok","Pwd":"Path","Get":"FileReady + 本体","Put":"Ok","Mkdir":"Ok","Rmdir":"Ok","Rm":"Ok","Rename":"Ok","Chmod":"Ok","Stat":"FileStat","Quota":"QuotaInfo","Quit":"Ok"}
rows=[[i,f"<code>{n}</code>",req_fields(f),REQ_DESC[n],f"<code>{REQ_RESP[n]}</code>"] for i,(n,f) in enumerate(wire.REQ)]
reqtab=table(["判別子","Request","フィールド(ワイヤ順)","意味","成功応答"],rows)
RESP_DESC={"Ok":"成功(本体なし)","Err":"失敗。<code>ErrorResponse</code> を 1 つ","DirListing":"一覧 1 ページ + 次ページのカーソル","Path":"仮想絶対パス","FileStat":"メタデータ","FileReady":"Get の応答ヘッダ。直後に本体が続く","QuotaInfo":"使用量・ファイル数・上限"}
rows=[[i,f"<code>{n}</code>",req_fields(f),RESP_DESC[n]] for i,(n,f) in enumerate(wire.RESP)]
resptab=table(["判別子","Response","フィールド(ワイヤ順)","意味"],rows)

def layout_of(fields, first=("disc",4,"判別子","bl-disc")):
    fs=[first]
    for n,t in fields:
        if t in ("u8","u16","u32","u64"): fs.append((n,int(t[1:])//8,t+" LE","bl-int"))
        elif t=="bool": fs.append((n,1,"bool","bl-tag"))
        elif t=="string": fs.append((n,None,"string","bl-str"))
        elif isinstance(t,tuple) and t[0]=="enum": fs.append((n,4,"数値 enum","bl-enum"))
        elif isinstance(t,tuple) and t[0]=="opt": fs.append((n,None,"Option","bl-opt"))
        elif isinstance(t,tuple) and t[0]=="seq": fs.append((n,None,"seq","bl-seq"))
        elif isinstance(t,tuple) and t[0]=="struct": fs.append((n,None,"struct","bl-body"))
    return bytes_layout(fs)

FIELD_NOTES={
 "Ls":[("path","一覧するディレクトリ。空文字列は cwd"),("cursor","<code>None</code> で先頭ページ。続きは受け取った <code>next_cursor</code> をそのまま返す(不透明、サーバ定義)")],
 "Get":[("path","ファイルパス"),("offset","再開位置(平文バイト)。サーバはここまで seek"),("length","最大本体バイト数。<code>None</code> は EOF まで"),("accept_encoding","復号できるコーデックを優先順で。空なら Identity のみ")],
 "Put":[("path","宛先"),("size","今回送る平文バイト数(offset 以降)"),("mode","POSIX 権限ビット"),("offset","再開位置。<code>&gt;0</code> のとき partial の長さと一致必須"),("hash_algorithm","<code>checksum</code> とトレーラのアルゴリズム(qftp/1 は Blake3 のみ)"),("checksum","ヘッダ経路のフルファイルダイジェスト(事前計算)"),("no_clobber","true なら既存宛先を <code>AlreadyExists</code> で拒否"),("checksum_trailer","true なら本体の直後にダイジェストを流す(ヘッダより優先)"),("encoding","本体の圧縮コーデック"),("plaintext_size","圧縮時の平文サイズ(<code>size</code> と一致必須)")],
 "Rename":[("from","元"),("to","先")],("Chmod"):[("path","対象"),("mode","権限ビット。suid/sgid/sticky は実装が落としてよい")],
}
msg_sections=[]
VEC_FOR={"Ls":["ls"],"Cd":["cd"],"Pwd":["pwd"],"Get":["get_full","get_range","get_accept_zstd"],"Put":["put_minimal","put_full","put_trailer","put_zstd"],"Mkdir":["mkdir"],"Rmdir":["rmdir"],"Rm":["rm"],"Rename":["rename"],"Chmod":["chmod"],"Stat":["stat"],"Quota":["quota"],"Quit":["quit"]}
for i,(n,f) in enumerate(wire.REQ):
    notes=FIELD_NOTES.get(n)
    nt=table(["フィールド","意味"],[[f"<code>{a}</code>",b] for a,b in notes]) if notes else ""
    dumps="".join(details(f'ベクタ <code>{v}</code>: {esc(VEC[v][1]["description"])}',dump(v)) for v in VEC_FOR[n])
    lay=layout_of(f,("disc",4,f"{i} = {n}","bl-disc")) if f else bytes_layout([("disc",4,f"{i} = {n}","bl-disc")])
    msg_sections.append(f'<h3 id="req-{n.lower()}"><code>Request::{n}</code>(判別子 {i})</h3>{lay}{nt}{dumps}')
VEC_FOR_R={"Ok":["ok"],"Err":["err","err_details","err_details_upload","err_details_retry_after"],"DirListing":["dir_listing","dir_listing_empty"],"Path":["path"],"FileStat":["file_stat"],"FileReady":["file_ready","file_ready_minimal","file_ready_zstd"],"QuotaInfo":["quota_info","quota_info_unlimited"]}
RESP_NOTES={
 "FileReady":[("size","クライアントが受け取る<strong>平文</strong>バイト数(offset・length 適用後)。Identity ではワイヤ本体長でもある"),("total_size","ファイル全体のサイズ。再開時の縮小検出に使う"),("checksum_follows","true なら本体直後にダイジェストトレーラ。再開 Get では false 禁止"),("hash_algorithm","トレーラのアルゴリズム"),("encoding","サーバが選んだコーデック"),("plaintext_size","圧縮時は <code>size</code> と等しい。Identity では無視")],
 "DirListing":[("entries","1 ページ分。上限 100,000 件 / ページ(SHOULD ~1 MiB で分割)"),("next_cursor","<code>Some</code> なら続きがある。<code>None</code> で終端")],
 "QuotaInfo":[("used_bytes","使用量(平文)"),("file_count","ファイル数"),("limit_bytes","<code>None</code> は無制限")],
}
for i,(n,f) in enumerate(wire.RESP):
    notes=RESP_NOTES.get(n); nt=table(["フィールド","意味"],[[f"<code>{a}</code>",b] for a,b in notes]) if notes else ""
    dumps="".join(details(f'ベクタ <code>{v}</code>: {esc(VEC[v][1]["description"])}',dump(v)) for v in VEC_FOR_R[n])
    lay=layout_of(f,("disc",4,f"{i} = {n}","bl-disc")) if f else bytes_layout([("disc",4,f"{i} = {n}","bl-disc")])
    msg_sections.append(f'<h3 id="resp-{n.lower()}"><code>Response::{n}</code>(判別子 {i})</h3>{lay}{nt}{dumps}')
sec("messages","メッセージ一覧", f"""
<p>ストリームの先頭フレームは <code>Request</code>、応答は <code>Response</code> です。どちらも位置依存 enum で、ペイロードは u32 LE の判別子から始まります。</p>
<h3>Request(13 種)</h3>{reqtab}
<h3>Response(7 種)</h3>{resptab}
<p>以下、各メッセージのバイト配置と、ゴールデンベクタの注釈つきダンプ(折り畳み)です。</p>
{"".join(msg_sections)}
""")

# ---------- 6 structures ----------
de=layout_of(wire.DIRENTRY,("name",None,"string","bl-str")); de=de  # first is name
de=bytes_layout([("name",None,"string","bl-str"),("file_type",4,"数値 enum","bl-enum"),("size",8,"u64","bl-int"),("modified",8,"u64 秒","bl-int"),("mtime_nanos",4,"u32","bl-int"),("uid",4,"u32","bl-int"),("gid",4,"u32","bl-int"),("mode",4,"u32","bl-int")],caption="図 4. DirEntry(FileStat は先頭の name を除いた同じ並び)")
er=bytes_layout([("code",4,"数値 enum","bl-enum"),("message",None,"string ≤ 1 KiB","bl-str"),("details",None,"Option<ErrorDetails>","bl-opt")],caption="図 5. ErrorResponse")
ed=bytes_layout([("tag",1,"Option","bl-tag"),("disc",4,"0 Range / 1 Upload / 2 RetryAfter","bl-disc"),("fields",None,"u64,u64 / u64,u64 / u32","bl-body")],caption="図 6. ErrorDetails(位置依存 enum)。Option の Some に続く")
sec("structures","共通データ構造", f"""
<h3>DirEntry / FileStat</h3>{de}
{table(["フィールド","意味"],[
 ["<code>name</code>","単一のパス要素。<code>/</code> <code>&#92;</code> NUL を含まず、<code>.</code> <code>..</code> でもない(受信側は必ず検査する)"],
 ["<code>file_type</code>","0 Regular / 1 Directory / 2 Symlink / 3 Other。未知の値は「ディレクトリではない」として扱う"],
 ["<code>modified</code> + <code>mtime_nanos</code>","Unix 秒とナノ秒部分(0..1,000,000,000)"],
 ["<code>uid</code> / <code>gid</code>","取得できない環境では 0"],
 ["<code>mode</code>","POSIX 権限ビット。ない環境では合成値"],
])}
{details("ベクタ <code>dir_listing</code>(2 エントリ + next_cursor)",dump("dir_listing"))}
<h3>ErrorResponse / ErrorDetails</h3>{er}{ed}
{table(["details バリアント","付随する code","フィールド"],[
 ["<code>Range { offset, file_size }</code>","<code>InvalidRange</code>","要求した offset と実際のサイズ"],
 ["<code>Upload { received, declared }</code>","<code>UploadOverflow</code> / <code>UploadTruncated</code>","受信済みと宣言サイズ"],
 ["<code>RetryAfter { millis }</code>","<code>RateLimited</code>","最低待ち時間"],
])}
<p><code>message</code> は運用者・開発者向けの英語診断文で、エンドユーザ表示や機械判定に使ってはなりません。判定は必ず <code>code</code>(と <code>details</code>)で行います。</p>
{details("ベクタ <code>err_details</code>(InvalidRange + Range)",dump("err_details"))}
{details("ベクタ <code>err_details_retry_after</code>(RateLimited + RetryAfter)",dump("err_details_retry_after"))}
""")

# ---------- 7 error codes ----------
RETRY={429:"バックオフ付きで再試行(<code>RetryAfter</code> があればその時間以上待つ)",500:"バックオフ付きで再試行(5xx 全般)",405:"0-RTT 拒否由来なら<strong>即時</strong>再試行。それ以外は再試行禁止"}
MEAN={400:"フレームまたはペイロードが復号できない",401:"認証失敗、またはユーザ未設定",403:"ACL またはファイルシステム権限で拒否",404:"パスが存在しない",405:"この文脈では非対応(0-RTT で来た変更操作など)",409:"宛先が存在し、存在しないことが要件(<code>no_clobber</code>)",413:"サーバの最大ファイルサイズ超過",416:"再開 offset(または Get 範囲)が不正",420:"ディレクトリが必要だが通常ファイル",421:"通常ファイルが必要だがディレクトリ",422:"転送バイトのハッシュ検証失敗",423:"宣言 <code>size</code> より多く送られた",424:"宣言 <code>size</code>(またはトレーラ)に届く前に FIN",429:"接続内の要求レート制限",430:"ストレージクォータ超過",431:"圧縮本体が復号できない(不正フレーム、窓超過)",500:"サーバ側 I/O エラー等"}
rows=[[c,f"<code>{wire.CODES[c]}</code>","client" if c<500 else "server",MEAN[c],RETRY.get(c,"再試行禁止(同じ要求は同じ結果)")] for c in sorted(wire.CODES)]
sec("errors","エラーコード", f"""
<p><code>ErrorResponse.code</code> は HTTP に似た<strong>数値ステータス</strong>(u32 LE)です。先頭の桁が分類を表し、未知のコードでも桁だけで再試行の可否を判断できます。</p>
{table(["コード","名前","分類","意味","再試行"],rows)}
{table(["未知コードの扱い","規定"],[
 ["復号","<code>Unknown(n)</code> として復号に成功する(フレームを拒否しない、MUST NOT)"],
 ["分類","先頭桁 4 → client、5 → server、それ以外 → server(保守的既定)"],
 ["message","必ず保持し、桁による再試行規則を適用する"],
 ["追加","新コードは前方互換。メジャーバージョンを上げずに追加できるが、変更履歴とベクタの追加が必要"],
])}
{details("ベクタ <code>err_NotFound</code>(code 404 = 0x194 がそのまま載る)",dump("err_NotFound"))}
""")

# ---------- 8 path ----------
sec("path","パス解決", f"""
<p>すべての <code>path</code>(<code>Rename</code> の <code>from</code> / <code>to</code> も)はサーバ側で 2 つの状態に対して解決されます。<strong>ユーザのルート</strong>(home、プロトコル上は <code>/</code>)と、<strong>コネクションの cwd</strong> です。</p>
{table(["入力","cwd","結果","備考"],[
 ["<code>/a/b</code>","任意","ルート/a/b","<code>/</code> 始まりはルートから"],
 ["<code>a/b</code>","<code>/x</code>","ルート/x/a/b","それ以外は cwd から"],
 ["<code>a//b/</code>","<code>/</code>","ルート/a/b","連続区切りは畳む、末尾区切りは無視"],
 ["<code>./a/../b</code>","<code>/x</code>","ルート/x/b","<code>.</code> は無視、<code>..</code> は 1 段上がる"],
 ["<code>/..</code>、<code>../../..</code>(深さ超過)","任意","<code>PermissionDenied</code>","ルートを越える試みは拒否。クランプしない"],
 ["途中に symlink","任意","<code>PermissionDenied</code>(参照実装)","symlink 経由のルート脱出は禁止(MUST)。<code>openat2(RESOLVE_BENEATH)</code> 相当があればルート内 symlink を許してよい"],
 ["<code>Ls</code> に空文字列","<code>/x</code>","ルート/x を一覧",""],
])}
{table(["規則","内容"],[
 ["区切り","<code>/</code>。<code>&#92;</code> 等が区切りになるかは実装定義。クライアントは依存してはならない"],
 ["Pwd の表現","仮想絶対パス(<code>/</code>、<code>/sub/dir</code>)。サーバの実パスを出してはならない"],
 ["Cd と並行ストリーム","新しい cwd は「<code>Cd</code> の成功応答を受け取った後に出した要求」にのみ保証される。同時に飛んでいる要求は旧 / 新どちらで解決されるか未規定"],
 ["文字集合","UTF-8 前提。非 UTF-8 は実装定義(参照実装は lossy 変換)。大文字小文字と Unicode 正規化はサーバのファイルシステムに従う"],
])}
""")

# ---------- 9 Get ----------
getseq=seq(["クライアント","サーバ"],[
 ("side",0,"offset = ローカル既存ファイルの長さ(なければ 0)"),
 ("msg",0,1,"Request::Get { path, offset, length, accept_encoding }"),
 ("side",1,"ACL / パス解決 / offset ≤ len ? / コーデック選択"),
 ("msg",1,0,"Response::FileReady { size, total_size, checksum_follows,\nhash_algorithm, encoding, plaintext_size }"),
 ("note",(0,1),"offset > 0 のとき: 両端が [0, offset) を自分の側のファイルから読み直してハッシュに畳む(ワイヤには流れない)"),
 ("msg",1,0,"本体(Identity: size バイト / Zstd: 自己終端の 1 フレーム)"),
 ("msg",1,0,"トレーラ(digest 長 = 32 バイト)+ FIN",{"dashed":True}),
 ("side",0,"hash([0, offset+本体)) == トレーラ ? 確定 : ローカル削除"),
],caption="図 7. Get の流れ。トレーラは checksum_follows = true のときのみ(再開 Get では必須)")
getlay=bytes_layout([("frame(FileReady)",None,"4 B 長 + ペイロード","bl-hdr"),("body",None,"size バイト or zstd フレーム","bl-body"),("trailer",32,"BLAKE3、フレーム化なし","bl-str"),("FIN",0,"最後のバイトに","bl-tag")],caption="図 8. Get ストリーム上のバイト列。本体とトレーラは長さプレフィクスを持たない")
sec("get","Get(ダウンロード)", f"""
{getseq}{getlay}
{table(["ケース","本体","トレーラ","FIN"],[
 ["Identity、size &gt; 0","ちょうど size バイト","checksum_follows なら 32 B","トレーラの最後(なければ本体の最後)"],
 ["Identity、size == 0","なし(本体フェーズをスキップ)","空の平文に対するダイジェスト","トレーラの最後(なければ空ストリーム)"],
 ["Zstd","1 個の自己終端 zstd フレーム(復号結果が plaintext_size バイト)。<code>size</code> はワイヤ長ではない","同上","同上"],
 ["Zstd、size == 0","空の zstd フレームを送る(受信側がフレーム境界を観測できるように)","同上","同上"],
 ["エラー","<code>FileReady</code> の代わりに <code>Response::Err</code> 1 つ、ストリーム終了","なし","Err の後"],
])}
<h3>トレーラは何をハッシュするか</h3>
<p>トレーラは<strong>平文の累積範囲 <code>[0, offset + 本体長)</code></strong> のダイジェストです。再開(<code>offset &gt; 0</code>)では、サーバは自分のファイルから、クライアントはローカルの partial から <code>[0, offset)</code> を読み直して先に畳みます。したがって <code>length</code> 未指定ならトレーラはファイル全体のハッシュに等しく、サーバ側ファイルが<strong>同じサイズで中身だけ変わった</strong>場合(<code>total_size</code> では検出できない)も不一致として検出できます。これが「再開 Get で <code>checksum_follows = false</code> を禁止する」理由です。</p>
{table(["検査","違反時"],[
 ["<code>offset &gt; len</code>","<code>InvalidRange</code> + <code>Range { offset, file_size }</code>"],
 ["<code>total_size &lt; offset</code>(再開中に縮小)","<code>InvalidRange</code>"],
 ["再開 Get に <code>checksum_follows = false</code>","禁止(サーバは送ってはならない)"],
 ["圧縮時に <code>size != plaintext_size</code>","クライアントはプロトコルエラーとして扱う(SHOULD)"],
 ["トレーラ不一致","クライアントはデータを破棄する(MUST)"],
])}
<h3>コーデックの選択</h3>
<p>クライアントは <code>accept_encoding</code> に復号できるコーデックを優先順で並べ、サーバは対応するものを 1 つ選んで <code>FileReady.encoding</code> で答えます。小さいファイルや既圧縮ファイルでは <code>Identity</code> を選んでよい(MAY)。空の <code>accept_encoding</code> は Identity のみを意味します。</p>
""")

# ---------- 10 Put ----------
putseq=seq(["クライアント","サーバ"],[
 ("msg",0,1,"Request::Stat { \"<dest>.qftp.partial\" }",{"dashed":True}),
 ("msg",1,0,"FileStat { size = p } | Err(NotFound)",{"dashed":True}),
 ("side",0,"offset = p(0 < p ≤ ローカル長)、それ以外は 0"),
 ("msg",0,1,"Request::Put { path, size, mode, offset, hash_algorithm,\nchecksum, no_clobber, checksum_trailer, encoding, plaintext_size }"),
 ("side",1,"検証必須形 / size == plaintext_size / 上限 /\nno_clobber / partial 長 == offset / クォータ"),
 ("msg",1,0,"Response::Err(検証失敗時、本体を読む前)",{"dashed":True}),
 ("note",(0,1),"offset > 0 のとき: 両端が [0, offset) を読み直してハッシュに畳む"),
 ("msg",0,1,"本体(Identity: size バイト / Zstd: 自己終端の 1 フレーム)"),
 ("msg",0,1,"トレーラ(32 バイト)+ FIN",{"dashed":True}),
 ("side",1,"checksum 解決 → 検証 → temp を rename → mode 適用"),
 ("msg",1,0,"Response::Ok | Response::Err"),
],caption="図 9. Put の流れ。Stat による再開位置の探索は慣習であり、partial の名前規則(<dest>.qftp.partial)は参照実装のもの")
putlay=bytes_layout([("frame(Put)",None,"4 B 長 + ペイロード","bl-hdr"),("body",None,"size バイト or zstd フレーム","bl-body"),("trailer",32,"checksum_trailer 時","bl-str"),("FIN",0,"最後のバイトに","bl-tag")],caption="図 10. Put ストリーム上のバイト列(クライアント → サーバ方向)。応答フレームは逆方向に 1 つ")
chk=table(["checksum(ヘッダ)","checksum_trailer","トレーラの到着","採用されるダイジェスト"],[
 ["None","false","—","<strong>検証なし</strong>(fresh かつ Identity のときのみ許される)"],
 ["Some","false","—","ヘッダの値"],
 ["任意","true","32 バイト揃った","<strong>トレーラ</strong>(ヘッダより優先)"],
 ["任意","true","途中で FIN","<code>UploadTruncated</code>(ヘッダへ黙って戻さない)"],
])
sec("put","Put(アップロード)", f"""
{putseq}{putlay}
<h3>チェックサムの解決</h3>
<p>ダイジェストは 2 経路あり、どちらも<strong>ファイル全体</strong>(再開時は再ハッシュしたプレフィクスを含む)を対象にします。</p>{chk}
<h3>検証が必須になる形</h3>
{table(["Put の形","チェックサムなしのとき","理由"],[
 ["再開(<code>offset &gt; 0</code>)","<code>Unsupported</code>(本体を読む前)","partial の長さ検査だけではプレフィクスの差し替えを検出できない"],
 ["圧縮(<code>encoding != Identity</code>)","<code>Unsupported</code>","ワイヤ長が平文長の証拠にならず、復号の破損・切り詰めが黙って確定してしまう"],
 ["圧縮で <code>size != plaintext_size</code>","<code>Malformed</code>","不変条件"],
])}
<h3>再開の規則</h3>
{table(["項目","規定"],[
 ["partial の場所","宛先から決定的に導ける名前(参照実装は <code>&lt;final&gt;.qftp.partial</code>、同じディレクトリ)。原子的 rename のため"],
 ["offset の検査","<code>offset &gt; 0</code> なら partial がちょうど offset バイトであること。違えば <code>InvalidRange</code> + <code>Range</code>"],
 ["fresh Put","<code>offset == 0</code> は古い partial を切り詰めて再利用"],
 ["圧縮 + 再開","offset 以降の平文だけを独立した zstd フレームとして送る。ディスク上のプレフィクスは平文のまま"],
 ["成功時","temp を原子的に rename し、<code>mode</code> を適用"],
 ["<code>no_clobber</code>","true で既存なら <code>AlreadyExists</code>。false(既定)は上書き"],
])}
<h3>失敗の分類</h3>
{table(["コード","タイミング","典型原因"],[
 ["<code>FileTooLarge</code> / <code>QuotaExceeded</code> / <code>PermissionDenied</code> / <code>AlreadyExists</code>","本体を読む前","事前検証"],
 ["<code>UploadOverflow</code>","本体受信中","宣言 size より多い(+ <code>Upload</code> details)"],
 ["<code>UploadTruncated</code>","FIN 到着時","size またはトレーラに届かない(+ <code>Upload</code> details)"],
 ["<code>DecodeError</code>","本体受信中","zstd フレーム不正、窓超過"],
 ["<code>ChecksumMismatch</code>","最終バイト後","ダイジェスト不一致。サーバは temp を削除"],
 ["<code>Internal</code>","任意","I/O エラー"],
])}
""")

# ---------- 11 compression ----------
comp=bytes_layout([("平文 [0,offset)",None,"ディスク上 / ハッシュ対象","bl-str"),("平文 [offset, …)",None,"→ zstd 1 フレーム → ワイヤ","bl-body"),("trailer",32,"平文全体のハッシュ","bl-enum")],caption="図 11. 圧縮はワイヤ上の本体だけを変換する。offset・トレーラ・クォータ・partial はすべて平文の世界")
sec("compression","転送圧縮(zstd)", f"""
<p>圧縮は転送ごとのオプトインで、<strong>平文ドメイン原則</strong>に従います。すなわち <code>offset</code>、<code>size</code>、トレーラ、クォータ、サーバ側 partial はすべて平文を指し、圧縮はワイヤ上の本体バイト列だけを変えます。</p>{comp}
{table(["項目","凍結値 / 規定"],[
 ["コーデック","<code>Encoding</code>: 0 Identity、1 Zstd。qftp/1 は zstd のみ"],
 ["フレーム","転送ごとに 1 個の自己終端 zstd フレーム。再開時はテール部分のみを新しいフレームに"],
 ["窓","<code>window_log = 23</code>(8 MiB)。エンコーダは全レベルで強制、デコーダは上限として設定。超過は <code>DecodeError</code>"],
 ["レベル","ワイヤ非交渉。送信側のローカルポリシー(参照実装は 3)"],
 ["境界","受信側はデコーダが「フレーム完了」と「消費した入力バイト数」を報告した位置でトレーラを切り出す。<code>size</code> は区切りに使わない"],
 ["伸長爆弾","復号出力を <code>plaintext_size</code> と最大ファイルサイズで打ち切る(MUST)。超過は Put では <code>UploadOverflow</code>。<code>plaintext_size</code> をメモリ確保に使わない"],
 ["クォータ","平文バイトで計上"],
 ["既圧縮の回避","送信側の判断(拡張子など)。ワイヤには影響しない"],
])}
""")

# ---------- 12 0-RTT ----------
sec("zero-rtt","0-RTT セッション再開", f"""
<p>サーバは QUIC の 0-RTT を有効にします。前回のチケットを持つクライアントは最初のフライトにアプリケーションデータを載せられますが、early data は<strong>再生可能</strong>で、しかも<strong>identity 解決前</strong>に届きます。そのため 2 段のゲートがあります。</p>
<h3>ゲート 1: 再生安全性(要求種別)</h3>
{table(["Request","0-RTT","理由"],[
 ["<code>Cd</code> <code>Pwd</code> <code>Stat</code> <code>Quit</code>","許可","読み取り専用・冪等・応答が小さく固定長"],
 ["<code>Ls</code> <code>Get</code> <code>Quota</code>","拒否","応答が大きくなり得る(反射増幅の道具になる)"],
 ["<code>Put</code> <code>Rm</code> <code>Mkdir</code> <code>Rmdir</code> <code>Rename</code> <code>Chmod</code>","拒否","再生で副作用が起きる"],
])}
<h3>ゲート 2: identity gate(サーバ設定)</h3>
{table(["サーバの状態","early data の扱い"],[
 ["mTLS 必須、または名前付きユーザが設定されている","<strong>すべて拒否</strong>(許可リストの要求も)。early data は anonymous としてしか実行できず、昇格後のユーザとは別のトラストドメインだから"],
 ["identity を持たない(全員 anonymous)","ゲート 1 のみ"],
])}
<p>拒否は <code>Unsupported</code>(405)で返り、クライアントはハンドシェイク完了後に<strong>バックオフなしで即時再送</strong>します(MUST)。拒否の理由が 0-RTT であることだけで、操作自体は有効だからです。参照クライアントはチケット(ホストごと、0600、24 時間)を保存しますが、early data にアプリケーションデータは載せません。</p>
""")

# ---------- 13 retry etc ----------
rseq=seq(["クライアント","サーバ"],[
 ("msg",0,1,"Initial(token なし)"),
 ("side",1,"状態を確保せずに token を発行"),
 ("msg",1,0,"Retry { token }"),
 ("msg",0,1,"Initial { token }"),
 ("side",1,"token 検証 → 接続状態を確保"),
],caption="図 12. stateless retry。トークンはクライアントに不透明で、そのまま返す")
sec("retry","stateless retry・レート制限・接続 ID", f"""
{rseq}
{table(["項目","規定","参照実装(実装定義)"],[
 ["retry","最初の Initial に retry を要求してよい(MAY)。トークンは送信元アドレスと元の DCID にコミットする","<code>&quot;qftp1&quot; || 発行時刻 || IP || port || dcid_len || dcid || HMAC-SHA256[..16]</code>、有効 60 秒、タグは 20 バイト以上を推奨"],
 ["接続レート制限","Initial ごとに送信元 IP で検査。超過は黙って破棄","トークンバケット 50 req/s、バースト 100"],
 ["要求レート制限","確立済み接続で <code>Request</code> 復号時に検査。超過は <code>RateLimited</code> + <code>RetryAfter</code>","同上(新設計では Initial 用と要求用を別バケットにする)"],
 ["サーバ接続 ID","クライアントの DCID から決定的に導出する(SHOULD)。再送 Initial が同じ接続に収束する","<code>HMAC-SHA256(プロセス寿命の seed, client_dcid)</code> を CID 長に切り詰め"],
])}
""")

# ---------- 14 versioning ----------
ver=seq(["旧デコーダ","新デコーダ"],[
 ("note",(0,0),"新フレーム(末尾フィールド追加)を受信\n→ 既知フィールドを読み、残りを無視 ✔"),
 ("note",(1,1),"旧フレーム(末尾フィールドなし)を受信\n→ 末尾で切り詰め = Malformed ✘\n(両形状を受ける寛容デコードが必要)",{"warn":True}),
],caption="図 13. append-only 規則は一方向にしか効かない")
sec("versioning","バージョニングと拡張", f"""
<p>メジャーバージョンは ALPN(<code>qftp/1</code>)で運びます。符号化は位置依存で自己記述ではないため、同一メジャー内で許される構造変更は<strong>既存メッセージの末尾へのフィールド追加</strong>だけです。</p>
{ver}
{table(["変更","同一メジャー内で可能か","備考"],[
 ["メッセージ末尾へのフィールド追加","可(条件つき)","旧デコーダは余剰バイトを無視できる。新デコーダは旧フレームを受けるために「短い形状 + 既定値」を明示的に受理し、既定値を文書化する(MUST)"],
 ["数値 enum への値追加(<code>ErrorCode</code> 等)","可(前方互換)","旧側は <code>Unknown(n)</code> として読み進む。受信側が扱えない値は <code>Unsupported</code> で優雅に失敗"],
 ["<code>Request</code> / <code>Response</code> / <code>ErrorDetails</code> のバリアント追加","不可","旧側は復号できない(<code>Malformed</code>)。新メジャーが必要"],
 ["フィールドの並べ替え・削除・型幅変更、判別子の付け直し、エンディアン変更","不可","新メジャー(<code>qftp/2</code>)"],
])}
<p>いずれの変更も、ゴールデンベクタの追加と <code>protocol-changelog.md</code> への記録が必須です。qftp/2 に先送りされている方向(自己記述エンコーディング、varint、帯域内 capability 交渉、メッセージ層 MAC、<code>Copy</code> / <code>Symlink</code> / <code>Transaction</code>)は同ファイルにあります。</p>
""")

# ---------- 15 limits ----------
sec("limits","実装定義パラメータと上限", f"""
<h3>フィールド上限(SHOULD)</h3>
{table(["対象","上限"],[["フレーム長","16 MiB"],["<code>path</code> / <code>from</code> / <code>to</code> / 各 <code>DirEntry.name</code>","4,096 バイト"],["<code>ErrorResponse.message</code>","1,024 バイト"],["<code>DirListing.entries</code>","100,000 件 / ページ(約 1 MiB で分割推奨)"],["最大ファイルサイズ","実装定義(参照実装 1 GiB、超過は <code>FileTooLarge</code>)"]])}
<h3>QUIC トランスポートパラメータ(参照実装)</h3>
{table(["パラメータ","値","備考"],[["<code>initial_max_streams_bidi</code>","4","参照クライアントは 1 本ずつ使う"],["<code>max_idle_timeout</code>","30 s",""],["<code>initial_max_stream_data</code>","16 MiB","ギガビット級 BDP 向け。ユーザ空間のチャンクは 64 KiB"],["<code>initial_max_data</code>","64 MiB","4 × 16 MiB"],["pacing","off","フロー制御と輻輳制御でバックプレッシャ"],["keepalive","なし","ブリッジのみ 15 s"],["active migration","無効",""]])}
<h3>その他の実装定義</h3>
{table(["項目","内容"],[["パス","UTF-8 前提。非 UTF-8 の扱い、大文字小文字、正規化、最大深さは実装定義"],["retry トークン形式、接続 ID 導出、レート制限の値","<a href='#retry'>§13</a>"],["partial の名前","<code>&lt;final&gt;.qftp.partial</code>(参照実装)"],["圧縮の既定オン / オフと既圧縮判定","送信側ポリシー"]])}
""")

# ---------- 16 appendix ----------
allv=[]
for f,kind in [("requests.json","Request"),("responses.json","Response"),("error-codes.json","Response")]:
    for v in json.load(open(f"{BASE}/test-vectors/{f}"))["vectors"]:
        allv.append(details(f'<code>{f}</code> / <code>{v["name"]}</code>: {esc(v["description"])}',dump(v["name"])))
sec("vectors","付録: 全ゴールデンベクタの注釈つきダンプ", f"""
<p>本書の生成器が <code>test-vectors/</code> の全 {len(allv)} ベクタを仕様(§3〜§6)どおりに復号したものです。生成時に「フレームを最後まで消費できること」を検査しており、1 件でも失敗すれば本書は生成されません。他言語実装のデバッグ時に、期待バイト列との突き合わせに使ってください。</p>
{"".join(allv)}
""")

# ---------- assemble ----------
from theme import CSS

toc="<nav class='toc'><b>目次</b><ol>"+"".join(f'<li><a href="#{i}">{t}</a></li>' for i,t,_ in S)+"</ol></nav>"
body="".join(f'<section id="{i}"><h2>{t}</h2>{h}</section>' for i,t,h in S)
doc=f"""<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>qftp/1 プロトコル解説(図解版)</title><style>{CSS}</style></head><body><main>
<header class="doc"><div class="kind">プロトコル解説(図解版)</div><h1>qftp/1 プロトコル解説</h1><div class="meta">作成日: 2026-09-03 / 対象ワイヤ: qftp/1(2026-05-30 凍結)/ バイト列の例は test-vectors から機械生成</div></header>
{toc}{body}
<script>
// open the <details> a fragment link points into (so #vectors links land on visible content)
function openTarget(){{var h=location.hash;if(!h)return;var el=document.querySelector(h);if(!el)return;var d=el.closest('details');if(d)d.open=true;}}
window.addEventListener('hashchange',openTarget);openTarget();
</script></main></body></html>"""
out=f"{BASE}/qftp-protocol-guide.html"
open(out,"w",encoding="utf-8").write(doc)
print(out, len(doc)//1024, "KiB", "sections:", len(S))
