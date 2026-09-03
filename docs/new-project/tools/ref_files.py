from theme import page, table, code
from svg import bytes_layout
MAGIC='"QFT2' + chr(92) + '0FP' + chr(92) + 'n"'
from theme import ROOT
OUT=f"{ROOT}/40-reference/file-formats.html"
S=[]
S.append(("paths","ファイルの配置",f"""
{table(["ファイル","既定パス","所有 / モード","作成者"],[
 ["サーバ設定","<code>/etc/qftp/server.toml</code>","root / 0644","運用者"],
 ["ユーザ定義","<code>/etc/qftp/users.toml</code>","root:&lt;サーバ実行ユーザのグループ&gt; / 0640(admin の <code>--mode</code> 既定)","qftp-admin"],
 ["トークン","<code>/etc/qftp/tokens.toml</code>","同上","qftp-admin"],
 ["永続自己署名","<code>$XDG_STATE_HOME/qftp/self-signed/{cert.pem,key.pem}</code>","サーバ実行ユーザ / dir 0700、key 0600","qftp-server"],
 ["ストレージルート","<code>root</code> 設定値","サーバ実行ユーザ","運用者"],
 ["クライアント設定","<code>~/.qftp/config.toml</code>","利用者 / 0600 推奨","利用者"],
 ["known_hosts","<code>~/.qftp/known_hosts</code>","利用者 / 0600","qftp-client"],
 ["セッションチケット","<code>~/.qftp/session-tickets/&lt;host_port&gt;.ticket</code>","利用者 / dir 0700、file 0600","qftp-client"],
 ["履歴","<code>~/.qftp_history</code>","利用者 / 0600","qftp-client"],
])}
"""))
S.append(("users","users.toml",f"""
{code('''# users.toml
[anonymous]                      # 任意。省略時: home = root、read のみ、quota なし
home = "public"
permissions = { read = true }

[[users]]
name = "alice"                   # 必須。空白のみ・"anonymous" は不可。大文字小文字は区別
home = "alice"                   # 任意。相対 → <root>/alice、省略 → <root>/<name>、絶対パス可
permissions = { read = true, write = true, delete = false, mkdir = true, rmdir = false, rename = false, chmod = false }
quota_bytes = 1073741824         # 任意。0 は不可(無制限は省略で表す)

[[users]]
name = "bob"
permissions = { read = true }''')}
{table(["検証","違反時"],[
 ["未知キー","エラー"],
 ["<code>permissions</code> の未指定キー","false"],
 ["相対 home に <code>..</code> を含む","エラー"],
 ["home が root の外(canonicalize 後)","エラー"],
 ["write 権限を持つ 2 ユーザの home が同一または入れ子(anonymous を含む)","エラー(クォータカウンタが独立なため)。read-only の anonymous の home は他ユーザの home を含んでよい(ADR-015)"],
 ["name の重複","エラー"],
 ["<code>quota_bytes = 0</code>","エラー"],
 ["home が存在しない","サーバ起動時に作成(0750)"],
])}
<p>mTLS の identity は証明書の SAN(dNSName → rfc822Name → URI)→ CN の順で候補を作り、<code>name</code> と完全一致(前後空白は除去)で照合します。複数ユーザに一致する証明書は拒否されます。</p>
"""))
S.append(("tokens","tokens.toml",f"""
{code('''# tokens.toml(qftp-admin token add が生成。手編集は check で検証すること)
[[tokens]]
user = "alice"
label = "laptop"                                   # user 内で一意(revoke は --user と組で指定)
sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
created = "2026-09-03T00:00:00Z"                   # RFC 3339
# expires = "2027-09-03T00:00:00Z"                 # 任意''')}
{table(["項目","規定"],[
 ["トークン本体","32 バイトの乱数を base64url(パディングなし、43 文字)で表した文字列。<code>token add</code> の stdout にだけ現れる"],
 ["保存","<code>sha256(token 文字列の UTF-8)</code> を小文字 hex 64 桁で保存(ADR-012)"],
 ["照合","受信文字列を SHA-256 し、全エントリと定数時間比較(早期終了しない)。一致したエントリの <code>user</code> が users.toml に存在しなければ拒否"],
 ["検証","<code>user</code> の存在、<code>label</code> の一意性、hex の長さ、未知キー"],
 ["失効","エントリ削除(<code>token revoke --user &lt;user&gt; &lt;label&gt;</code>)または <code>expires</code>。再読込は再起動(将来 SIGHUP)"],
])}
"""))
S.append(("known-hosts","known_hosts",f"""
{code('''# ~/.qftp/known_hosts — 1 行 1 ホスト。# 以降はコメント
files.work.example:4433 sha256:3b1f…e9a0
[2001:db8::1]:4433 sha256:77c2…01aa
home.lan:4433 sha256:0c9d…4e21   # 2026-09-03 に pin''')}
{table(["項目","規定"],[
 ["キー","接続に使った <code>host:port</code> の文字列(SNI ではない)。IPv6 は <code>[…]:port</code>。大文字小文字はそのまま"],
 ["値","leaf 証明書 DER の SHA-256、小文字 hex 64 桁、<code>sha256:</code> 接頭辞"],
 ["照合","先頭から最初に一致した行。複数行の同一ホストは許さない(追記時に既存行があれば置換ではなくエラー)"],
 ["不正行","警告して無視(<code>-v</code> で行番号)"],
 ["追記","<code>flock</code> で排他、0600、末尾に 1 行。ホスト文字列に空白・改行・<code>#</code> を含む場合は拒否(インジェクション防止)"],
 ["不一致","接続を閉じ(データ未送出)、SSH 風バナー + 実際に使ったファイルパスを表示、終了コード 77"],
])}
"""))
S.append(("ticket","セッションチケット(V2)",f"""
{bytes_layout([("magic",8,MAGIC,"bl-hdr"),("created",8,"u64 BE 秒","bl-int"),("leaf_sha256",32,"証明書の pin","bl-str"),("session",None,"quiche の session blob","bl-body")],caption="図 1. チケットファイルのレイアウト。長さプレフィクスはなく、残り全部が session")}
{table(["項目","規定"],[
 ["ファイル名","<code>&lt;host_port&gt;.ticket</code>。<code>host_port</code> の <code>:</code> <code>/</code> <code>&#92;</code> <code>[</code> <code>]</code> は <code>_</code> に置換"],
 ["書込","同一ディレクトリの temp(pid + 連番)に書き 0600 にして rename"],
 ["TTL","24 時間。<code>created</code> が未来(5 分超)または期限切れなら破棄"],
 ["pin 検査","接続後の leaf SHA-256 が <code>leaf_sha256</code> と異なれば破棄して警告"],
 ["保存条件","<code>zero_rtt = true</code> かつ CA / システムルート検証モード(TOFU / insecure では保存しない)"],
 ["旧形式","<code>QFT1</code>、ヘッダなしの blob は読まずに削除"],
])}
"""))
S.append(("misc","その他の規則",f"""
{table(["項目","規定"],[
 ["アップロード temp","<code>&lt;final&gt;.qftp.partial</code>(同じディレクトリ)。<code>TempName::is_temp</code> が唯一の判定。Ls 非表示、Get / Rm / Rename / Put の対象名として拒否(<code>PermissionDenied</code>)。起動時に 24 時間超のものを掃除"],
 ["Ls カーソル","<code>base64url(最後に返したエントリ名)</code>(ADR-008)。パディングなし。復号不能・ソート順に矛盾は <code>Malformed</code>"],
 ["永続自己署名","<code>cert.pem</code> / <code>key.pem</code>(ECDSA P-256、有効期間 1 年、SAN = localhost + bind アドレス)。期限切れ・解析不能なら再生成し、fingerprint をログに出す"],
 ["履歴","1 行 1 コマンド、UTF-8、最大 10,000 行(超過は古い順に削除)。失敗したコマンドも記録"],
 ["設定の秘密","config.toml に鍵を書く仕組みはない(パスのみ)。<code>--check-config</code> の出力にもパスだけが載る"],
])}
"""))
page("ファイル形式リファレンス","参照文書","作成日: 2026-09-03 / 対象: users.toml、tokens.toml、known_hosts、セッションチケット、temp と補助ファイル",S,OUT)
