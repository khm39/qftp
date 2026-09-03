from theme import page, table, code
OUT="/tmp/claude-0/-home-user-qftp/96263040-8562-5047-8304-4e5f08fbf7fd/scratchpad/qftp-design/40-reference/config-reference.html"
S=[]
S.append(("precedence","優先順位と読み込み規則",f"""
{table(["プログラム","既定の設定ファイル","優先順位(高 → 低)"],[
 ["qftp-server","<code>/etc/qftp/server.toml</code>(<code>--config</code> で上書き。ファイルがなければ既定値のみ)","CLI フラグ &gt; 設定ファイル &gt; 組込既定"],
 ["qftp-client","<code>~/.qftp/config.toml</code>(<code>--config</code>)","CLI フラグ &gt; コマンドライン URL &gt; <code>[host.alias]</code> の明示キー &gt; <code>[host.alias].endpoint</code> &gt; <code>[defaults]</code> &gt; 組込既定"],
 ["qftp-admin","<code>/etc/qftp/users.toml</code>、<code>/etc/qftp/tokens.toml</code>(<code>--users</code>、<code>--tokens</code>)","CLI フラグのみ"],
 ["qftp-web-bridge(Phase 7)","<code>/etc/qftp/web-bridge.toml</code>","サーバと同じ"],
])}
{table(["規則","内容"],[
 ["未知キー","エラー(<code>deny_unknown_fields</code>)。綴り間違いを黙って無視しない"],
 ["パス","<code>~/</code> を展開。相対パスは設定ファイルのディレクトリ基準ではなく<strong>プロセスの cwd 基準</strong>(systemd では絶対パスを使う)"],
 ["サイズ表記","整数(バイト)または文字列 <code>&quot;10M&quot;</code>(K / M / G = 10 の累乗、Ki / Mi / Gi = 2 の累乗)"],
 ["時間表記","文字列 <code>&quot;30s&quot;</code>、<code>&quot;5m&quot;</code>、<code>&quot;1h&quot;</code>"],
 ["環境変数","<code>RUST_LOG</code>(tracing フィルタ、設定の <code>log.level</code> より優先)、<code>HOME</code> / <code>XDG_STATE_HOME</code>(既定パス)。設定値を環境変数で上書きする仕組みは持たない"],
 ["<code>--check-config</code>","ファイルとフラグを読んで検証し、正規化した有効設定を TOML で stdout に出力して終了(0 = OK、1 = エラー)。秘密は含まない"],
])}
"""))
S.append(("server","qftp-server: server.toml",f"""
{code('''# /etc/qftp/server.toml — 全キーを既定値つきで示す(省略可能)
bind = "127.0.0.1:4433"          # UDP。必須ではないが本番では 0.0.0.0 / [::] を明示
root = "/srv/qftp"               # 必須。canonicalize される
users = "/etc/qftp/users.toml"   # 省略時は anonymous(read-only)のみ
require_retry = false
metrics_bind = "127.0.0.1:9090"  # 省略時は無効
shutdown_timeout = "30s"

[tls]
cert = "/etc/qftp/server.crt"    # self_signed = false のとき必須
key = "/etc/qftp/server.key"     # owner-only(0600 / 0400)かつ euid 所有
client_ca = "/etc/qftp/ca.crt"   # 指定すると mTLS 必須
self_signed = false
self_signed_persistent = false   # self_signed = true のときのみ有効
state_dir = "$XDG_STATE_HOME/qftp/self-signed"

[limits]
max_connections = 64
max_connections_per_ip = 8
initial_rate_rps = 50.0
initial_rate_burst = 100.0
request_rate_rps = 50.0
request_rate_burst = 100.0
max_file_size = "1Gi"
blocking_threads = 0             # 0 = CPU 数 × 2
max_streams_bidi = 4
idle_timeout = "30s"
half_open_timeout = "5s"
ls_page_entries = 10000
ls_page_bytes = "1Mi"

[log]
format = "text"                  # "text" | "json"
level = "info"                   # RUST_LOG が優先''')}
{table(["キー","型","既定","検証 / 備考","対応フラグ"],[
 ["<code>bind</code>","SocketAddr","<code>127.0.0.1:4433</code>","起動直後に解釈(TLS 生成前)","<code>--bind</code>"],
 ["<code>root</code>","path","必須","存在するディレクトリ。canonicalize","<code>--root</code>"],
 ["<code>users</code>","path","なし","ファイル形式リファレンス参照。読めなければ起動失敗","<code>--users</code>"],
 ["<code>require_retry</code>","bool","false","","<code>--require-retry</code>"],
 ["<code>metrics_bind</code>","SocketAddr","なし","非 loopback は警告","<code>--metrics-bind</code>"],
 ["<code>shutdown_timeout</code>","duration","30s","graceful の上限","<code>--shutdown-timeout</code>"],
 ["<code>tls.cert</code> / <code>tls.key</code>","path","必須(自己署名でない場合)","PEM。鍵は group / other ビットなし、euid 所有(root 除く)","<code>--cert</code> / <code>--key</code>"],
 ["<code>tls.client_ca</code>","path","なし","PEM バンドル。指定で mTLS 必須","<code>--client-ca</code>"],
 ["<code>tls.self_signed</code>","bool","false","<code>cert</code> / <code>key</code> と同時指定はエラー(プロトタイプは黙って自己署名を優先していた)","<code>--self-signed</code>"],
 ["<code>tls.self_signed_persistent</code>","bool","false","<code>self_signed = true</code> が必要","<code>--self-signed-persistent</code>"],
 ["<code>tls.state_dir</code>","path","<code>$XDG_STATE_HOME/qftp/self-signed</code>(なければ <code>~/.local/state/qftp/self-signed</code>)","0700 で作成","<code>--self-signed-state-dir</code>"],
 ["<code>limits.max_connections</code>","u32 ≥ 1","64","","<code>--max-connections</code>"],
 ["<code>limits.max_connections_per_ip</code>","u32 ≥ 1","8","IPv4 /32、IPv6 /64","<code>--max-connections-per-ip</code>"],
 ["<code>limits.initial_rate_rps</code> / <code>_burst</code>","f64 &gt; 0","50 / 100","Initial 用バケット","<code>--initial-rate-rps</code> / <code>--initial-rate-burst</code>"],
 ["<code>limits.request_rate_rps</code> / <code>_burst</code>","f64 &gt; 0","50 / 100","要求用バケット","<code>--request-rate-rps</code> / <code>--request-rate-burst</code>"],
 ["<code>limits.max_file_size</code>","size","1 GiB","≥ 1","<code>--max-file-size</code>"],
 ["<code>limits.blocking_threads</code>","u32","0(= CPU × 2)","tokio <code>max_blocking_threads</code>","<code>--blocking-threads</code>"],
 ["<code>limits.max_streams_bidi</code>","u32 ≥ 1","4","QUIC transport parameter","<code>--max-streams-bidi</code>"],
 ["<code>limits.idle_timeout</code>","duration","30s","","<code>--idle-timeout</code>"],
 ["<code>limits.half_open_timeout</code>","duration","5s","未確立接続の破棄","<code>--half-open-timeout</code>"],
 ["<code>limits.ls_page_entries</code> / <code>ls_page_bytes</code>","u32 / size","10000 / 1 MiB","1 ページの上限(entries ≤ 100000)","<code>--ls-page-entries</code> / <code>--ls-page-bytes</code>"],
 ["<code>log.format</code>","enum","text","<code>text</code> | <code>json</code>","<code>--log-format</code>"],
 ["<code>log.level</code>","string","info","tracing の EnvFilter 構文。<code>RUST_LOG</code> が優先","<code>--log-level</code>"],
])}
"""))
S.append(("client","qftp-client: config.toml",f"""
{code('''# ~/.qftp/config.toml
[defaults]
compress = true
bwlimit = "0"                      # 0 = 無制限。上下双方向
tofu = false                       # true で --trust-on-first-use 相当
tofu_accept_new = false            # 非対話でも初回 pin を自動受理
zero_rtt = true
ticket_dir = "~/.qftp/session-tickets"
known_hosts = "~/.qftp/known_hosts"
history = "~/.qftp_history"
fail_fast = true                   # batch / -e
connect_timeout = "8s"             # アドレスごとのハンドシェイク予算

[host.work]
endpoint = "qftps://files.work.example:4433/data"   # user@ / :port / /path を含められる
host = "files.work.example"        # endpoint より優先
port = 4433
server_name = "files.work.example" # SNI とホスト名検証
ca = "~/.qftp/work-ca.pem"
client_cert = "~/.qftp/work-cert.pem"
client_key = "~/.qftp/work-key.pem"
initial_path = "/data"
insecure = false
tofu = false
compress = true
bwlimit = "10M"''')}
{table(["キー","型","既定","備考"],[
 ["<code>[defaults].compress</code>","bool","true","<code>--no-compress</code> で false"],
 ["<code>[defaults].bwlimit</code>","size/s","0","<code>--bwlimit</code>"],
 ["<code>[defaults].tofu</code> / <code>tofu_accept_new</code>","bool","false / false","<code>-T</code> / <code>--tofu-accept-new</code>"],
 ["<code>[defaults].zero_rtt</code>","bool","true","<code>--no-zero-rtt</code> で false"],
 ["<code>[defaults].ticket_dir</code> / <code>known_hosts</code> / <code>history</code>","path","<code>~/.qftp/…</code>","対応フラグあり"],
 ["<code>[defaults].fail_fast</code>","bool","true","<code>--no-fail-fast</code>"],
 ["<code>[defaults].connect_timeout</code>","duration","8s","最後のアドレスは QUIC idle に委ねる"],
 ["<code>[host.*].endpoint</code>","URL","なし","<code>qftp://</code> / <code>qftps://</code>。パスワード付きは拒否。<code>user@</code> は将来用に保持"],
 ["<code>[host.*].host</code> / <code>port</code> / <code>server_name</code>","string / u16 / string","endpoint から","明示キーが endpoint に勝つ"],
 ["<code>[host.*].ca</code> / <code>client_cert</code> / <code>client_key</code>","path","なし","cert と key は対で必須"],
 ["<code>[host.*].initial_path</code>","string","なし","接続後に <code>Cd</code>"],
 ["<code>[host.*].insecure</code>","bool","false","true にできるだけで、CLI から false に戻す手段はない(<code>--insecure</code> は true のみ)"],
 ["<code>[host.*].tofu</code> / <code>compress</code> / <code>bwlimit</code>","","<code>[defaults]</code>","エイリアス単位の上書き"],
])}
<p><strong>解決の例</strong>: <code>qftp-client --bwlimit 1M work</code> は、<code>[defaults]</code> → <code>[host.work].endpoint</code>(host / port / server_name / initial_path)→ <code>[host.work]</code> の明示キー → フラグ <code>--bwlimit</code> の順に上書きされ、最終的に <code>bwlimit = 1M</code>、<code>initial_path = /data</code> になります。</p>
"""))
S.append(("admin","qftp-admin / qftp-web-bridge",f"""
{table(["プログラム","フラグ","既定"],[
 ["qftp-admin","<code>--users &lt;path&gt;</code>","<code>/etc/qftp/users.toml</code>"],
 ["qftp-admin","<code>--tokens &lt;path&gt;</code>","<code>/etc/qftp/tokens.toml</code>"],
 ["qftp-admin","<code>--mode &lt;octal&gt;</code>","0600(書込後のファイルモード)"],
])}
{code('''# /etc/qftp/web-bridge.toml(Phase 7)
bind = "0.0.0.0:4433"
http_bind = "127.0.0.1:8080"      # 開発用 SPA 配信。省略時は無効
root = "/srv/qftp"
users = "/etc/qftp/users.toml"
tokens = "/etc/qftp/tokens.toml"  # 省略時は anonymous(read-only)のみ
allowed_origins = ["https://files.example.com"]   # [] = 未設定、["*"] = 全許可

[tls]
cert = "/etc/qftp/server.crt"
key = "/etc/qftp/server.key"

[limits]
max_sessions = 256
max_streams_per_session = 64
auth_timeout = "10s"
auth_failures_per_ip = 10         # 1 分あたり
max_file_size = "1Gi"''')}
"""))
page("設定リファレンス","参照文書","作成日: 2026-09-03 / 対象: qftp-server、qftp-client、qftp-admin、qftp-web-bridge の設定ファイルとフラグ対応",S,OUT)
