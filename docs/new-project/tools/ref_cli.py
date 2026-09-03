from theme import page, table, code
from theme import ROOT
OUT=f"{ROOT}/40-reference/cli-reference.html"
S=[]
S.append(("conventions","共通規約",f"""
{table(["規約","内容"],[
 ["出力先","結果(一覧、統計、<code>--json</code>)は stdout。診断・警告・進捗バーは stderr。進捗バーは stderr が TTY のときだけ"],
 ["終了コード","sysexits 準拠(下表)。すべての経路(REPL / one-shot / batch)で同じ対応"],
 ["エラー文言","<code>qftp: &lt;動詞&gt; &lt;対象&gt;: &lt;理由&gt;</code>。理由は <code>ErrorCode</code> の名前と、あれば details(<code>InvalidRange: offset 10 &gt; size 5</code>)。サーバの <code>message</code> は <code>-v</code> のときだけ付記"],
 ["リモートパス","<code>qftp://[user@]host[:port]/path</code>、または <code>alias:/path</code>(<code>:</code> 以降省略時は <code>/</code>)。エイリアスは設定ファイルの <code>[host.*]</code>"],
 ["ローカルパス","REPL では <code>lcd</code> で変えたローカル cwd 基準。<code>~/</code> 展開。glob は <code>put</code> / <code>mput</code> のローカル引数のみ(クォートで抑止)"],
 ["クォート","REPL 行はシェル風に分割: 空白区切り、<code>'…'</code>、<code>&quot;…&quot;</code>、<code>&#92;</code> エスケープ。<code>!</code> 行は分割せず丸ごとシェルへ"],
 ["非 Unix","起動時に <code>qftp: unsupported platform</code> で終了コード 70(ADR-011)"],
])}
<h3>終了コード</h3>
{table(["コード","名前","いつ"],[
 ["0","OK","すべて成功"],
 ["64","EX_USAGE","引数 / URL / 設定ファイルの誤り、未知エイリアス、サーバの <code>Malformed</code>"],
 ["65","EX_DATAERR","転送失敗、サーバの 4xx / 5xx(下記以外)、チェックサム不一致、プロトコルエラー、batch の失敗あり"],
 ["69","EX_UNAVAILABLE","接続不能(全アドレス失敗、ALPN 不一致、アイドル切断)"],
 ["70","EX_SOFTWARE","内部エラー、非対応プラットフォーム"],
 ["74","EX_IOERR","ローカルファイル / 設定書込の I/O エラー"],
 ["77","EX_NOPERM","<code>Unauthorized</code>、<code>PermissionDenied</code>、mTLS 拒否(close 0x101)、TOFU 不一致"],
])}
"""))
S.append(("server","qftp-server",f"""
{code('''qftp-server [--config <path>] [フラグ…]
qftp-server --check-config [--config <path>] [フラグ…]
qftp-server --generate-completions <bash|zsh|fish|powershell>
qftp-server --version | --long-version''')}
<p>フラグと設定キーの対応表は設定リファレンス §2 にあります(多くは <code>limits.max_connections</code> → <code>--max-connections</code> のように末尾のキー名、一部は <code>tls.state_dir</code> → <code>--self-signed-state-dir</code> のように異なる)。フラグは設定ファイルの値を上書きします。終了コード: 0 正常終了(シグナルによる graceful を含む)、1 設定 / 起動失敗、2 実行時致命エラー(bind 喪失など)。</p>
{table(["シグナル","動作"],[["SIGTERM / SIGINT","graceful shutdown(新規拒否 → 転送完了待ち → <code>shutdown_timeout</code> で強制)"],["SIGHUP","将来: users.toml 再読込。コア区分では無視"]])}
"""))
S.append(("client-global","qftp-client: 起動形態とグローバルフラグ",f"""
{code('''qftp-client [フラグ…] [TARGET]                       # REPL(TARGET 省略時は 127.0.0.1:4433)
qftp-client [フラグ…] -e "<cmd>" [-e "<cmd>"…] TARGET  # コマンド列を実行して終了
qftp-client [フラグ…] --batch TARGET < script          # stdin から 1 行 1 コマンド(非 TTY なら自動)
qftp-client [フラグ…] <SUBCOMMAND> …                   # one-shot''')}
{table(["フラグ","引数","意味"],[
 ["<code>--config</code>","path","設定ファイル(既定 <code>~/.qftp/config.toml</code>)"],
 ["<code>--host</code>","host[:port]","接続先を上書き(IPv6 は <code>[::1]:4433</code>)"],
 ["<code>--server-name</code>","name","SNI とホスト名検証の名前"],
 ["<code>--ca</code>","path","CA バンドル。指定時は TOFU 無効"],
 ["<code>--insecure</code>","","証明書検証なし(開発用)。警告を出す"],
 ["<code>-T</code>, <code>--trust-on-first-use</code>","","TOFU。初回は対話で確認、非対話では拒否"],
 ["<code>--tofu-accept-new</code>","","非対話でも初回 pin を自動受理"],
 ["<code>--known-hosts</code>","path","既定 <code>~/.qftp/known_hosts</code>"],
 ["<code>--no-zero-rtt</code>","","チケットの再開を使わない(保存もしない)"],
 ["<code>--session-ticket-dir</code>","path","既定 <code>~/.qftp/session-tickets</code>"],
 ["<code>--client-cert</code> / <code>--client-key</code>","path","mTLS(対で必須)"],
 ["<code>--bwlimit</code>","rate","上下双方向の帯域上限(<code>1M</code>、<code>512Ki</code>)"],
 ["<code>--no-compress</code>","","zstd を使わない(Get の accept_encoding を空に、Put を Identity に)"],
 ["<code>--json</code>","","one-shot の結果を 1 行 JSON で stdout に出す(スキーマは §6)"],
 ["<code>-q</code> / <code>-v</code>(重ね可)","","警告のみ / info / debug / trace"],
 ["<code>-e</code>, <code>--execute</code>","cmd","REPL コマンドを実行して終了(反復可)"],
 ["<code>--batch</code>","","stdin から実行"],
 ["<code>--fail-fast</code> / <code>--no-fail-fast</code>","","batch / -e で最初の失敗で止める(既定 on)"],
 ["<code>--history</code>","path","既定 <code>~/.qftp_history</code>"],
 ["<code>--generate-completions</code>","shell",""],
])}
"""))
S.append(("oneshot","qftp-client: one-shot サブコマンド",f"""
{table(["サブコマンド","引数","オプション","動作"],[
 ["<code>ls</code>","REMOTE","<code>-l</code>(uid / gid / ナノ秒を追加)","全ページを取得して表示。temp(<code>*.qftp.partial</code>)はサーバが常に非表示"],
 ["<code>mget</code>","REMOTE_GLOB [LOCAL_DIR]","<code>-n</code>、<code>-f</code>","glob は最後のパス要素のみ。ディレクトリはスキップ"],
 ["<code>stat</code>","REMOTE","","1 件のメタデータ"],
 ["<code>get</code>","REMOTE [LOCAL]","<code>-r</code>(拡張区分)、<code>-n/--no-clobber</code>、<code>-f/--force</code>、<code>-i/--interactive</code>、<code>--dry-run</code>","LOCAL 省略時はリモートの basename。既存があれば上書き規則に従い、規則が「再開」なら自動再開"],
 ["<code>put</code>","LOCAL… REMOTE","同上","REMOTE が <code>/</code> で終わる、または LOCAL が複数ならディレクトリ扱い。partial があれば再開(<code>-f</code> は Stat を省略して 0 から)"],
 ["<code>mkdir</code> / <code>rmdir</code> / <code>rm</code>","REMOTE","",""],
 ["<code>rename</code>","FROM TO","","同一ホスト(同一 alias または同一 host:port)必須"],
 ["<code>chmod</code>","MODE REMOTE","","8 進"],
 ["<code>quota</code>","REMOTE(ホストのみ)","",""],
 ["<code>sync</code>(同期区分)","LOCAL_DIR REMOTE","<code>--delete</code>、<code>--dry-run</code>","ローカル → リモート一方向。<code>.qftpignore</code>。<code>--checksum</code> はない(ADR-010)"],
 ["<code>watch</code>(同期区分)","LOCAL_DIR REMOTE","<code>--debounce &lt;dur&gt;</code>","変更を反映(Mkdir を含む)。再接続バックオフ 1→30 s"],
])}
<h3>上書き規則(get / put 共通)</h3>
{table(["指定","既存ローカル(get)/ 既存リモート(put)","動作"],[
 ["<code>-n</code>","あり","スキップ(終了コード 0、stderr に skipped)。put は <code>no_clobber=true</code> をワイヤにも載せる"],
 ["<code>-f</code>","あり","0 から上書き(get はローカル削除、put は offset 0)"],
 ["<code>-i</code> または TTY","あり","<code>overwrite / resume / skip?</code> を尋ねる。resume は長さが小さいときのみ提示"],
 ["指定なし・非 TTY","あり","再開(get: ローカル長から、put: partial から)。再開できない(既存が完全 / 同サイズ)ならスキップ"],
 ["任意","なし","転送"],
])}
"""))
S.append(("repl","qftp-client: REPL コマンド",f"""
{table(["コマンド","構文","動作"],[
 ["<code>ls</code> / <code>dir</code>","<code>ls [-l] [path]</code>","全ページ取得。既定で mode / サイズ / mtime / 名前、<code>-l</code> で uid / gid / ナノ秒を追加"],
 ["<code>cd</code>","<code>cd [path]</code>","省略は <code>/</code>"],
 ["<code>pwd</code>","","仮想絶対パス"],
 ["<code>get</code>","<code>get [-r] [-n|-f] &lt;remote&gt; [local]</code>","one-shot と同じ規則。既定は確認(TTY)"],
 ["<code>put</code> / <code>mput</code>","<code>put [-r] [-n|-f] &lt;local-glob&gt;… [remote]</code>","複数一致時は remote をディレクトリ扱い(1 つの remote ファイルへ順に上書きしない)"],
 ["<code>mget</code>","<code>mget &lt;remote-glob&gt; [local-dir]</code>","glob は最後の要素のみ。ディレクトリはスキップ"],
 ["<code>mkdir</code> / <code>rmdir</code> / <code>rm</code> / <code>delete</code>","<code>&lt;path&gt;</code>",""],
 ["<code>rename</code> / <code>mv</code>","<code>&lt;from&gt; &lt;to&gt;</code>",""],
 ["<code>chmod</code>","<code>&lt;octal&gt; &lt;path&gt;</code>",""],
 ["<code>stat</code>","<code>&lt;path&gt;</code>",""],
 ["<code>quota</code>","",""],
 ["<code>lcd</code> / <code>lpwd</code> / <code>lls</code> / <code>lmkdir</code>","","ローカル側(プロセスの cwd は変えない)"],
 ["<code>!</code>","<code>!cmd…</code> / <code>!</code>","<code>$SHELL -c</code>(ローカル cwd で)。単独 <code>!</code> は対話シェル"],
 ["<code>stats</code>","","セッション統計(上下バイト、ファイル数、失敗数、平均速度)"],
 ["<code>help</code> / <code>?</code>","[cmd]",""],
 ["<code>quit</code> / <code>exit</code>","","<code>Quit</code> を送って終了"],
])}
<p>未知コマンドと引数不足は stderr に使い方を出し、REPL では続行、batch / <code>-e</code> では <code>fail_fast</code> に従います。転送中の Ctrl-C は現在のストリームを reset して <code>Quit</code> を送り、65 で終了します。</p>
"""))
JSONTAB=table(["サブコマンド","出力(1 行)"],[
 ["ls",'<code>{"entries":[{"name":"a","type":"regular","size":1,"mtime":"…","mode":420,"uid":0,"gid":0}],"truncated":false}</code>'],
 ["stat",'<code>{"type":"regular","size":1024,"mtime":"…","mode":420,"uid":0,"gid":0}</code>'],
 ["get / put",'<code>{"ok":true,"bytes":1024,"resumed_from":0,"encoding":"zstd","verified":true,"seconds":0.42}</code>'],
 ["quota",'<code>{"used_bytes":1,"file_count":2,"limit_bytes":null}</code>'],
 ["失敗時(全共通)",'<code>{"ok":false,"code":404,"error":"NotFound","details":null,"exit":65}</code>'],
])
S.append(("output","出力形式",f"""
<h3>ls(既定)</h3>
{code('''-rw-r--r--   1024  2026-09-03 12:34  report.pdf
drwxr-xr-x      -  2026-09-03 12:00  docs/
lrwxrwxrwx      -  2026-09-03 12:00  link -> (symlink)''')}
<p>列: mode(FileType を先頭 1 文字に反映)、サイズ(ディレクトリは <code>-</code>)、mtime(ローカル時刻、<code>YYYY-MM-DD HH:MM</code>)、名前(ディレクトリは <code>/</code> 付き)。<code>-l</code> で uid / gid とナノ秒を追加。エントリ名は端末エスケープを除去してから表示。</p>
<h3>stat</h3>
{code('''  path:  /docs/report.pdf
  type:  regular
  size:  1024
  mode:  0644
 mtime:  2026-09-03T12:34:56.123456789Z
   uid:  1000   gid: 1000''')}
<h3>--json(one-shot)</h3>
{JSONTAB}
<h3>ErrorCode → 終了コード</h3>
{table(["ErrorCode","終了コード","再試行"],[["Malformed","64","なし"],["Unauthorized、PermissionDenied","77","なし"],["NotFound、Unsupported、AlreadyExists、FileTooLarge、InvalidRange、NotADirectory、IsADirectory、ChecksumMismatch、UploadOverflow、UploadTruncated、QuotaExceeded、DecodeError","65","なし(StalePartial / UnsupportedEncoding の内部 1 回再試行を除く)"],["RateLimited","65(再試行後も失敗した場合)","<code>RetryAfter</code> 後に 1 回"],["Internal、Unknown(5xx)","65","なし(仕様の SHOULD_RETRY は満たさない。スクリプト側で制御)"],["Unknown(4xx)","65","なし"]])}
"""))
S.append(("admin","qftp-admin",f"""
{code('''qftp-admin [--users <path>] [--tokens <path>] [--mode <octal>] <SUBCOMMAND>
  init-users
  add-user <name> [--home <path>] [--read=<bool>] [--write] [--delete] [--mkdir] [--rmdir] [--rename] [--chmod] [--quota <size>]
  remove-user <name>
  list-users [--json]
  set-permissions <name> [--read <bool>] … [--chmod <bool>]
  set-quota <name> (--bytes <size> | --unlimited)
  set-anonymous (--home <path> [--read=<bool>] … | --remove)
  token add <user> [--label <text>]        # 平文トークンを 1 回だけ stdout に出す
  token revoke --user <user> (<label> | --all)
  token list [--json]
  check                                     # 両ファイルをサーバと同じ検証器で検証
  generate-completions <shell>''')}
<p>終了コード: 0 / 64 usage / 65 検証失敗(重複、未知ユーザ、home の入れ子など)/ 74 I/O。書込は同一ディレクトリの temp に書いて fsync し rename、モードは <code>--mode</code>(既定 0640。ファイル形式リファレンス §1 の配置に合わせる)。</p>
"""))
page("CLI リファレンス","参照文書","作成日: 2026-09-03 / 対象: qftp-server、qftp-client、qftp-admin",S,OUT)
