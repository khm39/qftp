# プロトタイプ実装の評価(現行挙動の棚卸し)

作成日: 2026-09-03 / 対象: プロトタイプリポジトリ `khm39/qftp` のコミット `ac73b20`(参照用。本パッケージはこの文書だけで読めるよう書かれており、旧リポジトリを開く必要はありません)

本書は、プロトタイプとして育ってきた現在の `qftp` リポジトリの**挙動としての仕様**を、コードから逆引きして一冊に集約したものです。新規プロジェクトを起こす際の「何を引き継ぎ、何を捨てるか」の判断材料を目的としています。

正本の扱いは次のとおりです。

- **ワイヤプロトコル**は本パッケージの `10-protocol/`(仕様書とゴールデンベクタ)が正本であり、本書はプロトコルを要約しません。
- **サーバ / クライアント / Web ブリッジの挙動**は正本となる文書が存在しないため、本書がコードから起こした初版の仕様書になります。「実装がそうなっている」ことと「そうあるべき」ことを区別するため、疑わしい挙動は §9 の不整合一覧に分離しました。

---

## 1. プロジェクトの位置づけ

- FTP の置き換えを狙った、QUIC + TLS 1.3 上のファイル転送プロトコルおよびそのリファレンス実装(Rust)です。
- 1 本の QUIC コネクション上で、コマンドもファイル本体も独立ストリームに多重化します。
- 中核機能は、再開可能転送、BLAKE3 整合性検証、mTLS 認証、ユーザ単位の ACL / クォータ、0-RTT 再開、stateless retry、zstd 転送圧縮です。
- ワイヤバージョンは `qftp/1`(ALPN)。2026-05-30 に「ワイヤ凍結」を宣言済みですが、リリースタグは 1 つも存在せず、`0.1.0` はプレースホルダです。**実運用中の旧 peer は存在しない**前提で、圧縮拡張も凍結ベースラインに畳み込まれています。

### 1.1 リポジトリ構成(現状)

| パス | 役割 | 規模 |
|---|---|---|
| `spec/` | プロトコル仕様(正本)。本パッケージの `10-protocol/` に移植済み | 約 1,400 行 |
| `test-vectors/` | ゴールデンベクタ。本パッケージの `10-protocol/test-vectors/` に移植済み | 生成物 |
| `crates/qftp-common` | ワイヤ型・フレーミング・quiche 設定・UDP I/O・fs ヘルパ | 約 2,700 行 |
| `crates/qftp-protocol` | パスサンドボックス、メタデータ系ハンドラ、ユーザ / ACL / クォータ、転送ストリーム状態、zstd | 約 3,900 行 |
| `crates/qftp-server` | ネイティブサーバ(quiche + mio、単一スレッドイベントループ) | 約 5,700 行 |
| `crates/qftp-client` | ネイティブクライアント(REPL / one-shot / watch / sync / put-multi) | 約 8,200 行 |
| `crates/qftp-web-bridge` + `web/` | WebTransport ブリッジ(wtransport / quinn + tokio)と SPA | 約 2,900 + 1,600 行 |
| `crates/qftp-admin` | `users.toml` 編集 CLI | 約 850 行 |
| `crates/qftp-conformance` | ベクタ生成と適合テスト | 約 500 行 |
| `crates/qftp-bench` | criterion ベンチ + ネイティブ e2e テストのホスト | 約 800 行 |
| `fuzz/` | cargo-fuzz(別ワークスペース、nightly) | 3 ターゲット |
| `docs/adr/` | ADR 0001(quiche 継続)/ 0002(OS ユーザ分離、却下) | |

合計約 32,000 行。テスト数はクライアント 115、protocol 75、common 55、server 49、web-bridge 21、admin 15、bench 6、conformance 3 です。

---

## 2. プロトコル仕様

ワイヤプロトコルは本パッケージの `10-protocol/`(Markdown 仕様書とゴールデンベクタ)が正本で、図解版 `qftp-protocol-guide.html` があります。本書では要約しません。

---

## 3. サーバ(`qftp-server`)仕様

### 3.1 起動と CLI

設定ファイルや環境変数の等価物はなく、すべて `--flag` です(`RUST_LOG`、`XDG_STATE_HOME` / `HOME` のみ参照)。

| フラグ | 既定 | 備考 |
|---|---|---|
| `--bind` | `127.0.0.1:4433` | TLS 設定後に解釈されるため、不正値の検出が遅い |
| `--root` | `.` | canonicalize 必須 |
| `--cert` / `--key` | 必須(`--self-signed` 時を除く) | 鍵ファイルは owner-only かつ euid 所有(root 除く)を検査 |
| `--self-signed` | off | rcgen で `localhost` 用の一時証明書。`$TMPDIR` に PEM を残す |
| `--self-signed-persistent` / `--self-signed-state-dir` | off | `$XDG_STATE_HOME/qftp/self-signed` に保存、期限切れで再生成 |
| `--client-ca` | なし | 指定で mTLS 必須(証明書の**存在**はアプリ層で強制) |
| `--users` | なし | `users.toml`。未指定時は anonymous 1 名 |
| `--max-connections` / `--max-connections-per-ip` | 64 / 8 | per-ip は IPv4 /32、IPv6 /64 |
| `--rate-limit-rps` / `--rate-limit-burst` | 50 / 100 | 検証なし(0 で全拒否) |
| `--require-retry` | off | |
| `--metrics-bind` | なし | 非 loopback で警告 |
| `--log-format` | `text` | `json` 可。clap enum ではない |
| `--generate-completions` | | |

起動順: 引数 → tracing → root canonicalize → TLS(3 モード)→ ユーザディレクトリ(home 作成、24 h 超の `*.qftp.partial` 掃除、`walk_size` で使用量を同期プライミング)→ UDP bind(4 MiB バッファ要求)→ SIGINT/SIGTERM ハンドラ → metrics スレッド → イベントループ。

### 3.2 `users.toml`

```toml
[anonymous]                # 任意。省略時は root 直下・read-only・クォータなし
[[users]]
name = "alice"
home = "alice"             # 任意。相対は <root>/ 下、省略は <root>/<name>、絶対可
permissions = { read = true, write = true, delete = false, mkdir = false, rmdir = false, rename = false, chmod = false }
quota_bytes = 1000000      # 任意。0 は拒否
```

検証規則: 未知キー拒否、`..` を含む相対 home 拒否、root 外 home 拒否、**home の重複・入れ子拒否**(クォータカウンタが独立なため)、名前重複拒否。`--users` なしの anonymous は **read-only**(README / `--help` の「フル権限」記述は誤り、§9 参照)。

### 3.3 認証・identity

- mTLS 時、ハンドシェイク完了後に peer cert から候補(SAN dNSName → rfc822 → URI → CN、制御文字除去)を抽出し `users` に照合。不一致は QUIC close `0x101`、複数ユーザに一致は `Ambiguous` で拒否。anonymous への格下げはしません。
- `--client-ca` なしでは全接続が anonymous。`ErrorCode::Unauthorized` はサーバから送出されることがありません。

### 3.4 ACL とクォータ

- `Op` = Read / Write / Delete / Mkdir / Rmdir / Rename / Chmod。`Ls` / `Stat` / `Get` → Read、`Put` → Write、他は同名。**`Cd` / `Pwd` / `Quota` / `Quit` は権限不要**。未知 `Request` は fail-closed。
- クォータは `used_bytes + in_flight_bytes` の reserve-before-check 方式。`Rm` / `Rename` は `quota_aware_*` で減算。中断した Put の partial は `used_bytes` に残高計上され、再開または上書きまで消費扱い。
- `Quota` 応答の `file_count` はサーバ・ブリッジとも **0 固定**(起動時の `walk_size` で数えた値は保持していない)。

### 3.5 接続ライフサイクル

1. Initial: DCID 長 8..=20 検査 → per-IP トークンバケット → (`--require-retry`)retry トークン発行 / 検証(`"qftp1" || mint_secs || ip || port || dcid_len || dcid || HMAC-SHA256[..16]`、有効 60 s、アドレス一致)→ 接続スロット取得 → SCID 導出 → `quiche::accept`。
2. 未確立 5 s で reap。アイドル 30 s で切断。
3. 要求ごと: レート制限 → 0-RTT ゲート → ACL → デコード検証(パス 4 KiB 等)。
4. メタデータ系(Ls / Stat / Mkdir / Rm / Rename / Chmod / Cd / Pwd)は 4 スレッドの `HandlerPool` に委譲(接続ごと 1 件 in-flight)。**Get / Put のディスク I/O、open、flush はイベントループスレッド上で実行**(HOL の原因)。
5. シャットダウン: フラグ → 全接続に `close(0x00,"server shutdown")` → 新規 Initial 無視 → マップが空になるまで待機(ハード期限なし)。

### 3.6 転送状態機械

- Get: `start_get`(partial 名拒否 → resolve → 祖先 symlink 再検査 → `O_NOFOLLOW|O_NONBLOCK` open → regular / ≤1 GiB / `offset ≤ len` 検査 → 圧縮判定 ≥1024 B かつ非既圧縮拡張子)→ Phase 0 プレフィクス再ハッシュ(チャンク/ティック)→ Phase A 本体(identity は `seek_relative` 巻き戻し、zstd はエンコーダ pending 消化)→ Phase B トレーラ → FIN。**途中失敗は `Err` を送らず bare FIN**。
- Put: `start_put`(検証必須形の拒否、`resolve_parent`、`no_clobber` lstat、`UploadClaim`、temp open 0600、再開時は長さ一致検査と `ResumeRehash`、クォータ予約)→ rehash phase → Phase A 受信(identity は body/trailer/overflow 分類、zstd はデコーダ境界)→ Phase B トレーラ → チェックサム解決 → 祖先再検査 → `no_clobber` 再検査 → rename → mode 適用 → `Ok`。
- 中断時の会計は `StreamState::Drop` が担当(予約解放、書き込みフラッシュ、書けた分を `used_bytes` に計上、partial は残す)。

### 3.7 メトリクス / healthz

ラベルなしカウンタ・ゲージ 15 個(`qftp_connections_open`、`qftp_connections_total`、`qftp_connections_rejected_{caps,rate}_total`、`qftp_initials_dropped_bad_dcid_total`、`qftp_retries_issued_total`、`qftp_bytes_{received,sent}_total`、`qftp_requests_{,failed_,rate_limited_}total`、`qftp_{uploads,downloads}_completed_total`、`qftp_zero_rtt_{accepted,rejected}_total`)。HTTP/1.1 を手書き(GET のみ、200 ms スリープポーリング、32 接続上限)。`/healthz` は無条件 `ok`。

---

## 4. クライアント(`qftp-client`)仕様

### 4.1 起動形態

```
qftp-client [FLAGS] [TARGET]                # REPL / -e / --batch
qftp-client [FLAGS] <SUBCOMMAND> ...        # one-shot
```

`TARGET` は `qftp://[user@]host[:port][/path]`(`qftps://` 同義)またはエイリアス名。省略時は `127.0.0.1:4433`、SNI `localhost`。パスワード付き URL は拒否。`user@` は解釈されますが未使用です。

### 4.2 グローバルフラグ

`--config`(既定 `~/.qftp/config.toml`)、`--host`、`--server-name`、`--ca`、`--insecure`、`-T/--trust-on-first-use`、`--known-hosts`、`--no-zero-rtt`、`--session-ticket-dir`、`--client-cert` / `--client-key`(相互必須)、`-q`、`-v`(重ね可)、`--bwlimit`(アップロードのみ、K/M/G/Ki/Mi/Gi)、`--no-compress`。REPL 専用: `-e/--execute`(反復可)、`--batch`(非 TTY で自動)、`--history`(既定 `~/.qftp_history`)、`--generate-completions`。

優先順位: 組込既定 < alias.endpoint < alias 明示フィールド < コマンドライン URL < CLI フラグ。

### 4.3 設定ファイル

```toml
[host.<alias>]
endpoint = "qftps://[user@]host[:port][/path]"
host = "..."; port = 4433; server_name = "..."; user = "..."
insecure = false; ca = "~/x.pem"; client_cert = "~/c.pem"; client_key = "~/k.pem"
initial_path = "/dir"
```

`[host.*]` 以外のセクションはありません(グローバル既定なし)。未知キーはエラー。

### 4.4 サーバ検証モード

| モード | チェーン検証 | ホスト名検証 | ピン留め | 0-RTT |
|---|---|---|---|---|
| 既定 | システム / `--ca` | あり(RFC 6125 相当、ハンドシェイク後に自前実装) | なし | 有効 |
| `-T`(`--ca` なし) | なし | なし | leaf SHA-256 を `~/.qftp/known_hosts` に自動追記(プロンプトなし)、不一致は SSH 風バナーで終了 | 無効 |
| `--insecure` | なし | なし | なし | 無効 |

`known_hosts` は `host:port sha256:<hex>` 1 行形式。TOFU は **REPL 経路でのみ有効**で、one-shot / sync / watch / put-multi では警告付きで無視されます。

### 4.5 セッションチケット(0-RTT)

`~/.qftp/session-tickets/<host_port>.ticket`(0600、原子的書込)。V2 形式 = `QFT2\0FP\n` + unix 秒 + leaf SHA-256 + quiche session blob。TTL 24 h。フィンガープリント不一致で破棄。保存タイミングは REPL 正常終了 / one-shot / sync / put-multi(watch は保存しない)。クライアントは 0-RTT で**アプリケーションデータを送りません**(再開ハンドシェイクのみ)。

### 4.6 REPL コマンド

`ls|dir [path]`、`cd [path]`、`pwd`、`get [-r] <remote> [local]`、`put|mput [-r] <local-glob> [remote]`、`mget <remote-glob> [local-dir]`、`mkdir`、`rmdir`、`rm|delete`、`rename|mv`、`chmod <octal> <path>`、`stat`、`quota`、`lcd`、`lpwd`、`lls`、`lmkdir`、`!cmd`、`stats`、`help`、`quit|exit`。

- 行は空白分割のみ(クォート非対応、空白を含むパス不可)。
- `get` は既存ローカルファイル長から自動再開。`get -r` は BFS(上限 10,000 ディレクトリ)、既存ローカル名はスキップ。
- `put` はローカル glob 展開、`.qftp.partial` を `Stat` して再開。`put -r` は symlink をスキップ、`Mkdir` エラー無視。
- `ls` は**ページネーションカーソルを追いません**。
- 補完は先頭語とローカルファイル名のみ。
- バッチ / `-e` はコマンド失敗で継続し、終了コードは常に 0(トランスポートエラーのみ 1)。

### 4.7 one-shot サブコマンド

`put <REMOTE> <LOCAL>...`、`get <REMOTE> [LOCAL]`(両者 `-n/--no-clobber`、`-f/--force`、`-i/--interactive`、`--dry-run`、`-r` は未実装エラー)、`ls`、`stat`、`rm`、`mkdir`、`rmdir`、`rename <FROM> <TO>`、`watch`、`sync`、`put-multi`。リモート引数は URL または `alias[:/path]`。

終了コード: 0 / 64(usage、`Malformed`)/ 65(転送・その他)/ 77(`Unauthorized` / `PermissionDenied`)。ただし `anyhow` 経由の失敗(URL 不正、接続失敗、TOFU 不一致)は 1 で終了し、sysexits 規約は部分的にしか守られていません。

### 4.8 watch / sync / put-multi

- `watch <local-dir> <url> [--debounce-ms 200]`: `notify` で再帰監視、イベントを合体して `Put` / `Rm`。ディレクトリ作成は反映しません(`Mkdir` なし)。再接続バックオフ 1→30 s。設定ファイルのエイリアス・CA は無視(空 config で解決)。常に終了コード 0。
- `sync <local-dir> <url> [--delete] [--checksum] [--dry-run]`: ローカル→リモート一方向。`.qftpignore`(ルート直下のみ、否定なし)。差分判定はサイズと mtime(±2 s)。**`--checksum` は常に全件再アップロードするスタブ**。削除は全アップロード成功時のみ。常に終了コード 0。
- `put-multi <LOCAL> <REMOTE_PATH> --to h1,h2 [--strict]`: ホストごとに OS スレッドで並列 `put`。BLAKE3 は各スレッドで再計算。

### 4.9 転送クライアント側

- Get: `accept_encoding=[Zstd]`(`--no-compress` で空)、`size + offset == total_size` 検査、`O_NOFOLLOW` open、再開時はローカルプレフィクスをハッシュ、トレーラ不一致でローカル削除、`InvalidRange` 再開失敗は 0 から 1 回再試行。
- Put: 1 MiB チャンク、トークンバケット pacer、圧縮は ≥1024 B かつ非既圧縮拡張子、`checksum_trailer=true` 固定、`Unsupported`(zstd)なら Identity で全量再送、`ChecksumMismatch|InvalidRange`(再開時)は呼び出し側が 0 から再試行。ヘッダ送出後に応答を待たないため、`PermissionDenied` は本体送信後に判明します。
- グローバル状態: `QUIET`、`BW_LIMIT_BPS`、`COMPRESSION_DISABLED`、統計カウンタが process-wide の atomics。

---

## 5. Web ブリッジ(`qftp-web-bridge` + `web/`)仕様

### 5.1 アーキテクチャ

- WebTransport(HTTP/3)を `wtransport 0.7`(quinn + tokio)で終端する**独立バイナリ**。`qftp-server` にプロキシせず、`qftp-protocol` を直接駆動して同じ `--root` / `users.toml` を共有します。クォータカウンタはプロセスごとに独立(サーバと合算されない)。
- 1 WebTransport 双方向ストリーム = 1 `Request`、ワイヤは qftp/1 と同一。**各ストリームの cwd は home で初期化され破棄される**ため `Cd` は効きません。
- SPA は手書き HTTP/1.1(GET のみ、`Connection: close`)で `--http-bind`(既定 `127.0.0.1:8080`)から配信。ルート: `/`、`/app.js`、`/blake3.js`、`/style.css`、`/config.json`(`{certHash, webtransportPort}`)。
- ワークスペース内に quiche と quinn の 2 スタックが併存し、ブリッジのみ MSRV 1.88(他は 1.85)。

### 5.2 CLI と認証

`--cert` / `--key`(必須)、`--bind`(`0.0.0.0:4433`)、`--root`、`--users`、`--users-tokens`、`--http-bind`、`--allowed-origins`。固定値: セッション 256、ストリーム/セッション 64、認証タイムアウト 10 s、keepalive 15 s。

- `tokens.toml`: `[[tokens]] token = "..."; user = "alice"`。平文保存、期限なし、失効は再起動。トークンは WebTransport URL のクエリ(`?token=`)で運ばれ、定数時間比較。失敗回数制限なし。
- Origin ポリシー: 未設定 → ヘッダなし(非ブラウザ)は許可、ブラウザはトークン認証時のみ、anonymous では拒否。`*` → 全許可。リスト → 正規化完全一致のみ。

### 5.3 転送

- Get: 常に Identity(`accept_encoding` 無視)、`offset` / `length` 対応、トレーラは常に付与(プレフィクス再ハッシュ)。
- Put: **`offset` は 0 のみ**(再開非対応)、zstd は `Unsupported`、`no_clobber` / クォータ / `UploadClaim` / チェックサム(トレーラ優先)/ 原子 rename に対応。
- `Quota` は `file_count: 0` 固定。`Quit` はストリームを閉じるだけ。

### 5.4 SPA(`web/app.js`)

- bincode 互換の codec を JS で手書き(全 13 Request / 7 Response、`Err.details` と `FileReady` の `encoding` 系は未デコード)。
- 純 JS BLAKE3(メインスレッド)。ダウンロードは**全量をメモリに蓄積**して検証後 Blob 化(最大 1 GiB)。
- 画面: 非対応 / ログイン / ブラウザ(Up、パス、New folder、Refresh、Disconnect、D&D アップロード、進捗、Rename / Delete)。Ls ページネーションは追従。`Stat` / `Chmod` / `Quota` / 範囲 Get / キャンセルは未露出。
- 証明書ピン留めは `/config.json` の `certHash` に**どんな失敗でも**フォールバック。

### 5.5 デプロイ例

docker-compose(server: UDP 4434、bridge: UDP 4433 + HTTP 8080、nginx: TLS 8443 → 8080)。自己署名は ECDSA P-256 かつ 14 日以内(ブラウザの `serverCertificateHashes` 制約)。nginx は静的ページのみ中継し、WebTransport は中継しません。

---

## 6. 管理 CLI(`qftp-admin`)

`--users <path>`(既定 `/etc/qftp/users.toml`)配下に `init-users`、`add-user <name> [--home] [--read=true] [--write ...]`、`remove-user`、`list-users`、`set-permissions <name> --read <bool> ...`、`set-quota <name> --bytes N | --unlimited`、`generate-completions`。`toml_edit` でコメントを保持し、権限キーは `PERM_KEYS` 順で安定出力。temp + rename の原子書込(結果ファイルは 0600)。`[anonymous]` セクションと `tokens.toml` は扱えません。

---

## 7. 運用・ビルド・検証基盤

- **CI**(`ci.yml`): stable のみ。fmt / clippy `-D warnings` / build / `test --workspace --all-targets`(**criterion ベンチが 1 GiB スイープをテストモードで実行**)/ ベクタ再生成 diff ゲート / Node で JS テスト。`cargo-deny`(advisories, licenses, sources, bans)+ `cargo-audit`(重複)。カバレッジは `--lib` のみ、閾値なし。MSRV ジョブなし、Linux 以外なし。
- **release.yml**: `v*` タグで test → 4 ターゲット(x86_64 / aarch64 × linux-gnu / darwin)tarball + `.sha256` → cargo-deb(Linux 2 種)→ GitHub Release。署名 / SBOM なし。コメントや README は cargo-dist と記載(実態は手書き)。タグは未発行。
- **soak.yml**: dispatch のみ、`--users` なしで put/get ループ、RSS / FD を表示するだけ(アサートなし)。
- **fuzz**: 別ワークスペース(nightly)。`request_deser` / `response_deser` / `walk_safe`。zstd デコード、TOML、ブリッジのトークン / origin 解析、JS codec は未対象。
- **bench**: `qftp-bench` が release バイナリを**ネストした cargo build**で用意し、サブプロセスで REPL を叩く。64 KiB を繰り返した高圧縮ペイロード(SFTP 比較スクリプトは `/dev/urandom`)。失敗も計測値に混入。
- **e2e**: ネイティブ経路の e2e はベンチクレート内の 6 テストのみ(0 バイト往復、ホスト名接続、Get / Put 再開 3 種、多チャンク再開)。サーバ側は `stream_reset_dos` 1 本、ブリッジは Rust wtransport クライアントによる 1 ファイル。
- **パッケージ**: Dockerfile(distroless、`qftp-admin` 未同梱、既定 CMD が証明書引数なしで起動失敗)、systemd unit(`/usr/local/bin` 前提、deb は `/usr/bin`)、docker-compose(server に `--client-ca` なしで alice / bob へ到達不能)。
- **ADR**: 0001 quiche + mio 継続(理由: 書き直しコスト、依存の小ささ、単一スレッドの予測性。代償: 手書き多重化・状態機械、HTTP/3 なし)。ブリッジは別プロセスで quinn。0002 OS ユーザ分離は実装後に却下(root 相当コンポーネント追加、仮想ユーザ方針と矛盾)。

---

## 8. セキュリティモデル(`10-protocol/security-model.md` の要約)

- 信頼の根は QUIC + TLS 1.3(quiche / BoringSSL)。mTLS が認証プリミティブ。
- 公開インターネット想定: spoofing → `--require-retry`、flood → 接続上限 + per-IP レート制限、fuzz でデコーダ堅牢化。
- パストラバーサルは構造的に不可能(コンポーネント逐次解決、symlink 全拒否)。ただしプロセスはサンドボックスではなく、専用非特権ユーザで動かす前提。
- TOFU は SSH と同じ「初回が傍受されない」仮定。検査はハンドシェイク後。
- Web ブリッジは別トラストバウンダリ: mTLS なし、URL クエリのベアラトークン(中継機器のログ漏洩リスク)、ブラウザ信頼証明書必須、anonymous は read-only、WebTransport は CORS 対象外なので `--allowed-origins` が唯一の防御。
- BLAKE3 は完全性のみで真正性ではない(MAC は qftp/2)。
- 圧縮: 本体のみ・ファイルごと独立フレームで CRIME / BREACH 非適用。伸長爆弾は平文出力カウンタと窓上限で防御。
- ハードニング: `--require-retry`、接続上限、`--client-ca` + `--users`、専用ユーザ(`DynamicUser=`)、`--root` 限定、metrics は loopback、JSON ログ。

---

## 9. 既知の不整合・未実装・構造的問題(引き継ぎ判断用。ファイル名はプロトタイプ内の位置を示す参考情報で、読解に旧リポジトリは不要です)

### 9.1 仕様と実装の乖離

| # | 項目 | 現状 | 影響 |
|---|---|---|---|
| G1 | Ls ページネーション | ワイヤに `cursor` / `next_cursor` はあるがサーバは常に `None`、100,000 超は `Internal` で**一覧不能** | 大ディレクトリが扱えない。クライアントもカーソルを追わない |
| G2 | anonymous 既定権限 | コードは read-only、README / `--help` は「フル権限」 | soak / bench の前提が食い違う |
| G3 | ブリッジの `Cd` | `Ok` を返すが cwd は保持されない | 仕様違反(cwd はコネクション状態) |
| G4 | ブリッジの Put 再開・圧縮 | `offset>0` と zstd を `Unsupported` | ネイティブと機能差 |
| G5 | `Quota.file_count` | サーバ・ブリッジとも 0 固定 | ワイヤにあるフィールドが常に無意味 |
| G6 | Get 途中失敗 | `Err` なしの bare FIN | クライアントは短い本体とトレーラ欠落として観測 |
| G7 | 0-RTT 再試行 | クライアントの `Unsupported` ヒント文は自動再試行を謳うが未実装(そもそも early data を送らない) | 表示と実態の不一致 |
| G8 | `HashAlgorithm` の agility | `TrailerBuf` は 32 バイト固定、`digest_len()` は未使用 | 将来の追加時に破綻 |
| G9 | `#[serde(default)]` | bincode では無効なのに多数付与、`ErrorDetails` の `#[non_exhaustive]` も互換性を与えない | 誤った互換性の印象 |
| G10 | test-vectors/README | Put checksum が `[u8;32]`、Get の順序に `accept_encoding` なし | 文書の陳腐化 |
| G11 | 検証応答 | `validate_response` が `safe_entry_name` を強制せずクライアント任せ | 実装ごとの防御漏れ |
| G12 | `.qftp.partial` 規則 | `temp_path_for` / `is_upload_temp` / sweep の 3 箇所で微妙に異なる | 裸の `.qftp.partial` が Ls 非表示・削除不能・未掃除 |
| G13 | `Cd` が無権限で可能 | 権限ゼロのユーザでもディレクトリ存在を探れる | 情報漏洩(軽微) |

### 9.2 構造的問題(新設計で解消すべきもの)

1. **2 つの QUIC スタック**(quiche + mio / quinn + tokio)と MSRV の分裂。転送ドライバはブリッジ側で再実装され、状態(`StreamState`)は protocol クレート、遷移はサーバクレートに分かれています。
2. **ワイヤ型クレートが QUIC スタックを抱える**(`qftp-common` が quiche / mio / libc に依存)。conformance、admin、fuzz まで BoringSSL をビルドします。未使用依存(blake3、anyhow)もあります。
3. **サーバ**: `server.rs` 1,865 行、`start_put` 430 行、`drive_put` 373 行。Get / Put のディスク I/O がイベントループ上で実行され、遅いディスクが全接続を止めます。Initial と要求のレート制限が同一バケット。identity-path の Put 失敗は temp を残し zstd-path は削除する、など経路によってクリーンアップ規則が異なります。
4. **クライアント**: `main.rs` 1,296 行に REPL 実行ロジックが集中。Quit + チケット保存が 4 箇所、`Session` 構築が 5 箇所、URL→文字列→再解析が 3 箇所で重複。TOFU が REPL 限定。process-wide なグローバル状態。stdout / stderr と終了コードの規約が不統一。
5. **ブリッジ**: 手書き HTTP/1.1、JS の手書き codec(3 箇所のエラー表)、ダウンロード全量メモリ、平文トークン、失敗レート制限なし。
6. **テスト基盤**: e2e がベンチクレートに寄生し、`cargo test` 内で `cargo build --release` を実行。3 箇所に手書きのサブプロセスフィクスチャ。CI で 1 GiB ベンチが毎回走る。MSRV 未検証。fuzz がワークスペース外でロックファイルも別。
7. **仕様の所在**: プロトコルは `spec/` に集約された一方、サーバ / クライアント / ブリッジの挙動仕様は README とコードコメントに散在しています(本パッケージの設計書群がその代替です)。
8. **識別子の不統一**: `Rm` ↔ `Op::Delete` ↔ `permissions.delete`、`Put` ↔ `Op::Write`、`Response::Path` ↔ `Request::Pwd`、`FileStat` が構造体名と variant 名を兼ねる。エラーメッセージや doc コメントに Issue 番号・レビューサイクル名が埋め込まれ、テストがその文字列に依存。

### 9.3 文書・パッケージの不整合

README / `--help` の anonymous 権限、cargo-dist 記述、Dockerfile の既定 CMD と `qftp-admin` 欠落、systemd の binary パス、docker-compose の `--client-ca` 欠落、CHANGELOG の重複セクション、`web-client.md` の制約一覧(圧縮・`Cd` 未記載)。

---

## 10. 新規プロジェクトでの扱い

§9 の各項目は、本パッケージの設計書で次のように扱います。

| 項目 | 扱い |
|---|---|
| G1 Ls ページネーション | サーバ機能設計書で MVP に含める |
| G2 anonymous 権限 | read-only を正とし、文書側を修正 |
| G3 / G4 / G5 ブリッジの Cd・再開・圧縮・file_count | 転送エンジン共有とセッション状態保持で解消(Web ブリッジ機能設計書) |
| G6 Get 途中失敗 | 本体送出前は Err、送出後は reset_stream(転送エンジン設計書) |
| G7 0-RTT 再試行の表示 | クライアント機能設計書で挙動と表示を一致させる |
| G8 / G12 固定トレーラ長・temp 規則の重複 | 転送エンジン設計書のビジネスルールで単一化 |
| G9 / G10 serde(default)・ベクタ README | 手書き codec(ADR-003)と README 修正済み |
| G11 応答検証 | `qftp-wire::validate` で安全名検査を強制 |
| G13 Cd の権限 | read 権限の対象にする(サーバ機能設計書) |
| 構造的問題 1〜8 | アーキテクチャ設計書 §4・§6 と `30-plan/repository-layout.md` |
