DOC_TYPE="architecture"; TITLE="qftp システムアーキテクチャ"; FILENAME="architecture-qftp.html"
ANSWERS={
"overview.name":"<p>qftp(QUIC File Transfer Protocol)リファレンス実装 第 2 世代。ネイティブサーバ、ネイティブクライアント、管理 CLI、および(Web 区分の)ブラウザ向け WebTransport ブリッジを含みます。</p>",
"overview.purpose":"<p>凍結済みワイヤプロトコル <code>qftp/1</code> に準拠したリファレンス実装の全体設計です。対象はシステム全体(全バイナリと共有ライブラリ)で、ワイヤプロトコル自体は本書の対象外です(<a href=\"../10-protocol/README.md\">プロトコル仕様</a>を正本とします)。</p><p>本パッケージでは機能を次の 4 区分で表します。区分は実装順序ではなく、機能の集合とその依存関係を表す名前です。</p><table><tr><th>区分</th><th>含まれる機能</th><th>依存</th></tr><tr><td><b>コア</b></td><td>全 13 リクエスト、Get / Put(再開・BLAKE3・zstd)、Ls ページネーション、mTLS / users.toml / ACL / クォータ、0-RTT / retry / レート制限、TLS 3 モードと TOFU、metrics / healthz / JSON ログ、REPL と one-shot(単一ファイル操作)</td><td>—</td></tr><tr><td><b>拡張</b></td><td>再帰 get / put、mget、双方向 bwlimit、qftp-admin、systemd / Docker / release 成果物、ベンチ</td><td>コア</td></tr><tr><td><b>同期</b></td><td>sync、watch</td><td>コア、拡張</td></tr><tr><td><b>Web</b></td><td>qftp-web-bridge、SPA、tokens.toml</td><td>コア(転送エンジン共有)</td></tr></table>",
"overview.audience":"<p>実装を担当する開発者、レビュアー、および運用設計を行う担当者。</p>",
"overview.positioning":"<p>本設計パッケージの最上位文書です。下位に機能設計書(転送エンジン / サーバ / クライアント / Web ブリッジ)、シーケンス設計書(接続確立 / Get / Put)、運用設計書が並びます。上位にあたる要件は <code>00-background/decisions.md</code>(ADR)と本書 §2 の課題・成功指標で表します。管理 CLI と画面については設計書を持たず、参照文書(<code>40-reference/</code>)で規定します。</p>",
"business-context.problem":"<ul><li>プロトタイプは 8 クレート・約 32,000 行に成長し、QUIC スタックが 2 系統(quiche + mio と quinn + tokio)、転送ドライバが 2 実装、MSRV が 2 種類に分裂しています。</li><li>サーバの Get / Put ディスク I/O がイベントループ上で実行され、遅いディスクが全接続を停止させます(HOL)。</li><li>ワイヤに定義済みの Ls ページネーションが未実装で、10 万エントリ超のディレクトリが一覧不能です。</li><li>サーバ・クライアント・ブリッジの挙動仕様が文書化されておらず、README とコードコメントに散在しています。</li><li>e2e テストがベンチクレートに寄生し、<code>cargo test</code> 内で <code>cargo build --release</code> を実行するなど検証基盤が脆弱です。</li></ul>",
"business-context.stakeholders":"<table><tr><th>関係者</th><th>関心事</th></tr><tr><td>メンテナ(khm39)</td><td>読める大きさで仕様準拠の実装、安全に変更できる検証基盤</td></tr><tr><td>サーバ運用者</td><td>単一プロセス・非特権ユーザで動く、設定と監視が明快なサーバ</td></tr><tr><td>CLI 利用者</td><td>scp / sftp 感覚で使える REPL と one-shot、再開と整合性検証が自動で効くこと</td></tr><tr><td>他言語実装者</td><td>仕様書とベクタだけで実装できること(本パッケージが自己完結であること)</td></tr></table>",
"business-context.success-metrics":"<ul><li>ゴールデンベクタ全件で双方向一致(conformance 緑)。</li><li>プロトタイプの主要ユースケース(サーバ + CLI で Ls / Get / Put / 再開 / mTLS / 0-RTT / retry)が機能等価で動く。</li><li>実装行数がプロトタイプの半分程度(目安 15,000 行)、クレート数が 7 + fuzz に収まる。</li><li>単一 QUIC スタック(ネイティブ)・単一 MSRV・単一転送エンジン。</li><li>e2e がプロセス内フィクスチャで実行され、CI の所要時間がベンチに支配されない。</li></ul>",
"system-overview.context-diagram":"""<pre>
                 UDP/QUIC (ALPN qftp/1, TLS 1.3, mTLS 任意)
 [qftp-client] ────────────────────────────────────▶ [qftp-server] ──▶ ストレージルート
   REPL / one-shot                                        │              (per-user home)
   ~/.qftp/config.toml, known_hosts, session-tickets       │
                                                          ├──▶ users.toml (ACL / quota)
 [Prometheus] ◀── HTTP/1.1 /metrics /healthz ─────────────┘
 [qftp-admin] ──▶ users.toml(編集のみ、サーバとは無接続)

 (Web 区分) [ブラウザ SPA] ── WebTransport(HTTP/3) ──▶ [qftp-web-bridge] ──▶ 同じルート / users.toml
</pre><p>図中の外部要素はプロトコル仕様の範囲外です。<code>qftp-admin</code> はファイル編集ツールであり、サーバの実行時状態には触れません。</p>""",
"system-overview.components":"""<table><tr><th>クレート</th><th>役割</th><th>依存(qftp 内)</th></tr>
<tr><td><code>qftp-wire</code></td><td>ワイヤ型(Request / Response / ErrorCode …)、手書き codec、フィールド上限検証、定数。I/O・QUIC・FS・blake3 に依存しない葉クレート。<code>tests/conformance.rs</code> でゴールデンベクタを検証し、<code>examples/gen_vectors.rs</code> で再生成する</td><td>なし</td></tr>
<tr><td><code>qftp-core</code></td><td>パスサンドボックス、ユーザ / ACL / クォータ、メタデータ操作(Ls ページング等)、<b>sans-I/O 転送エンジン</b>(Get / Put の状態機械)、zstd、temp 名規則と掃除、X.509 からの identity 抽出、ベアラトークンと origin ポリシー(Web 区分と admin が共有)</td><td>wire</td></tr>
<tr><td><code>qftp-quic</code></td><td>quiche の設定(サーバ / クライアント)、TLS モード、stateless retry トークン、SCID 導出、0-RTT ポリシー、tokio(current_thread)上の quiche ドライバ(UDP 受送信、タイマー)、quiche ストリーム上のフレーム送受信、GSO 送信、接続上限・レートバケット</td><td>wire</td></tr>
<tr><td><code>qftp-server</code>(lib + bin)</td><td>設定、受付・identity 昇格、コネクション / ストリーム dispatch、転送エンジンのホスト(ファイル I/O は <code>spawn_blocking</code> / <code>tokio::fs</code>)、メトリクス、シャットダウン。<code>run(config)</code> をライブラリ関数として公開。<code>test-util</code> feature でプロセス内フィクスチャを公開し、<code>tests/</code> に e2e、<code>benches/</code> にベンチを置く(ADR-007)</td><td>core, quic</td></tr>
<tr><td><code>qftp-client-core</code>(lib)</td><td>Session API(connect / request / get / put)、サーバ信頼ポリシー(CA / TOFU / insecure)、セッションチケット、設定解決、再開ロジック、クライアント側エンジンのホスト</td><td>core, quic</td></tr>
<tr><td><code>qftp-client</code>(bin)</td><td>CLI、REPL(パーサ / コマンド / 補完)、one-shot、出力整形と終了コード。同期区分: sync / watch</td><td>client-core</td></tr>
<tr><td><code>qftp-admin</code>(bin)</td><td>users.toml / tokens.toml 編集 CLI</td><td>core(スキーマのみ)</td></tr>
<tr><td><code>fuzz</code></td><td>codec / パス解決 / zstd / 設定パーサのファズ(ワークスペース内、stable では check のみ)</td><td>wire, core</td></tr>
<tr><td><code>qftp-web-bridge</code>(Web 区分)</td><td>WebTransport 終端(wtransport、ADR-006)+ 同じ転送エンジンの tokio ホスト</td><td>core</td></tr></table>
<p>conformance は <code>qftp-wire</code> の tests / examples、フィクスチャ・e2e・ベンチは <code>qftp-server</code> の test-util feature / tests / benches に置き、独立クレートにしない(ADR-007)。Web 区分の <code>qftp-web-bridge</code> を加えると 8 クレート。境界の根拠は <code>30-repository/repository-layout.md</code> を参照。</p>""",
"system-overview.external-systems":"<ul><li>Prometheus 等のスクレイパ(<code>/metrics</code>、テキスト形式 0.0.4)。</li><li>ログ集約基盤(JSON ログ)。</li><li>PKI(サーバ証明書 / クライアント証明書の発行)。実装は PEM を読むだけで発行には関与しません。</li><li>systemd / Docker(プロセス管理)。</li></ul>",
"system-overview.data-flow":"""<ol><li>クライアントが QUIC 接続を確立(retry → ハンドシェイク → identity 解決)。</li><li>コマンドごとに双方向ストリームを 1 本開き、<code>Request</code> フレームを送る。</li><li>サーバはフレームを <code>qftp-wire</code> でデコードし、レート制限・0-RTT ゲート・ACL を通したうえで <code>qftp-core</code> に渡す。</li><li>メタデータ操作は tokio のブロッキングプール(<code>spawn_blocking</code>)で実行され、<code>Response</code> がストリームに返る。</li><li>Get / Put は sans-I/O エンジンがストリーム上のバイト列とブロッキングプールのファイル操作を仲介し、BLAKE3 トレーラで整合性を検証する。</li><li>メトリクスは QUIC ドライバタスクがカウンタを更新し、メトリクス HTTP タスクが読み出す(同一の current_thread ランタイム上)。</li></ol>""",
"technology-stack.choices":"""<table><tr><th>領域</th><th>採用</th><th>備考</th></tr>
<tr><td>言語</td><td>Rust(edition 2021、MSRV は単一。quiche の要求に合わせて決定)</td><td></td></tr>
<tr><td>QUIC / TLS</td><td><b>quiche</b>(BoringSSL)</td><td>ネイティブサーバ・クライアント共通。方針決定事項(決定事項 ADR-001)</td></tr>
<tr><td>ランタイム</td><td>tokio(<code>current_thread</code>)。ソケットと全 quiche 接続を 1 タスクが持ち、ファイル I/O は <code>spawn_blocking</code> / <code>tokio::fs</code></td><td>ブリッジ(wtransport)と同じランタイム。マルチスレッド化は必要になってから</td></tr>
<tr><td>ワイヤ符号化</td><td>手書き codec(bincode 不使用)</td><td>ADR-003</td></tr>
<tr><td>整合性 / 圧縮</td><td>blake3、zstd(level 3、window_log 23)</td><td>仕様の凍結値</td></tr>
<tr><td>証明書</td><td>rcgen(自己署名生成)、x509-parser(identity 抽出、SAN 検証)</td><td></td></tr>
<tr><td>CLI</td><td>clap(derive)、rustyline、indicatif</td><td></td></tr>
<tr><td>設定</td><td>TOML(serde + toml、toml_edit は admin のみ)</td><td></td></tr>
<tr><td>可観測性</td><td>tracing(text / JSON)、Prometheus テキスト形式(ライブラリは実装時に選定)</td><td></td></tr>
<tr><td>検証</td><td>cargo-fuzz、criterion、cargo-deny</td><td></td></tr></table>""",
"technology-stack.rationale":"""<ul><li><b>quiche</b>: 方針として指定されています。Cloudflare のエッジで実運用されている実績、依存グラフの小ささ、単一スレッドループでの予測可能なスケジューリングがプロトタイプの ADR-0001 で挙げられた理由であり、本設計でも維持します。プロトタイプの痛みは quiche 自体ではなく「転送状態機械とディスク I/O をイベントループに直書きしたこと」に由来するため、後述の sans-I/O エンジンとブロッキングプールで切り離します。</li><li><b>tokio(current_thread)</b>: quiche はソケットもタイマーも呼び出し側任せなので、mio でも tokio でも駆動できます。tokio を選ぶ理由は、自前の I/O ワーカープールと起床配管が <code>spawn_blocking</code> / <code>tokio::fs</code> に置き換わって実装量が減ること、ブリッジ(wtransport)と同じランタイムになること、将来ブリッジを同一プロセスに載せてクォータを共有する選択肢が開くことです。<code>current_thread</code> を選ぶのは、mio ループと同じ「1 スレッドが全接続を持つ」構造を保ち、接続状態にロックを持ち込まないためです。</li><li><b>手書き codec</b>: 仕様が bincode を非規範と明記しており、bincode 1.x は unmaintained(RUSTSEC-2025-0141)です。手書きにすると Rust 実装も他言語実装と同じ立場でベクタに従い、寛容デコード(末尾フィールド欠落の受理)も残りバイト長を見て自然に書けます。</li><li><b>sans-I/O エンジン</b>: 状態機械がソケットにもディスクにも触れないため、quiche ループ・tokio ブリッジ・純メモリのテストが同じコードを駆動できます。プロトタイプでブリッジが Get / Put を再実装せざるを得なかった原因を除きます。</li></ul>""",
"technology-stack.alternatives":"""<table><tr><th>代替案</th><th>棄却理由</th></tr>
<tr><td>quinn + tokio + rustls に統一</td><td>async fn で状態機械が簡潔になり、rustls の verifier で TOFU をハンドシェイク中に行える利点はあるが、方針として quiche が指定された。quiche でも sans-I/O 化により同等の分離が得られる</td></tr>
<tr><td>mio の単一スレッドループ + 自前 I/O ワーカープール(プロトタイプ方式)</td><td>依存は最小だが、ワーカー完了の起床配管(<code>mio::Waker</code>)と GSO 以外の I/O をすべて自前で持つ。ブリッジと別ランタイムになる。tokio の <code>current_thread</code> なら同じ構造をより少ないコードで得られるため不採用</td></tr>
<tr><td>tokio-quiche(quiche の非同期ラッパ)</td><td>0.19.1(2026-09 時点)、MSRV 1.88、Cloudflare の <code>foundations</code> に依存する重めのクレート。接続ごとにタスクを分けるマルチスレッド構造で配管が多い。マルチコアが必要になった時点で再評価</td></tr>
<tr><td>WebTransport を quiche で終端(同一プロセス)</td><td>quiche 0.29 の h3 は拡張 CONNECT まで対応するが WebTransport の振り分けを持たず、h3 モジュールが全双方向ストリームを HTTP/3 として解釈するため外側から足せない。HTTP/3 最小サブセットの自前実装は 2,000〜3,000 行規模で見送り(ADR-006)</td></tr>
<tr><td>bincode 2 系(互換設定)</td><td>同一バイト列は出せるが、仕様と実装の主従、寛容デコードの課題が残る</td></tr>
<tr><td>転送エンジンを async fn で書く</td><td>1 タスクが全接続をポーリング駆動する構造では、転送ごとの async fn を安全に待ち合わせる手段がない(await 中に他接続が止まる)。sans-I/O ならドライバ・ブリッジ・純メモリのテストが同一コードを駆動できる</td></tr>
<tr><td>OS ユーザ分離(setuid ワーカー)</td><td>プロトタイプで実装後に却下済み。root 相当コンポーネントの追加と仮想ユーザ方針の矛盾(ADR-004 として引き継ぐ)</td></tr></table>""",
"technology-stack.constraints":"<ul><li>ワイヤプロトコル <code>qftp/1</code> は凍結済みで変更しない。</li><li>QUIC スタックは quiche を基本とする(方針)。</li><li>quiche は BoringSSL の C/C++ ビルドを要するため、クロスビルド(aarch64-unknown-linux-gnu)は CI で常時検証する。</li><li>Web ブリッジは WebTransport を要し、quiche では終端できない(調査済み、ADR-006)。wtransport(quinn + tokio)を別バイナリで使う。</li><li>OS 対応は Linux / macOS。Windows は対象外で、非 Unix では起動時にエラー終了する(ADR-011)。</li></ul>",
"quality-attributes.performance":"<ul><li>単一接続の Get / Put スループットが 1 Gbps 級のリンクを飽和させること(プロトタイプの流量制御窓 16 MiB / 64 MiB を維持)。</li><li>ディスク I/O がイベントループをブロックしない(1 つの遅い転送が他接続の Ls 応答時間に影響しない)。</li><li>目標数値はベンチ(乱数ペイロード、圧縮あり / なし)で確定する。</li></ul>",
"quality-attributes.availability":"<ul><li>単一プロセス、冗長化なし(FTP サーバ相当)。可用性 SLO は運用設計書で決める(未記入)。</li><li>graceful shutdown: 新規接続拒否 → 転送完了待ち → ハード期限(既定 30 s)で強制終了。</li><li><code>/healthz</code> は受付ループの生存とシャットダウン状態を反映する。</li></ul>",
"quality-attributes.scalability":"<ul><li>単一のドライバタスクが全接続を持つ。CPU スケールアウトは複数プロセス(別ポートまたは UDP LB)で行う。SO_REUSEPORT による複数ループは QUIC の CID ルーティングと相性が悪く採らない。必要になれば DCID で振り分ける接続ごとのタスク分割(ADR-001)へ移行する。</li><li>ディスク I/O は tokio のブロッキングプール(設定 <code>limits.blocking_threads</code> で指定、既定は CPU 数 × 2)。</li><li>接続数は <code>max_connections</code> / <code>max_connections_per_ip</code> で明示的に上限を置く。</li></ul>",
"quality-attributes.security":"<p><a href=\"../10-protocol/security-model.md\">security-model.md</a> を全体方針とします。要点: TLS 1.3 が信頼の根、mTLS + users.toml が認証・認可、パスサンドボックス(symlink 全拒否)、retry / 接続上限 / レート制限、0-RTT identity gate、BLAKE3 は完全性のみ、伸長爆弾は平文出力カウンタで防御、専用非特権ユーザで実行。</p>",
"quality-attributes.operability":"<ul><li>設定は TOML ファイル + フラグ上書き。<code>--check-config</code> で起動せず検証。</li><li>ログは text / JSON、メトリクスは Prometheus。</li><li>systemd unit と Docker イメージを同梱し、パスやユーザを一致させる。</li><li><code>qftp-admin</code> で users.toml / tokens.toml を安全に編集。</li></ul>",
"decisions.key-decisions":"""<table><tr><th>ID</th><th>判断</th></tr>
<tr><td>ADR-001</td><td>ネイティブサーバ / クライアントの QUIC スタックは quiche、ランタイムは tokio(<code>current_thread</code>)</td></tr>
<tr><td>ADR-002</td><td>Get / Put の転送エンジンは sans-I/O の状態機械として <code>qftp-core</code> に 1 実装し、ホスト(quiche ループ / ブリッジ / テスト)が I/O を担う</td></tr>
<tr><td>ADR-003</td><td>ワイヤ符号化は手書き codec。適合性はゴールデンベクタで担保</td></tr>
<tr><td>ADR-004</td><td>OS ユーザ分離は行わない(仮想ユーザモデル)</td></tr>
<tr><td>ADR-005</td><td>ディスク I/O は <code>spawn_blocking</code> / <code>tokio::fs</code> に委譲し、QUIC ドライバのタスクはソケットと状態遷移のみを扱う</td></tr>
<tr><td>ADR-006</td><td>Web ブリッジは wtransport(quinn + tokio)の別バイナリ。quiche 方針の明示的例外(quiche での WebTransport 終端は調査の結果、不可と判断)</td></tr>
<tr><td>ADR-007</td><td>e2e は <code>qftp-server/tests</code>、フィクスチャは <code>test-util</code> feature、ベンチは <code>benches/</code>。専用クレートは作らない</td></tr>
<tr><td>ADR-008</td><td>Ls カーソルは最後に返した名前の base64url</td></tr>
<tr><td>ADR-009</td><td>Put は本体送信と応答読みを並行し、早期拒否を待たない</td></tr>
<tr><td>ADR-010</td><td>sync <code>--checksum</code> と put-multi は作らない</td></tr>
<tr><td>ADR-011</td><td>Windows は対象外(非 Unix は起動時エラー)</td></tr>
<tr><td>ADR-012</td><td>ベアラトークンは admin が生成し SHA-256 で保存</td></tr>
<tr><td>ADR-013</td><td>リリースは手書きの GitHub Actions workflow</td></tr></table><p>各 ADR の本文は <code>00-background/decisions.md</code> にあります。</p>""",
"decisions.tradeoffs":"""<ul><li><b>quiche + tokio current_thread</b>: 単一タスクが全接続を持つため挙動が読みやすくロックが不要な代わりに、状態機械を明示的に書く必要がある。sans-I/O 化でその負担を「テスト可能な純粋ロジック」に変える。tokio の依存グラフとバイナリサイズはブリッジで既に受け入れているもの。</li><li><b>sans-I/O エンジン</b>: コマンド / イベントの往復が増え、直書きより行数はやや増える。代わりにソケット・ディスクなしで全経路をユニットテストでき、ブリッジ再実装が不要になる。</li><li><b>手書き codec</b>: derive の手軽さを失うが、仕様とバイト列の対応が明示的になる。</li><li><b>ブロッキングプールへの委譲</b>: タスク間の往復コストが加わるが、HOL を解消し、大容量転送中でも小さな要求が待たされない。GSO は tokio の <code>UdpSocket</code> にないため <code>try_io</code> 経由で <code>sendmsg</code> を呼ぶ手間が残る。</li></ul>""",
"decisions.related-adrs":"<p><code>00-background/decisions.md</code>(ADR-001〜015)。プロトタイプ時代の ADR-0001(quiche 継続)と ADR-0002(OS ユーザ分離却下)は同ファイルに要約を引き継いでいます。</p>",
"risks.known-risks":"""<ul><li>quiche で TOFU / ホスト名検証がハンドシェイク後にしか行えないため、検査完了前にアプリケーションデータを送らない規律をクライアントコアで強制する必要がある。</li><li>sans-I/O エンジンとホストの境界設計を誤ると、ホスト側に状態が漏れてプロトタイプの二の舞になる。エンジンの公開 API を API 仕様(<code>40-reference/engine-api.html</code>)で固定する。</li><li>BoringSSL のビルド時間と C++ ツールチェーン依存。</li><li>プロトタイプの細かな挙動(自動再開、StalePartial 再試行など)の取りこぼし。</li></ul>""",
"risks.open-questions":"<ul><li>可用性 SLO と性能目標の数値。</li><li>実装前の技術検証の結果(tokio current_thread 上の quiche 駆動構造、GSO)。</li></ul>",
"risks.mitigations":"<ul><li>実装前に quiche の 0-RTT 受理 + 1-RTT ゲート、retry、GSO を最小サーバで技術検証を行い、結果を ADR に追記する。</li><li>エンジンの API を先に固定し、純メモリのホストでユニットテストを書いてからサーバに組み込む。</li><li>e2e テスト仕様(<code>40-reference/e2e-test-spec.html</code>)を受け入れ条件とする。</li><li>CI に MSRV ジョブと aarch64 クロスビルドを最初から置く。</li></ul>",
"references.related-docs":"<ul><li>機能設計書: <a href=\"feature-transfer-engine.html\">転送エンジン</a>、<a href=\"feature-server.html\">サーバ</a>、<a href=\"feature-client.html\">クライアント</a>、<a href=\"feature-web-bridge.html\">Web ブリッジ</a>(管理 CLI は <a href=\"../40-reference/cli-reference.html#admin\">CLI リファレンス</a> と <a href=\"../40-reference/file-formats.html\">ファイル形式リファレンス</a> で規定)</li><li>シーケンス設計書: <a href=\"sequence-connection-setup.html\">接続確立</a>、<a href=\"sequence-get-transfer.html\">Get</a>、<a href=\"sequence-put-transfer.html\">Put</a></li><li><a href=\"operations-qftp-server.html\">運用設計書</a>(画面設計書は Web 区分の設計時に作成)</li><li>参照文書: <code>40-reference/</code>(転送エンジン API、設定、CLI、ファイル形式、e2e テスト)</li><li>決定事項: <code>00-background/decisions.md</code>(ADR-001〜013)</li><li>リポジトリ構成: <code>30-repository/repository-layout.md</code></li></ul>",
"references.artifacts":"<ul><li>プロトコル仕様: <code>10-protocol/</code>(README / qftp-protocol / wire-format / error-codes / versioning / security-model / protocol-changelog)</li><li>ゴールデンベクタ: <code>10-protocol/test-vectors/</code></li><li>drawio / OpenAPI: なし(本プロジェクトは HTTP API を持たない)</li></ul>",
}
