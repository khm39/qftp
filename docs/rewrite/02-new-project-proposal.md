# qftp 新規プロジェクト設計案

作成日: 2026-09-03 / 前提文書: [01-current-spec.md](01-current-spec.md)

> **決定事項(2026-09-03 追記)**: 本書執筆後、次の方針が決まりました。(1) 新リポジトリで始める。(2) ネイティブ実装の QUIC スタックは **quiche** を基本とする(本書 §2-A の quinn 推奨は採用されず)。(3) 設計書は旧リポジトリを参照せずに読める自己完結パッケージとする。これらを反映した設計パッケージは [`docs/new-project/`](../new-project/README.md) にあり、以降はそちらが正本です。本書は経緯の記録として残します。

本書は、プロトタイプ実装を捨てて qftp を新規プロジェクトとして起こす際の設計案です。現行仕様のうち何を引き継ぎ、何を捨て、どの順で作るかを、判断理由つきで示します。「推奨」と書いた箇所は私の意見であり、代案とトレードオフを併記しています。

---

## 0. 結論(要約)

1. **ワイヤプロトコル(`spec/` + `test-vectors/`)はそのまま引き継ぎ、実装だけを書き直す。** qftp/1 は凍結済みで、ワイヤを変える理由が現状ありません。
2. **QUIC スタックを quinn + tokio + rustls に統一する**(ADR-0001 を新 ADR で上書き)。理由は §2-A。
3. **符号化を手書き codec に置き換え、bincode への依存を切る。** 適合性はゴールデンベクタで担保します(§2-B)。
4. **転送エンジンを 1 つの非同期実装に集約し、サーバ・ブリッジ・クライアントが共有する**(§2-D)。
5. **クレートを「ワイヤ → コア → トランスポート → アプリ」の一方向依存に再編する**(§3)。
6. **MVP はネイティブサーバ + クライアント(REPL / one-shot)に絞り、Web / watch / sync / put-multi は後続フェーズに送る**(§4、§6)。
7. **e2e をプロセス内フィクスチャに置き換え、ベンチを `cargo test` から切り離す**(§2-H)。

---

## 1. ゴールと非ゴール

### ゴール

- `spec/` に完全準拠した、読める大きさのリファレンス実装(目安: 現行 32,000 行 → 15,000 行前後)。
- サーバ / クライアント / ブリッジの**挙動仕様が文書として存在する**状態(現行は README とコードコメントに散在)。
- 単一 QUIC スタック、単一 MSRV、単一の転送エンジン。
- 変更が安全に行える検証基盤(プロセス内 e2e、conformance、fuzz、MSRV ジョブ)。

### 非ゴール

- ワイヤプロトコルの変更(qftp/2 の議論は別途)。
- OS ユーザ分離(ADR-0002 の却下判断を引き継ぐ)。
- 機能の追加。現行機能の「整理と再実装」が目的で、新機能は後続フェーズ。

---

## 2. 主要な設計判断

### A. QUIC スタック: quinn + tokio + rustls に統一(推奨)

**現状**: ネイティブは quiche + mio(同期・単一スレッド・手書き多重化)、ブリッジは wtransport(quinn + tokio)。2 スタック、2 MSRV、転送ドライバ 2 実装。

**推奨する理由**

- 現行の痛みの多く(430 行の `start_put`、チャンク/ティックの状態機械、イベントループ上のディスク I/O による HOL、`compute_poll_timeout` 起因の再開停止バグ)は、同期イベントループで非同期処理を手書きしていることに由来します。ADR-0001 自身が「async fn なら 30 行程度に潰れる」と認めています。
- ブリッジは既に quinn 上にあり、WebTransport は quiche では実現できません。統一するなら方向は quinn 側しかありません。
- rustls は証明書検証をフック(`ServerCertVerifier`)として差し込めるため、TOFU とホスト名検証を**ハンドシェイク中**に行えます。現行はハンドシェイク完了後に自前検査しており、TOFU が REPL 経路限定になっている原因でもあります。
- BoringSSL の C++ ビルドが不要になり、クロスビルド(aarch64、musl)とビルド時間が軽くなります。
- 0-RTT(サーバ側 early data 受理、クライアント側 `into_0rtt`)、stateless retry(`Incoming::retry`)、GSO は quinn が提供しています。ただし **early data の受理と「1-RTT 完了までの要求ゲート」を quinn の API でどう表現するかは着手前に spike で検証してください**(私の知識では可能ですが、API の細部は quinn のバージョンに依存します)。

**代案: quiche 継続**。Cloudflare の実績と依存の小ささは本物ですが、ブリッジとの 2 スタック問題は解消せず、書き直しの主目的(実装の整理)に反します。quiche を残すなら、少なくとも転送ドライバを `qftp-core` の同期状態機械として 1 実装に集約し、ブリッジ側で同じものを駆動する設計が必要です。

**リスク**: quinn の 0-RTT サーバ API の制約、tokio の依存グラフ増加(現行 ADR の懸念)。後者はブリッジで既に受け入れている代償です。

### B. 符号化: 手書き codec(推奨)

**現状**: bincode 1.3.3(RUSTSEC-2025-0141 で unmaintained、`deny.toml` で無視中)。`#[serde(default)]` が多数付いているが bincode では無効で、互換性があるかのような誤解を招いています。

**推奨する理由**

- `spec/wire-format.md` は「bincode は非規範」と明記しています。手書きにすれば Rust 実装も他言語実装と同じ立場でベクタに従うことになり、仕様とコードの主従が明確になります。
- 位置依存 enum / 数値 enum / `Option` / `string` / `seq` の 5 種の規則しかないため、エンコーダ + デコーダで 500 行程度です。
- 将来「末尾フィールド追加を旧フレームでも受ける」寛容デコード(`versioning.md` の一方向性問題)は、手書きなら残りバイト長を見て自然に実装できます。
- `serde` 自体は JSON ベクタ生成と設定ファイルのために残します。ワイヤ型に `Serialize`/`Deserialize` を derive するのは JSON 表現専用とし、ワイヤ符号化は別トレイト(`WireEncode` / `WireDecode`)にします。

**代案: bincode 2 系**。互換設定で同じバイト列を出せますが、仕様の主従関係と寛容デコードの課題は残ります。

### C. ワイヤ型クレートを依存ゼロの葉にする

`qftp-wire` は `Request` / `Response` / `ErrorCode` などの型、手書き codec、フィールド上限の検証、定数(`ALPN`、`MAX_MESSAGE_SIZE`)だけを持ち、QUIC / tokio / ファイルシステムに依存しません。conformance、fuzz、admin、将来の WASM ビルドがこのクレートだけで完結します。

### D. 転送エンジンを 1 実装に集約

`qftp-core::transfer` に、`Get` / `Put` の**サーバ側**の状態機械を async fn として 1 つだけ実装し、入出力はトレイトで抽象化します。

```rust
pub trait ByteSink { async fn write_all(&mut self, buf: &[u8]) -> io::Result<()>; async fn finish(&mut self) -> io::Result<()>; }
pub trait ByteSource { async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>; }  // Ok(0) = FIN

pub async fn serve_get(req: GetRequest, ctx: &SessionCtx, out: &mut impl ByteSink) -> Result<(), TransferError>;
pub async fn serve_put(req: PutRequest, ctx: &SessionCtx, body: &mut impl ByteSource, out: &mut impl ByteSink) -> Result<(), TransferError>;
```

quinn の `SendStream` / `RecvStream` と wtransport の同名型はいずれも `AsyncRead` / `AsyncWrite` を実装するため、両者に薄いアダプタを被せるだけで同じエンジンを駆動できます。ブリッジの Put 再開・圧縮非対応(現行 G4)は自動的に解消します。

クライアント側の `Get` / `Put` も対称に `qftp-core::transfer::client` に置き、REPL / one-shot / 将来の sync が同じ関数を呼びます。

**設計規則(現行の不整合を潰すため)**

- 失敗時の temp / クォータ処理は**経路によらず同一**(現行は identity と zstd で異なる)。`PutJob` を RAII にし、`Drop` の会計規則を 1 箇所に置く。
- Get の途中失敗は可能な限り `Response::Err` を送る(ワイヤ上、本体送出前なら可能)。本体送出後は QUIC の `reset_stream` でエラーコードを通知する(仕様には「実装定義」として追記)。
- `HashAlgorithm::digest_len()` をトレーラ長の唯一の情報源にする(32 固定の `TrailerBuf` を廃止)。
- `.qftp.partial` の規則は `TempName` 型 1 箇所に集約する。

### E. サーバ

- **設定ファイル(TOML)+ フラグ上書き**。現行の全フラグを 1:1 で設定キーにし、`--config` を追加します。`users.toml` は現行スキーマのまま互換にします(`qftp-admin` の出力がそのまま使えるため)。
- **ディスク I/O は `tokio::task::spawn_blocking` または `tokio::fs`** に寄せ、コネクションタスクをブロックしない。
- **レート制限のバケットを Initial 用と要求用で分離**(現行は共有で、正当なクライアントが自 IP の新規接続を締め出せる)。
- **Ls ページネーションを初日から実装**(G1)。カーソルは「ソート済み名前 + ページ番号」の HMAC 付き opaque 文字列にし、サーバ発行以外は拒否。
- `Cd` を Read 権限の対象にする(G13)。ワイヤ非変更、`spec/qftp-protocol.md` の ACL 表に追記。
- `healthz` は受付ループの生存とシャットダウン状態を反映する。
- メトリクスは `prometheus-client` 系の crate を使い、手書き HTTP をやめる(`/metrics` `/healthz` は hyper で提供)。
- 0-RTT identity gate、retry トークン形式、SCID 導出、half-open reap、接続上限は現行の規則をそのまま移植します(セキュリティレビュー済みの資産)。

### F. クライアント

- **`qftp-client-core`(ライブラリ)と `qftp-client`(バイナリ)に分離**。`Session` API(connect / request / get / put)を公開し、REPL・one-shot・sync・テストがすべてこれを使います。
- **グローバル状態を廃止**。`TransferOptions { quiet, bwlimit, compress }` を `Session` に持たせ、alias 単位で `bwlimit` や `compress` を設定できるようにします(現行はプロセス全体の atomics)。
- **サーバ識別ポリシーを 1 型に統合**(`ServerTrust::{Ca(bundle), SystemRoots, Tofu(known_hosts), Insecure}`)し、rustls verifier として実装。one-shot / sync / watch でも TOFU が使えるようになります。
- **出力と終了コードの規約を固定**: 結果は stdout、診断は stderr、終了コードは sysexits(0 / 64 / 65 / 77)を **すべての経路**で守る。バッチ / `-e` は `--fail-fast` を既定にし、失敗があれば非 0 で終了。
- REPL パーサにクォート対応を入れる(空白を含むパスが扱えない現状の解消)。
- `ls` / `mget` / `get -r` / `sync` はページネーションを必ず追う。
- 設定ファイルに `[defaults]` セクション(`compress`、`bwlimit`、`tofu`、`ticket_dir`、`history`)を追加。`[host.*]` は現行互換。
- `known_hosts` / セッションチケットの形式は現行 V2 を踏襲(リリース前なので変更自由ですが、変える理由がありません)。

### G. Web ブリッジと SPA

- ブリッジは**別バイナリのまま**、`qftp-core` のエンジンと `qftp-transport` の共通部分を使う。`Cd` をセッション状態として保持する(G3)。
- **手書き HTTP/1.1 を廃止**。SPA は静的ファイルとして配布し、開発用の `--http-bind` は hyper で提供する。
- SPA の codec は現行どおり JS 手書きでも動きますが、**`qftp-wire` を WASM にビルドして codec + BLAKE3 + zstd を 1 実装で共有する**案を Phase 4 で評価します(Rust 側の型変更が JS に波及しなくなる利点が大きい)。
- トークンは**ハッシュ化して保存**(argon2 または SHA-256 + 定数時間比較)、失敗回数の per-IP 制限、`/config.json` は HTTPS 経由でのみ信頼するようピン留めフォールバック条件を「証明書エラーのときだけ」に限定。
- ダウンロードはストリーミング(`File System Access API` またはチャンク Blob)に変更し、1 GiB のメモリ蓄積を避ける。

### H. テスト・ベンチ・CI

- **`qftp-testkit` クレート**: プロセス内でサーバを起動し、`qftp-client-core` で叩くフィクスチャ。ポート競合の心配がなく、`cargo build --release` のネストも不要。
- **e2e は専用クレート `qftp-e2e`**(bench から分離)。現行の 6 シナリオ(0 バイト、ホスト名接続、Get / Put 再開、同サイズ破損 partial、多チャンク再開)に加え、サーバ調査で挙がった未カバー項目(zstd 往復、チェックサム不一致、クォータ、`no_clobber` 競合、mTLS 拒否、`--require-retry`、0-RTT 拒否、half-open reap、シャットダウン drain)を最初から入れる。
- **conformance**: 現行のベクタと生成 → diff ゲートをそのまま移植。加えて「旧フレーム(末尾フィールドなし)を新デコーダが読む」ケースをベクタ化しておく。
- **fuzz**: ワークスペース内に置き、stable の CI で `cargo check` だけは通す(実行は nightly の定期ジョブ)。zstd デコーダ、TOML 設定、トークン / origin 解析を対象に追加。
- **bench**: `cargo test` から除外(`harness = false` のテストモード問題)。ペイロードは乱数、`--no-compress` と圧縮ありの両方を計測。
- **CI マトリクス**: MSRV + stable、Linux + macOS。`cargo-audit` は `cargo-deny` に統合。カバレッジは e2e 込みで計測し閾値を置く。
- **リリース**: 現行の手書き workflow を維持するか cargo-dist に本当に移行するかを決め、文書と一致させる。SBOM / attestation は後続。

---

## 3. クレート構成と依存方向

```
qftp-wire        型・手書き codec・検証・定数            deps: なし(serde は JSON 表現用のみ)
   ↑
qftp-core        パスサンドボックス、ユーザ/ACL/クォータ、  deps: qftp-wire, blake3, zstd, tokio(fs/io のみ)
                 転送エンジン(server/client)、圧縮、
                 temp 名規則、identity 抽出(x509)
   ↑
qftp-transport   quinn Endpoint 構築、TLS 設定、           deps: qftp-wire, quinn, rustls, rcgen
                 verifier(CA/TOFU/insecure)、retry、
                 0-RTT ポリシー、SCID 導出、
                 フレーム送受信アダプタ
   ↑                    ↑                    ↑
qftp-server      qftp-client-core     qftp-web-bridge
(bin)            (lib) ← qftp-client   (bin, wtransport)
                          (bin)
qftp-admin       ← qftp-core(users.toml スキーマのみ)
qftp-conformance ← qftp-wire
qftp-testkit     ← qftp-server(lib 化した run 関数)+ qftp-client-core
qftp-e2e         ← qftp-testkit
qftp-bench       ← qftp-testkit
fuzz             ← qftp-wire, qftp-core
```

規則: 上位から下位への依存のみ。`qftp-core` は QUIC を知らず、`qftp-wire` はファイルシステムを知りません。サーバの `main` は「設定を読む → `qftp_server::run(config).await`」だけにし、`run` をライブラリとして公開してテストキットから起動できるようにします。

### 3.1 モジュール骨子(参考)

| クレート | 主要モジュール |
|---|---|
| `qftp-wire` | `message`(型)、`codec`(encode/decode)、`error_code`、`limits`、`validate` |
| `qftp-core` | `path`(walk_safe / resolve / recheck)、`user`(schema / directory / quota)、`identity`(x509 → 候補)、`fs_ops`(Ls ページング / Stat / Mkdir …)、`transfer::{server,client}`、`compress`、`temp` |
| `qftp-transport` | `endpoint::{server,client}`、`tls::{server,client,verifier}`、`retry`、`zero_rtt`、`framing`(AsyncRead/Write 上の send/recv_message)、`limits`(接続上限・レートバケット) |
| `qftp-server` | `config`、`accept`(接続受付・identity 昇格)、`session`(cwd・ストリーム dispatch)、`metrics`、`shutdown`、`main` |
| `qftp-client-core` | `session`(connect / request / get / put)、`trust`(known_hosts、TOFU)、`tickets`、`config`、`resume`、`options` |
| `qftp-client` | `cli`、`repl::{parser,commands,completer}`、`oneshot`、`output`(整形・終了コード)、Phase 3: `sync`、`watch`、`fanout` |

---

## 4. 機能スコープ

| 機能 | 判断 | 理由 |
|---|---|---|
| Ls / Cd / Pwd / Stat / Mkdir / Rmdir / Rm / Rename / Chmod / Quota / Quit | MVP | プロトコル中核 |
| Get / Put(再開・BLAKE3・zstd) | MVP | 同上。エンジン共有 |
| Ls ページネーション | MVP | ワイヤ凍結済み・未実装の負債 |
| mTLS / users.toml / ACL / クォータ | MVP | 現行スキーマ互換 |
| 0-RTT(identity gate 込み)/ retry / レート制限 / 接続上限 | MVP | セキュリティ資産 |
| 自己署名(一時 / 永続)/ TOFU / CA / insecure | MVP | クライアント運用の前提 |
| metrics / healthz / JSON ログ | MVP | 運用要件 |
| REPL(履歴・補完・`-e`・batch)/ one-shot(put/get/ls/stat/rm/mkdir/rmdir/rename) | MVP | 主要 UI |
| `get -r` / `put -r` / `mget` | Phase 2 | REPL と one-shot の両方で提供(現行は one-shot 未実装) |
| `--bwlimit`(上下双方向) | Phase 2 | 現行は上りのみ |
| `qftp-admin` | Phase 2 | `users.toml` 互換なので現行コードの移植で足りる。`[anonymous]` と `tokens.toml` 対応を追加 |
| `sync` | Phase 3 | `--checksum` は「サーバの BLAKE3 を取る手段がない」ため**実装するかフラグを削るか**の判断が必要。ワイヤに `Stat` 拡張がない以上、削除を推奨 |
| `watch` | Phase 3 | `Mkdir` 反映・エイリアス対応を含めて再設計 |
| `put-multi` | Phase 3 または廃止 | 利用実態が不明。`sync` の複数ターゲット化で代替可能なら廃止を推奨 |
| Web ブリッジ + SPA | Phase 4 | エンジン共有で再開・圧縮・`Cd` が揃う。codec の WASM 共有を評価 |
| Windows 対応 | 未決 | 現行は「黙って劣化」(O_NOFOLLOW なし、mode 合成)。対象外と明記するか、明示的に `Unsupported` を返すか決める |

---

## 5. 現行資産の引き継ぎ方

| 資産 | 扱い |
|---|---|
| `spec/`、`test-vectors/`、`PROTOCOL-CHANGELOG.md` | **そのままコピー**(履歴を残すなら `git filter-repo --path spec --path test-vectors` で抽出)。後述の追記のみ |
| `SECURITY.md` の脅威モデル・ハードニング一覧 | そのまま。新設計で変わる点(トークンのハッシュ保存等)だけ更新 |
| `docs/adr/0001` | **新 ADR 0003 で上書き**(quinn 統一の決定と理由)。0001 は Superseded として保持 |
| `docs/adr/0002` | そのまま(却下の記録) |
| `users.toml` / `config.toml` / `known_hosts` / チケット形式 | スキーマ互換で引き継ぐ |
| 手書き HMAC retry トークン、SCID 導出、0-RTT ゲート、identity 抽出、walk_safe、zstd 窓制限、伸長爆弾ガード | **ロジックを移植**(セキュリティレビューを経た規則。コードは新構造に合わせて書き直す) |
| `qftp-admin` | ほぼそのまま移植 |
| e2e シナリオ 6 本、`stream_reset_dos`、ブリッジ e2e | シナリオとして移植(フィクスチャは testkit に置換) |
| JS BLAKE3 / codec | Phase 4 まで保留。WASM 化の評価結果で存廃を決める |
| `bench` / `bench-sftp.sh` | ペイロードを乱数化して移植 |
| README の CLI リファレンス | 本書 §2-E/F の規約で書き直し、`docs/` 配下の挙動仕様書を正本にする |

### 5.1 `spec/` への追記候補(ワイヤ非変更)

- `Cd` を Read 権限の対象とする旨(ACL 表)。
- Get の本体送出後のエラー通知手段(`reset_stream` のエラーコード)を実装定義として記載。
- 「旧フレームを新デコーダが読む」寛容デコードの既定値表(現状は規則のみで具体値がない)。
- `test-vectors/README.md` の `[u8;32]` と Get フィールド順の修正(G10)。

---

## 6. 移行計画

各フェーズは「前フェーズの成果物に対して conformance と e2e が緑」を完了条件(DoD)にします。

| Phase | 内容 | DoD |
|---|---|---|
| 0 | リポジトリ作成、`spec/` 移植、ADR 0003、**quinn 0-RTT / retry の spike**、CI 骨格(fmt / clippy / MSRV / conformance) | spike が「サーバ側 early data を受理しつつ 1-RTT 完了まで要求をゲートできる」ことを実証 |
| 1 | `qftp-wire`(手書き codec)+ `qftp-conformance` + fuzz(deser 2 本) | 全ベクタ双方向一致、既存 `error-codes.json` 含む |
| 2 | `qftp-core`(path / user / fs_ops / transfer / compress)を**ユニットテストのみ**で完成 | 現行 `handler.rs` / `stream.rs` / `user.rs` の全テスト相当を移植して緑 |
| 3 | `qftp-transport` + `qftp-server`(MVP 機能)+ `qftp-testkit` | e2e: Ls ページング、Get / Put 往復、再開 3 種、zstd、mTLS、retry、0-RTT 拒否、シャットダウン |
| 4 | `qftp-client-core` + `qftp-client`(REPL / one-shot MVP) | 現行 README のクイックスタートが動く。終了コード規約の e2e |
| 5 | Phase 2 機能(再帰、mget、admin、bwlimit)+ 運用(metrics、systemd、Docker、release) | 現行 CHANGELOG の機能一覧と機能等価 |
| 6 | sync / watch(必要なら fanout) | 各コマンドの e2e |
| 7 | Web ブリッジ + SPA(WASM 評価込み) | ブラウザ e2e(Playwright) |

Phase 4 終了時点で現行の主要ユースケース(サーバ + CLI クライアント)を置き換えられます。現行リポジトリは Phase 5 完了まで並走させ、その後アーカイブする想定です。

---

## 7. 要判断事項

以下は私だけでは決められない、あるいは方針で結果が大きく変わる項目です。**推奨**を付けていますが、異なる判断であれば設計を合わせます。

1. **新リポジトリか、同一リポジトリ内の新ワークスペースか。** 推奨: 新リポジトリ(`spec/` を履歴ごと移植)。理由は、現行コードを参照しながら段階的に消していく運用より、参照専用として凍結した方が「捨てる」判断が明確になるためです。
2. **QUIC スタック**(§2-A)。推奨: quinn 統一。quiche を残す判断なら §2-D の同期版エンジン設計に切り替えます。
3. **Web ブリッジをスコープに含めるか。** 推奨: 含めるが Phase 7。ブラウザ利用の実需がなければ落として構いません。
4. **sync `--checksum`、`put-multi` の存廃**(§4)。推奨: 前者はフラグ削除、後者は廃止。
5. **Windows を対象にするか**(§4)。推奨: Phase 5 まで対象外と明記し、非 Unix では起動時に明示エラー。
6. **サーバ設定ファイルの導入**(§2-E)。推奨: 導入。フラグのみ運用を続けるなら現行互換のフラグ集合を維持します。
7. **リリース方式**(手書き workflow か cargo-dist か)。どちらでも構いませんが、文書と一致させる必要があります。

---

## 8. リスク

- **quinn の 0-RTT / early data API の制約**により、identity gate の実装形が現行と変わる可能性があります(Phase 0 の spike で確定)。
- **手書き codec の誤り**はベクタで検出できますが、ベクタに無いフィールド組合せは fuzz と往復テストで補う必要があります。
- **エンジン共有の抽象化コスト**: quinn / wtransport のストリーム型差異が想定より大きい場合、アダプタ層が厚くなります。`AsyncRead` / `AsyncWrite` + `finish` の最小トレイトに留めることで抑えます。
- **機能等価の確認**: 現行の細かな挙動(たとえば `get` の自動再開、`put` の StalePartial 再試行)は仕様書化していないと再実装時に落ちます。§5 の e2e シナリオ移植と、[01-current-spec.md](01-current-spec.md) §4.9 の規則を受け入れ条件に含めてください。
