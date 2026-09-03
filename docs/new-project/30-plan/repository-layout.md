# 新リポジトリのレイアウト案

## クレート構成(8 クレート)

| # | クレート | 種別 | 役割 | 依存(qftp 内) |
|---|---|---|---|---|
| 1 | `qftp-wire` | lib | ワイヤ型、手書き codec、フィールド検証、定数。`tests/conformance.rs` でゴールデンベクタを検証し、`examples/gen_vectors.rs` でベクタを再生成する | なし |
| 2 | `qftp-core` | lib | パスサンドボックス、ユーザ / ACL / クォータ、identity 抽出、メタデータ操作(Ls ページング)、sans-I/O 転送エンジン、zstd、temp 名規則、掃除 | wire |
| 3 | `qftp-quic` | lib | quiche 設定、TLS モード、stateless retry、SCID 導出、0-RTT ポリシー、mio イベントループ骨格、quiche ストリーム上のフレーム送受信、GSO、接続上限・レートバケット | wire |
| 4 | `qftp-server` | lib + bin | 設定、受付、コネクション / ストリーム dispatch、I/O ワーカープール、転送エンジンのホスト、メトリクス、シャットダウン。`run(config)` を公開 | core, quic |
| 5 | `qftp-client-core` | lib | Session API、サーバ信頼ポリシー(CA / TOFU / insecure)、セッションチケット、設定解決、再開ロジック、クライアント側エンジンのホスト | core, quic |
| 6 | `qftp-client` | bin | CLI、REPL、one-shot、出力整形と終了コード。Phase 6: sync / watch | client-core |
| 7 | `qftp-admin` | bin | users.toml / tokens.toml 編集 | core |
| 8 | `qftp-e2e` | lib + tests + benches(`publish = false`) | プロセス内フィクスチャ(lib)、e2e テスト(`tests/`)、criterion ベンチ(`benches/`、`test = false` で `cargo test` から除外) | server, client-core |

補助: `fuzz/`(cargo-fuzz、ワークスペース内、`publish = false`。stable では `cargo check` のみ)。Phase 7 で `qftp-web-bridge`(bin)を 9 番目として追加する。

### 統合した(作らない)クレート

| 当初案 | 統合先 | 理由 |
|---|---|---|
| `qftp-conformance` | `qftp-wire` の `tests/` と `examples/` | 依存が wire だけで、ベクタ検証は wire のテストそのもの。examples は dev-dependencies(serde_json)を使えるので生成バイナリも置ける |
| `qftp-testkit` | `qftp-e2e` の lib | フィクスチャの利用者は e2e とベンチだけ |
| `qftp-bench` | `qftp-e2e` の `benches/` | 同じフィクスチャを使う。`cargo test` から除外する設定を 1 箇所で管理できる |

### 分けたままにするクレート

- `qftp-client-core` と `qftp-client`: e2e が clap / rustyline / indicatif を引かずに Session API を使うため。lib + bin を 1 クレートにすると lib 利用者も bin の依存をビルドする。
- `qftp-quic` と `qftp-core`: core が quiche を知らない(sans-I/O)ことを依存関係で強制するため。
- `qftp-wire` と `qftp-core`: wire は依存ゼロの葉で、fuzz / 将来の WASM / 他言語向けベクタ生成が QUIC も blake3 もビルドせずに済むため。

## ディレクトリ構成

```
qftp/
├── Cargo.toml                 # workspace(単一 MSRV、resolver 2)
├── README.md
├── LICENSE.md                 # MIT
├── SECURITY.md                # spec/security-model.md への導線と報告窓口
├── CHANGELOG.md               # 実装の変更履歴(ワイヤ変更は spec/protocol-changelog.md)
├── spec/                      # 本パッケージの 10-protocol/ をそのまま配置(正本)
│   └── test-vectors/
├── docs/
│   ├── adr/                   # 00-background/decisions.md を 1 ADR 1 ファイルに分割
│   ├── design/                # 20-design/*.html
│   ├── background/            # prototype-assessment.md
│   └── plan/                  # roadmap.md、本ファイル
├── crates/
│   ├── qftp-wire/
│   │   ├── src/{lib,message,codec,limits,validate}.rs
│   │   ├── tests/conformance.rs
│   │   └── examples/gen_vectors.rs
│   ├── qftp-core/
│   │   └── src/{lib,path,user,identity,fs_ops,compress,temp,sweep}.rs
│   │       src/transfer/{mod,server,client,event,cmd,accounting}.rs
│   ├── qftp-quic/
│   │   └── src/{lib,config,tls,retry,scid,zero_rtt,event_loop,framing,egress,limits}.rs
│   ├── qftp-server/
│   │   └── src/{lib,main,config,accept,connection,dispatch,io_pool,host,metrics,health,shutdown}.rs
│   ├── qftp-client-core/
│   │   └── src/{lib,session,trust,tickets,config,resume,host,options}.rs
│   ├── qftp-client/
│   │   └── src/{main,cli,oneshot,output}.rs  src/repl/{mod,parser,commands,completer}.rs
│   ├── qftp-admin/
│   │   └── src/main.rs
│   └── qftp-e2e/
│       ├── src/{lib,server_fixture,client,certs,fs}.rs
│       ├── tests/*.rs
│       └── benches/throughput.rs
├── fuzz/
├── examples/
│   ├── systemd/qftp-server.service
│   └── docker-compose/
├── scripts/
├── Dockerfile
└── .github/workflows/         # ci.yml、fuzz.yml、release.yml
```

## 依存方向(上位 → 下位のみ)

```
qftp-wire ◀── qftp-core ◀──┬── qftp-server ◀──────────┐
    ▲            ▲         │                          ├── qftp-e2e
    └── qftp-quic ◀────────┴── qftp-client-core ◀─────┘
                                     ▲
                                     └── qftp-client
qftp-core ◀── qftp-admin
qftp-wire, qftp-core ◀── fuzz
```

規則:

- `qftp-wire` は QUIC・tokio・ファイルシステム・blake3 に依存しない。
- `qftp-core` は quiche を知らない(sans-I/O)。
- `qftp-quic` はファイルシステムを知らない。
- バイナリの `main` は「設定を読む → ライブラリの `run` を呼ぶ」だけにする。

## モジュール骨子

| クレート | モジュール |
|---|---|
| `qftp-wire` | `message`(Request / Response / ErrorCode / ErrorDetails / DirEntry / FileStat / FileType / HashAlgorithm / Encoding)、`codec`(`WireEncode` / `WireDecode`、フレーム長プレフィクス、寛容デコード)、`limits`、`validate`(フィールド上限、安全名) |
| `qftp-core` | `path`(walk_safe / resolve / resolve_parent / recheck)、`user`(schema / directory / quota / claim)、`identity`(x509 → 候補 → 解決)、`fs_ops`(Ls ページング / Stat / Mkdir / Rmdir / Rm / Rename / Chmod / Quota)、`transfer::{server, client, event, cmd, accounting}`、`compress`、`temp`(`TempName`)、`sweep` |
| `qftp-quic` | `config`(transport parameters、サーバ / クライアント)、`tls`(materials / self_signed / modes)、`retry`、`scid`、`zero_rtt`、`event_loop`(mio、Waker、timers)、`framing`、`egress`(GSO)、`limits` |
| `qftp-server` | `config`、`accept`、`connection`、`dispatch`、`io_pool`、`host`、`metrics`、`health`、`shutdown` |
| `qftp-client-core` | `session`、`trust`、`tickets`、`config`、`resume`、`host`、`options` |
| `qftp-client` | `cli`、`repl::{parser, commands, completer}`、`oneshot`、`output`、Phase 6: `sync`、`watch` |
| `qftp-e2e` | `server_fixture`(プロセス内 `run`)、`client`(Session ラッパ)、`certs`(rcgen)、`fs`(一時ディレクトリ、乱数ファイル) |

## CI 構成

- `check`: fmt、clippy `-D warnings`、build、`cargo test --workspace`(ベンチは `test = false` で除外)、`cargo run -p qftp-wire --example gen-vectors -- spec/test-vectors` → `git diff --exit-code`。
- `msrv`: 宣言 MSRV での build + test。
- `cross`: aarch64-unknown-linux-gnu の build。
- `macos`: build + test。
- `deny`: advisories / licenses / sources / bans。
- `fuzz-check`: stable で `cargo check -p qftp-fuzz`。
- `fuzz`(定期、nightly): 各ターゲット 180 s、corpus キャッシュ。
- `release`(タグ): test → 4 ターゲット tarball + sha256 → deb → GitHub Release。
