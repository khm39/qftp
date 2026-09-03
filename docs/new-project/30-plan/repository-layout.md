# 新リポジトリのレイアウト案

```
qftp/
├── Cargo.toml                 # workspace(単一 MSRV、resolver 2)
├── README.md                  # クイックスタートと文書への導線
├── LICENSE.md                 # MIT
├── SECURITY.md                # spec/security-model.md への導線と報告窓口
├── CHANGELOG.md               # 実装の変更履歴(ワイヤ変更は spec/protocol-changelog.md)
├── spec/                      # 本パッケージの 10-protocol/ をそのまま配置(正本)
│   ├── README.md
│   ├── qftp-protocol.md
│   ├── wire-format.md
│   ├── error-codes.md
│   ├── versioning.md
│   ├── security-model.md
│   ├── protocol-changelog.md
│   └── test-vectors/
├── docs/
│   ├── adr/                   # 00-background/decisions.md を 1 ADR 1 ファイルに分割
│   ├── design/                # 20-design/*.html(設計書)
│   ├── background/            # prototype-assessment.md
│   └── plan/                  # roadmap.md、本ファイル
├── crates/
│   ├── qftp-wire/             # 型、手書き codec、検証、定数(依存なし)
│   ├── qftp-core/             # path / user / identity / fs_ops / transfer / compress / temp
│   ├── qftp-quic/             # quiche 設定、TLS モード、retry、SCID、0-RTT、mio ループ骨格、framing、GSO
│   ├── qftp-server/           # lib(run(config))+ bin
│   ├── qftp-client-core/      # Session API、trust、tickets、config
│   ├── qftp-client/           # CLI、REPL、one-shot(Phase 6: sync、watch)
│   ├── qftp-admin/
│   ├── qftp-conformance/      # gen-vectors + 適合テスト
│   ├── qftp-testkit/          # プロセス内サーバフィクスチャ + クライアントコア
│   ├── qftp-e2e/              # e2e テストのみ(publish = false)
│   ├── qftp-bench/            # criterion(cargo test から除外、乱数ペイロード)
│   └── qftp-web-bridge/       # Phase 7
├── fuzz/                      # ワークスペース内。stable では cargo check のみ、実行は nightly の定期ジョブ
├── examples/
│   ├── systemd/qftp-server.service
│   └── docker-compose/
├── scripts/                   # gen-test-mtls.sh、bench.sh
├── Dockerfile
└── .github/workflows/         # ci.yml(stable + MSRV、Linux + macOS、aarch64 cross)、fuzz.yml、release.yml
```

## 依存方向(上位 → 下位のみ)

```
qftp-wire ◀── qftp-core ◀── qftp-quic ◀── qftp-server ◀── qftp-testkit ◀── qftp-e2e / qftp-bench
                 ▲              ▲              ▲
                 │              └── qftp-client-core ◀── qftp-client
                 ├── qftp-admin(スキーマのみ)
                 ├── qftp-web-bridge(Phase 7)
                 └── fuzz
qftp-conformance ◀── qftp-wire
```

規則:

- `qftp-wire` は QUIC・tokio・ファイルシステムに依存しない。
- `qftp-core` は QUIC を知らない(sans-I/O)。
- `qftp-quic` はファイルシステムを知らない。
- バイナリの `main` は「設定を読む → ライブラリの `run` を呼ぶ」だけにする。

## モジュール骨子

| クレート | モジュール |
|---|---|
| `qftp-wire` | `message`(Request / Response / ErrorCode / ErrorDetails / DirEntry / FileStat / FileType / HashAlgorithm / Encoding)、`codec`(`WireEncode` / `WireDecode`、フレーム長プレフィクス)、`limits`、`validate`(フィールド上限、安全名) |
| `qftp-core` | `path`(walk_safe / resolve / resolve_parent / recheck)、`user`(schema / directory / quota / claim)、`identity`(x509 → 候補 → 解決)、`fs_ops`(Ls ページング / Stat / Mkdir / Rmdir / Rm / Rename / Chmod / Quota)、`transfer::{server, client, event, cmd, accounting}`、`compress`(zstd 単一フレーム、既圧縮判定)、`temp`(`TempName`)、`sweep` |
| `qftp-quic` | `config::{server, client}`(transport parameters)、`tls::{materials, self_signed, modes}`、`retry`(token)、`scid`、`zero_rtt`(許可リスト、identity gate)、`event_loop`(mio、Waker、timers)、`framing`(quiche ストリーム上の send / recv_message)、`egress`(GSO)、`limits`(接続上限、レートバケット) |
| `qftp-server` | `config`、`accept`、`connection`(状態、cwd、ストリーム表)、`dispatch`(要求ゲートと分岐)、`io_pool`、`host`(転送エンジンのホスト実装)、`metrics`、`health`、`shutdown`、`main` |
| `qftp-client-core` | `session`(connect / request / get / put / close)、`trust`(CA / TOFU / insecure、known_hosts)、`tickets`、`config`(resolve)、`resume`、`host`(クライアント側エンジンのホスト実装)、`options` |
| `qftp-client` | `cli`、`repl::{parser, commands, completer}`、`oneshot`、`output`(整形、JSON、終了コード)、Phase 6: `sync`、`watch` |
| `qftp-testkit` | `server_fixture`(プロセス内 `run`)、`client`(Session ラッパ)、`certs`(rcgen)、`fs`(一時ディレクトリ、乱数ファイル) |

## CI 構成

- `check`: fmt、clippy `-D warnings`、build、test(bench は除外)、conformance 再生成 → diff。
- `msrv`: 宣言 MSRV での build + test。
- `cross`: aarch64-unknown-linux-gnu の build。
- `macos`: build + test。
- `deny`: advisories / licenses / sources / bans(cargo-audit は統合)。
- `fuzz-check`: stable で `cargo check -p qftp-fuzz`。
- `fuzz`(定期、nightly): 各ターゲット 180 s、corpus キャッシュ。
- `release`(タグ): test → 4 ターゲット tarball + sha256 → deb → GitHub Release。方式は決定事項(手書き workflow か cargo-dist)に従い、文書と一致させる。
