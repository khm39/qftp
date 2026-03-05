# CLAUDE.md

## プロジェクト概要

QFTP (QUIC File Transfer Protocol) — QUICプロトコル上に構築されたRust製ファイル転送システム。UDP + TLS暗号化による安全なファイル操作を提供する。QUICトランスポートに`quiche`、バイナリプロトコルのシリアライズに`bincode`を使用。

## リポジトリ構成

```
crates/
├── qftp-common/       # 共通プロトコル定義 & QUICトランスポート層
│   └── src/
│       ├── lib.rs         # protocol・transportモジュールの再エクスポート
│       ├── protocol.rs    # Request/Responseのenum、DirEntry、FileStat型
│       └── transport.rs   # 長さプレフィクス付きメッセージング、QUIC設定ヘルパー
├── qftp-server/       # ファイルサーバー（単一接続、mioイベントループ）
│   └── src/
│       ├── main.rs        # サーバー起動、QUIC接続管理、イベントループ
│       └── handler.rs     # コマンド別リクエストハンドラー（ls, get, put等）
└── qftp-client/       # 対話型クライアント（REPL）
    └── src/
        ├── main.rs        # クライアント起動、QUIC接続、ストリーム管理
        └── repl.rs        # コマンド解析、出力フォーマット
```

## ビルド・実行

```sh
# 全クレートをビルド
cargo build

# リリースモードでビルド
cargo build --release

# サーバー起動（指定ディレクトリをルートとして公開）
cargo run -p qftp-server -- --root /path/to/serve

# クライアント起動
cargo run -p qftp-client -- --host 127.0.0.1

# コンパイルチェックのみ
cargo check

# clippyリント実行
cargo clippy --all-targets
```

## テスト

自動テストは未整備。サーバーとクライアントを手動で起動して動作確認を行う。

## アーキテクチャと主要な設計方針

### プロトコル (`qftp-common/src/protocol.rs`)
- enum型の`Request`/`Response`をserde + bincodeでシリアライズ
- 対応コマンド: Ls, Cd, Pwd, Get, Put, Mkdir, Rmdir, Rm, Rename, Chmod, Stat, Quit
- 構造化型: `DirEntry`（ディレクトリ一覧）、`FileStat`（ファイルメタデータ）

### トランスポート層 (`qftp-common/src/transport.rs`)
- 長さプレフィクス付きフレーミング: 4バイトビッグエンディアンu32ヘッダー + ペイロード
- 最大メッセージサイズ: 16 MB
- ストリームバッファ: 64 KBチャンク (`STREAM_BUF_SIZE`)
- QUIC接続制限: 合計10 MB、ストリームあたり1 MB
- ALPNプロトコル識別子: `"qftp"`
- アイドルタイムアウト: 30秒

### サーバー (`qftp-server/`)
- 同時接続数1（並行接続は拒否）
- ストリームごとの状態機械: `ReadingRequest` → `ReadingFileData` → `Done`
- ルートディレクトリのサンドボックス化 — パスの正規化により全パスをルート配下に制限
- 最大アップロードサイズ: 1 GB
- 起動時に`rcgen`で自己署名TLS証明書を自動生成

### クライアント (`qftp-client/`)
- `rustyline`によるREPL（履歴機能付き）
- クライアント起点の双方向QUICストリーム（ID: 0, 4, 8, ...）
- 人間が読みやすいファイルサイズ（KB/MB/GB）とUnixパーミッション表示

## コードスタイル

- **Rust edition 2021**
- エラー処理: アプリケーションエラーには`anyhow::Result`、commonクレートの型付きエラーには`thiserror`
- ログ: `log`マクロ (`info!`, `warn!`, `error!`) + `env_logger`
- CLI引数: `clap` deriveマクロ
- Rustのイディオム: パターンマッチ、`?`によるエラー伝播、enum型の状態機械
- コミットメッセージ: 命令形、内容を具体的に記述（例: "Extract config into shared function", "Fix ls to default to current directory"）

## 主要な定数

| 定数 | 値 | 定義場所 |
|---|---|---|
| `MAX_MESSAGE_SIZE` | 16 MB | `transport.rs` |
| `STREAM_BUF_SIZE` | 64 KB | `transport.rs` |
| `MAX_UPLOAD_SIZE` | 1 GB | `handler.rs` |
| QUIC最大データ量 | 10 MB | `transport.rs` |
| QUICストリーム最大データ量 | 1 MB | `transport.rs` |
| アイドルタイムアウト | 30秒 | `transport.rs` |

## 依存クレート

主要: `quiche`（QUIC）、`serde`+`bincode`（シリアライズ）、`mio`（非同期I/O）、`clap`（CLI）、`ring`（暗号）、`anyhow`/`thiserror`（エラー処理）、`rcgen`（証明書生成）、`rustyline`（REPL）
