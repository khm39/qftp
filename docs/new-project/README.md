# qftp 設計パッケージ

作成日: 2026-09-03

QUIC 上のファイル転送プロトコル **qftp/1** と、そのリファレンス実装(サーバ、クライアント、管理 CLI、Web ブリッジ)の仕様・設計一式です。**このパッケージだけで自己完結**しており、外部のリポジトリを参照する必要はありません。工程や進め方は含みません。

## 構成

| ディレクトリ | 内容 |
|---|---|
| `00-background/` | `decisions.md`: 設計を縛る決定(ADR-001〜015)。状況・決定・理由・帰結の形式 |
| `10-protocol/` | ワイヤプロトコル仕様(正本)。README / qftp-protocol / wire-format / error-codes / versioning / security-model / protocol-changelog、`test-vectors/`。**`qftp-protocol-guide.html`**(図解版: シーケンス図・バイト配置図・ベクタの注釈つきダンプ。非規範) |
| `20-design/` | 設計書(HTML)。アーキテクチャ、機能(転送エンジン / サーバ / クライアント / Web ブリッジ)、シーケンス(接続確立 / Get / Put)、運用 |
| `30-repository/` | `repository-layout.md`: クレート構成(7 + fuzz)、依存方向、ディレクトリ、モジュール骨子、CI 構成 |
| `40-reference/` | 実装契約(HTML): 転送エンジン API、設定、CLI、ファイル形式、テスト仕様 |
| `tools/` | 設計書・参照文書・図解版の生成器(Python 3、標準ライブラリのみ)。`QFTP_DESIGN_ROOT` 未設定時はパッケージ自身を出力先にする |

## 機能の区分

機能は次の 4 区分で表します。区分は機能の集合と依存関係の名前であり、実装順序ではありません(定義はアーキテクチャ設計書 §1.2)。

| 区分 | 内容 |
|---|---|
| コア | 全リクエスト、Get / Put(再開・BLAKE3・zstd)、Ls ページネーション、mTLS / ACL / クォータ、0-RTT / retry / レート制限、TLS モードと TOFU、metrics、REPL と one-shot |
| 拡張 | 再帰転送、mget、双方向 bwlimit、qftp-admin、systemd / Docker / release 成果物、ベンチ |
| 同期 | sync、watch |
| Web | qftp-web-bridge、SPA、tokens.toml |

## 設計書一覧(`20-design/`)

| ファイル | 種類 | 記入状況 |
|---|---|---|
| `architecture-qftp.html` | アーキテクチャ設計書 | 全項目 |
| `feature-transfer-engine.html` | 機能設計書: 転送エンジン(sans-I/O) | 全項目 |
| `feature-server.html` | 機能設計書: ネイティブサーバ | 全項目 |
| `feature-client.html` | 機能設計書: ネイティブクライアント | 全項目 |
| `feature-web-bridge.html` | 機能設計書: Web ブリッジ(Web 区分) | 性能・可用性が未記入 |
| `sequence-connection-setup.html` | シーケンス設計書: 接続確立 | 全項目 |
| `sequence-get-transfer.html` | シーケンス設計書: Get | 全項目 |
| `sequence-put-transfer.html` | シーケンス設計書: Put | 全項目 |
| `operations-qftp-server.html` | 運用設計書 | 運用主体が決める項目(体制、SLO / SLA / エラーバジェット、ダッシュボード、通知先、連絡フロー、ポストモーテム、保管期間、RTO / RPO、証跡、現状使用率、成長率)は未記入 |

管理 CLI は機能設計書を持たず、CLI リファレンスとファイル形式リファレンスで規定します。画面設計書(Web クライアント)は未作成で、Web 区分の設計時にテンプレートから作成します。

「未記入」項目は各 HTML 内で赤い枠で表示されます。設計書の正本は `tools/<module>.py` の `ANSWERS`(セクション ID.項目 ID → HTML)で、HTML 末尾の JSON はそこから生成した写しです。

## 文書間の役割分担と更新規則

- 正本の優先順位: `10-protocol/` の Markdown 仕様書 > 参照文書(`40-reference/`) > 設計書(`20-design/`) > 図解版。食い違いは上位が勝ちます。
- 設計書は「目的・スコープ・判断・リスク」を持ち、契約(型・設定キー・CLI・ファイル形式)は参照文書にだけ書きます。設計書からはリンクで参照します。
- 図解版 `10-protocol/qftp-protocol-guide.html` は非規範です。バイト列の例は `tools/guide.py` がベクタから機械生成しますが、本文は手書きです。Markdown 仕様書を改訂したら図解版の該当節も更新し、`python3 tools/guide.py` で再生成してください。
- 参照文書と設計書は `tools/` の生成器から生成します。HTML を直接編集せず、生成器を編集して再生成してください(`python3 tools/build.py architecture feature_engine …`、`python3 tools/ref_engine.py` など。テンプレートは `tools/templates/` に同梱)。

## 主要な決定(要約)

1. ワイヤプロトコル `qftp/1` は凍結済み。仕様は `10-protocol/` が正本。
2. ネイティブサーバ / クライアントの QUIC スタックは **quiche**、ランタイムは **tokio(current_thread)**(ADR-001)。
3. Get / Put の転送エンジンは **sans-I/O の状態機械**として 1 実装し、quiche ドライバ・ブリッジ・テストが共有する(ADR-002)。
4. ワイヤ符号化は手書き codec(ADR-003)。ディスク I/O は tokio のブロッキングプールへ(ADR-005)。
5. クレートは 7 つ(wire / core / quic / server / client-core / client / admin)+ fuzz(ADR-007)。
6. Web ブリッジは wtransport の別バイナリ(ADR-006)。Ls カーソルは base64url(ADR-008)。Put は応答並行読み(ADR-009)。

## 仕様外(記載しないもの)

- 実装の順序・工程・完了条件。
- 運用主体が決める数値(SLO、体制、バックアップ頻度、キャパシティ)。運用設計書では未記入のままにしています。
- 実装前に実機で確認すべき技術項目は ADR-001 の帰結に列挙しています。
