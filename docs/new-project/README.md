# qftp 新規プロジェクト 設計パッケージ

作成日: 2026-09-03 / 更新: 2026-09-03(クレート構成を 12 → 8 に整理、ADR-006 を wtransport で確定、ADR-001/005 を tokio current_thread に変更、プロトコル図解版 HTML を追加、ADR-007〜013 を確定、40-reference/ を追加、管理 CLI 機能設計書と画面設計書を削除し重複を参照文書へ統合)

本パッケージは、QUIC 上のファイル転送プロトコル **qftp/1** の実装を新規リポジトリで起こすための設計一式です。**このパッケージだけで自己完結**しており、プロトタイプのリポジトリを参照する必要はありません。

## 構成

| ディレクトリ | 内容 | 状態 |
|---|---|---|
| `00-background/` | `prototype-assessment.md`(プロトタイプの挙動棚卸しと問題一覧)、`decisions.md`(ADR-001〜013) | 完成 |
| `10-protocol/` | ワイヤプロトコル仕様(正本)。README / qftp-protocol / wire-format / error-codes / versioning / security-model / protocol-changelog、`test-vectors/`。**`qftp-protocol-guide.html`**(図解版: シーケンス図・バイト配置図・ベクタの注釈つきダンプ。非規範) | 完成(凍結済み仕様の移植 + 図解版) |
| `20-design/` | 設計書(HTML、ブラウザで開く。印刷対応) | 骨組み + 判明分を記入 |
| `30-plan/` | `roadmap.md`(フェーズと完了条件)、`repository-layout.md`(リポジトリ構成と 7 クレート) | 完成 |
| `40-reference/` | 実装レベルの参照文書(HTML): 転送エンジン API、設定、CLI、ファイル形式、e2e テスト仕様 | 完成(初版) |

## 設計書一覧(`20-design/`)

| ファイル | 種類 | 記入状況 |
|---|---|---|
| `architecture-qftp.html` | アーキテクチャ設計書 | 全項目記入 |
| `feature-transfer-engine.html` | 機能設計書: 転送エンジン(sans-I/O) | 全項目記入 |
| `feature-server.html` | 機能設計書: ネイティブサーバ | 全項目記入 |
| `feature-client.html` | 機能設計書: ネイティブクライアント | 全項目記入 |
| `feature-web-bridge.html` | 機能設計書: Web ブリッジ(Phase 7) | 性能・可用性が未記入 |
| `sequence-connection-setup.html` | シーケンス設計書: 接続確立 | 全項目記入 |
| `sequence-get-transfer.html` | シーケンス設計書: Get | 全項目記入 |
| `sequence-put-transfer.html` | シーケンス設計書: Put | 全項目記入 |
| `operations-qftp-server.html` | 運用設計書 | 監視・アラート・障害対応・定期作業を記入。SLO / 体制 / バックアップ頻度 / キャパシティ実測は未記入 |

管理 CLI は機能設計書を持たず、CLI リファレンスとファイル形式リファレンスで規定します。画面設計書(Web クライアント)は Phase 7 開始時にテンプレートから作成します。

「未記入」項目は各 HTML 内で赤い枠で表示されます。項目を埋める際は、HTML 末尾の `<script id="design-doc-meta">` の JSON(`answers`)がソース・オブ・トゥルースです(同じキーで本文と JSON の両方を更新してください)。

## 文書間の役割分担と更新規則

- 設計書(`20-design/`)は「目的・スコープ・判断・リスク」を持ち、契約(型・設定キー・CLI・ファイル形式)は参照文書(`40-reference/`)にだけ書きます。設計書からはリンクで参照します。
- 図解版 `10-protocol/qftp-protocol-guide.html` は非規範です。バイト列の例は `tools/guide.py` がベクタから機械生成しますが、本文は手書きです。Markdown 仕様書を改訂したら図解版の該当節も更新し、`python3 tools/guide.py` で再生成してください。
- 参照文書は `tools/ref_*.py` から生成します。HTML を直接編集せず、生成器を編集して再生成してください。

## 主要な決定(要約)

1. ワイヤプロトコル `qftp/1` は凍結済みのまま引き継ぎ、実装のみ書き直す。
2. ネイティブサーバ / クライアントの QUIC スタックは **quiche**、ランタイムは **tokio(current_thread)**(ADR-001)。
3. Get / Put の転送エンジンは **sans-I/O の状態機械**として 1 実装し、quiche ループ・ブリッジ・テストが共有する(ADR-002)。
4. ワイヤ符号化は手書き codec(ADR-003)。ディスク I/O は tokio のブロッキングプールへ(ADR-005)。
5. クレートは 7 つ(wire / core / quic / server / client-core / client / admin)+ fuzz。conformance は wire の tests、e2e とベンチは server の tests / benches(ADR-007)。
6. MVP はサーバ + CLI クライアント。再帰転送・admin は Phase 5、sync / watch は Phase 6、Web は Phase 7。

## 未決事項

設計上の未決事項は 2026-09-03 にすべて決定済みです(ADR-007〜013)。残るのは運用主体が決める数値と、Phase 0 の spike で確定する技術項目です。

- Phase 0 の quiche spike の結果(early data ゲート、tokio current_thread 上の駆動構造、`try_io` 経由の GSO)。
- 運用 SLO・体制・バックアップ方針(運用設計書)。
