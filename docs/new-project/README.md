# qftp 新規プロジェクト 設計パッケージ

作成日: 2026-09-03 / 更新: 2026-09-03(クレート構成を 12 → 8 に整理、ADR-006 を wtransport で確定、ADR-001/005 を tokio current_thread に変更、プロトコル図解版 HTML を追加)

本パッケージは、QUIC 上のファイル転送プロトコル **qftp/1** の実装を新規リポジトリで起こすための設計一式です。**このパッケージだけで自己完結**しており、プロトタイプのリポジトリを参照する必要はありません。

## 構成

| ディレクトリ | 内容 | 状態 |
|---|---|---|
| `00-background/` | `prototype-assessment.md`(プロトタイプの挙動棚卸しと問題一覧)、`decisions.md`(ADR-001〜006) | 完成 |
| `10-protocol/` | ワイヤプロトコル仕様(正本)。README / qftp-protocol / wire-format / error-codes / versioning / security-model / protocol-changelog、`test-vectors/`。**`qftp-protocol-guide.html`**(図解版: シーケンス図・バイト配置図・ベクタの注釈つきダンプ。非規範) | 完成(凍結済み仕様の移植 + 図解版) |
| `20-design/` | 設計書(HTML、ブラウザで開く。印刷対応) | 骨組み + 判明分を記入 |
| `30-plan/` | `roadmap.md`(フェーズと完了条件)、`repository-layout.md`(リポジトリ構成と 8 クレート) | 完成 |

## 設計書一覧(`20-design/`)

| ファイル | 種類 | 記入状況 |
|---|---|---|
| `architecture-qftp.html` | アーキテクチャ設計書 | 全項目記入 |
| `feature-transfer-engine.html` | 機能設計書: 転送エンジン(sans-I/O) | 全項目記入 |
| `feature-server.html` | 機能設計書: ネイティブサーバ | 全項目記入 |
| `feature-client.html` | 機能設計書: ネイティブクライアント | 全項目記入 |
| `feature-admin.html` | 機能設計書: 管理 CLI | 全項目記入 |
| `feature-web-bridge.html` | 機能設計書: Web ブリッジ(Phase 7) | 性能・可用性が未記入 |
| `sequence-connection-setup.html` | シーケンス設計書: 接続確立 | 全項目記入 |
| `sequence-get-transfer.html` | シーケンス設計書: Get | 全項目記入 |
| `sequence-put-transfer.html` | シーケンス設計書: Put | 全項目記入 |
| `operations-qftp-server.html` | 運用設計書 | 監視・アラート・障害対応・定期作業を記入。SLO / 体制 / バックアップ頻度 / キャパシティ実測は未記入 |
| `screen-web-client.html` | 画面設計書: Web クライアント(Phase 7) | 遷移・要素・状態を記入。モックアップ / レイアウト詳細 / アクセシビリティは未記入 |

「未記入」項目は各 HTML 内で赤い枠で表示されます。項目を埋める際は、HTML 末尾の `<script id="design-doc-meta">` の JSON(`answers`)がソース・オブ・トゥルースです(同じキーで本文と JSON の両方を更新してください)。

## 主要な決定(要約)

1. ワイヤプロトコル `qftp/1` は凍結済みのまま引き継ぎ、実装のみ書き直す。
2. ネイティブサーバ / クライアントの QUIC スタックは **quiche**、ランタイムは **tokio(current_thread)**(ADR-001)。
3. Get / Put の転送エンジンは **sans-I/O の状態機械**として 1 実装し、quiche ループ・ブリッジ・テストが共有する(ADR-002)。
4. ワイヤ符号化は手書き codec(ADR-003)。ディスク I/O は tokio のブロッキングプールへ(ADR-005)。
5. クレートは 8 つ(wire / core / quic / server / client-core / client / admin / e2e)+ fuzz。conformance・testkit・bench は独立クレートにしない。
6. MVP はサーバ + CLI クライアント。再帰転送・admin は Phase 5、sync / watch は Phase 6、Web は Phase 7。

## 未決事項

- Phase 0 の quiche spike の結果(early data ゲート、tokio-quiche の可否)。
- 運用 SLO・体制・バックアップ方針(運用設計書)。
- sync `--checksum` と `put-multi` の存廃(推奨: 前者はフラグ削除、後者は廃止)。
- リリース方式(手書き workflow か cargo-dist)。
