# 運用設計書 セクション仕様

## 1. 概要 (overview)
- 対象システム (target-system): 運用対象のシステム名・サブシステム範囲
- 運用範囲 (scope): この設計書が扱う運用領域（監視のみ / 監視+障害対応 / 全運用）
- 担当体制 (team): 運用担当・オンコール体制・関係部署

## 2. SLO・SLA (service-levels)
- サービスレベル目標 (slo): 内部目標（可用性%・レイテンシ等の数値）
- 顧客約束 (sla): 顧客に対する公式な約束（あれば）
- エラーバジェット (error-budget): 許容ダウンタイム・期間あたりの計算方法

## 3. 監視 (monitoring)
- 監視対象 (targets): メトリクス・ログ・トレース・合成監視の対象
- 監視ツール (tools): 使用する監視サービス（Datadog / CloudWatch / Prometheus 等）
- ダッシュボード (dashboards): 主要ダッシュボードのURL・用途

## 4. アラート (alerting)
- アラート条件 (conditions): 何の値がどう変化したら発火するか
- 通知先・エスカレーション (escalation): 一次通知先・エスカレーション順・時間
- 静観条件 (silence-rules): 計画メンテ・既知障害時の静観方法

## 5. 障害対応 (incident-response)
- 障害分類 (severity-classification): Sev1〜Sev3 等の定義と判断基準
- 初動手順 (initial-response): 検知から一次対応までの流れ
- 連絡フロー (communication): 社内外への報告タイミング・テンプレート
- ポストモーテム方針 (postmortem-policy): 何を起点に・誰が・いつまでに作るか

## 6. バックアップ・リストア (backup-restore)
- バックアップ対象・頻度 (backup-targets): 何を・どれくらいの頻度で取るか
- 保管期間・場所 (retention): 保管期間・保管先・暗号化
- リストア手順 (restore-procedure): 復旧手順の概要・所要時間
- RTO/RPO (rto-rpo): 目標復旧時間・目標復旧時点

## 7. 定期作業 (routine-operations)
- 日次・週次・月次タスク (recurring-tasks): 定期実行する人手作業
- 自動化状況 (automation): 自動化済み・未自動化の区分
- 証跡管理 (audit-records): 実施記録の残し方・監査対応

## 8. キャパシティ管理 (capacity)
- 現状リソース使用率 (current-usage): 計測中のリソースと現在値
- 増強判断基準 (scale-up-criteria): スケールアウト/アップを判断する閾値
- 想定成長率 (growth-forecast): 中長期の負荷増加見込み

## 9. 関連資料 (references)
- 関連設計書 (related-docs): アーキテクチャ設計書・機能設計書・障害対応手順書など
- 外部設計成果物 (artifacts): drawio (構成図)・Runbook・ダッシュボードURL 等
