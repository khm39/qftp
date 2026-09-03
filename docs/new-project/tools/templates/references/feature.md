# 機能設計書 セクション仕様

## 1. 概要 (overview)
- 機能名 (name): 何の機能か。短い名詞句で
- 目的 (purpose): なぜこの機能を作るのか。解決する課題・ビジネス価値
- 想定ユーザー (target-user): 誰が使うか。役割・属性
- 利用シーン (use-case): いつ・どこで使われるか。代表的なシナリオ1〜3個

## 2. スコープ (scope)
- 含むもの (in-scope): この機能で実装するもの
- 含まないもの (out-of-scope): 今回はやらないと明示するもの（誤解を防ぐため必須）
- 前提条件 (assumptions): すでに整っている前提・依存する仕様

## 3. 機能要件 (functional-requirements)
- 主要フロー (main-flow): ハッピーパスの動作手順を順序付きで
- 入力 (inputs): ユーザーから受け取るデータ・操作
- 出力 (outputs): 機能の結果・表示・通知
- ビジネスルール (business-rules): バリデーション・計算式・状態遷移など
- 異常系・例外処理 (exceptional-cases): エラー・失敗時の挙動

## 4. 非機能要件 (non-functional-requirements)
- 性能 (performance): レスポンスタイム・スループット目標
- セキュリティ (security): 認証・認可・データ保護
- 可用性 (availability): SLA・障害時挙動
- ロギング・監視 (observability): 取得するログ・メトリクス

## 5. 影響範囲・連携 (impact)
- 影響する既存機能 (affected-features): 改修が必要な周辺機能
- 外部システム連携 (external-systems): 呼び出すAPI・連携するサービス
- データモデル変更 (data-changes): 追加/変更するテーブル・カラム（詳細は別管理のDB設計を参照）

## 6. リスク・代替案 (risks)
- リスク (risks): 技術リスク・運用リスク・スケジュールリスク
- 代替案と棄却理由 (alternatives): 検討した別案・なぜ選ばなかったか

## 7. 関連資料 (references)
- 関連ドキュメント (docs): 仕様書・議事録・Issue へのリンク
- 外部設計成果物 (artifacts): drawio (DB設計)・OpenAPI (API仕様)・Figma 等の相対パスまたはURL
