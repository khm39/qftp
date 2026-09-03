# アーキテクチャ設計書 セクション仕様

## 1. 概要 (overview)
- システム名 (name): アーキテクチャ設計の対象システム名
- 目的・対象範囲 (purpose): この設計書が扱う範囲。サブシステム単位かシステム全体か
- 想定読者 (audience): 開発者・運用・経営層など、誰に読まれる想定か
- 文書の位置付け (positioning): 既存ドキュメント階層のどこに位置するか（要件定義の下、機能設計の上 など）

## 2. ビジネス文脈 (business-context)
- 解決する課題 (problem): 既存システムや現状業務の課題
- ステークホルダー (stakeholders): 主要関係者と関心事
- 成功指標 (success-metrics): どうなれば成功と言えるか（定量・定性）

## 3. システム全体像 (system-overview)
- コンテキスト図 (context-diagram): 外部システム・利用者との関係（drawio 等の相対パス）
- 主要コンポーネント (components): 内部の主要要素と役割
- 外部システム連携 (external-systems): 連携する外部サービス・API
- データフロー (data-flow): コンポーネント間で流れる主要データ

## 4. 技術選定 (technology-stack)
- 採用技術 (choices): 言語・フレームワーク・ミドルウェア・クラウドサービス
- 採用理由 (rationale): なぜそれを選んだか
- 検討した代替案 (alternatives): 比較検討した別案と棄却理由
- 制約・前提 (constraints): 技術選定を縛った組織・予算・既存資産の制約

## 5. 品質特性 (quality-attributes)
- 性能 (performance): スループット・レイテンシ目標
- 可用性 (availability): SLO・冗長化方針
- スケーラビリティ (scalability): スケールアウト/アップ戦略、想定成長率
- セキュリティ (security): 認証・認可・データ保護の全体方針
- 運用性 (operability): 監視・デプロイ・障害復旧の容易さ

## 6. アーキテクチャ判断記録 (decisions)
- 主要な意思決定 (key-decisions): 設計上の重要な判断（マイクロサービス分割粒度、同期/非同期、データ整合性レベル など）
- トレードオフ (tradeoffs): 各判断で何を取り何を捨てたか
- 関連 ADR (related-adrs): 個別の判断記録へのリンク（存在すれば）

## 7. リスク・課題 (risks)
- 既知のリスク (known-risks): 技術リスク・スケジュールリスク・運用リスク
- 未解決の論点 (open-questions): まだ決まっていないこと
- 緩和策 (mitigations): リスクに対する対策・モニタリング方針

## 8. 関連資料 (references)
- 関連設計書 (related-docs): 機能設計書・運用設計書・要件定義書など
- 外部設計成果物 (artifacts): drawio (構成図・シーケンス図)・OpenAPI・Figma 等の相対パスまたはURL
