# 画面設計書 セクション仕様

## 1. 概要 (overview)
- 画面名 (name): 画面の名称
- 画面ID (screen-id): システム内での識別子（例: `SCR-001`、ルーティングパス `/cart` など）
- 目的 (purpose): この画面が果たす役割・ユーザーが達成したいこと
- 利用ユーザー (target-user): 想定する閲覧者・操作者

## 2. 画面イメージ (mockup)
- モックアップ (image): 画面の見た目。優先順位は (a) HTML/CSS で擬似モックを描く（完全に自己完結） (b) 画像 data URI で埋め込み (c) 相対パスで画像参照。複数バリエーション（デスクトップ/モバイル/状態別）があれば並べる
- 出所 (source): Figma エクスポート・手描き・HTML/CSS 生成 など。元データへのリンクを残す
- 注釈 (annotations): 図中のポイント解説。要素番号 → 意味の対応表でもよい

## 3. 画面遷移 (navigation)
- 遷移元 (from): どの画面から来るか
- 遷移先 (to): どの画面へ進むか・条件
- 遷移図 (flow-diagram): Mermaid flowchart で画面遷移を表現（必要なら）

## 4. レイアウト (layout)
- レイアウト概略 (overview): 画面構成の言葉での説明（ヘッダ・メイン・サイドバー等）
- 主要領域 (regions): 領域ごとの役割・配置
- レスポンシブ対応 (responsive): ブレークポイント・モバイル/デスクトップの差異

## 5. UI要素 (ui-elements)
- 入力要素 (inputs): フォーム項目・バリデーション・初期値
- ボタン・アクション (actions): ボタンラベル・遷移先・呼び出すAPI
- 表示要素 (displays): テーブル・カード・グラフ等の表示項目
- アイコン・画像 (visuals): 使うアイコン・画像とその意味

## 6. 状態と振る舞い (states)
- 画面状態 (screen-states): 初期表示・ローディング中・空状態・エラー・成功
- 動的挙動 (interactions): クリック/ホバー/スクロール時の挙動
- バリデーションメッセージ (validation-messages): エラー表示の文言と表示位置

## 7. データ・API連携 (data)
- 表示データの取得元 (data-source): どのAPI/データから取得するか
- 更新操作の送信先 (data-sink): 入力データの送信先API
- 取得失敗時の挙動 (data-failure): API失敗時の表示・リトライ方針

## 8. アクセシビリティ (accessibility)
- キーボード操作 (keyboard): タブ順序・ショートカット
- スクリーンリーダー (screen-reader): aria属性・ラベル付け
- 色・コントラスト (visual): 色覚配慮・最小コントラスト比

## 9. 関連資料 (references)
- 関連ドキュメント (docs): 機能設計書・要件定義書へのリンク
- デザインカンプ (design-assets): Figma URL・drawio・スクリーンショットの相対パス
