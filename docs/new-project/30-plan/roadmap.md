# ロードマップ(フェーズと完了条件)

各フェーズの完了条件(DoD)は「前フェーズまでの成果物に対して conformance と e2e が緑」を含みます。フェーズ番号は設計書からの参照に使うため固定します。

| Phase | 内容 | 完了条件 |
|---|---|---|
| 0 | 新リポジトリ作成、`10-protocol/` を `spec/` として配置、ADR 配置、CI 骨格(fmt / clippy / MSRV / aarch64 クロスビルド / conformance)、**quiche spike**(サーバ側 early data 受理と 1-RTT ゲート、stateless retry、tokio current_thread 上での quiche 駆動、`UdpSocket::try_io` 経由の GSO 送信、`spawn_blocking` 往復コストの粗い計測) | spike の結果を ADR-001 に追記。CI が空ワークスペースで緑 |
| 1 | `qftp-wire`(型、手書き codec、検証、定数、`tests/conformance.rs`、`examples/gen_vectors.rs`)、fuzz(request / response deser) | 全ベクタで双方向一致。旧フレーム(末尾フィールドなし)を新デコーダが読むケースをベクタ化 |
| 2 | `qftp-core`(path / user / identity / fs_ops(Ls ページング)/ transfer エンジン / compress / temp)を**ユニットテストのみ**で完成 | 純メモリホストで Get / Put の全経路(再開・圧縮・全失敗分類)をテスト。プロトタイプ評価文書 §9 の G1・G6・G8・G12・G13 が設計どおり |
| 3 | `qftp-quic` + `qftp-server`(MVP 機能)+ `test-util` フィクスチャ + `qftp-server/tests` の e2e | e2e: Ls ページング、Get / Put 往復、再開 3 種、zstd、mTLS(拒否 / Ambiguous)、retry、0-RTT 拒否、レート制限、接続上限、STOP_SENDING 耐性、graceful shutdown、HOL(大転送中の Ls 応答時間) |
| 4 | `qftp-client-core` + `qftp-client`(REPL / one-shot MVP) | クイックスタート(自己署名 + TOFU、ls / get / put / quit)が動く。終了コード規約の e2e。TOFU が one-shot でも効く |
| 5 | 再帰転送、mget、双方向 bwlimit、`qftp-admin`(トークン生成・SHA-256 保存)、metrics / systemd / Docker / release(手書き workflow)、ベンチ(`qftp-server/benches`) | プロトタイプの機能一覧と等価(sync / watch / put-multi / Web を除く) |
| 6 | sync / watch(`--checksum` と put-multi は作らない、ADR-010) | 各コマンドの e2e。`.qftpignore` 互換 |
| 7 | Web ブリッジ(wtransport、ADR-006 確定済み)+ SPA(WASM 共有の評価) | ブリッジ自クレートの `tests/` とブラウザ e2e(Playwright)。再開・圧縮・Cd がネイティブと同一 |

## フェーズ間の依存

```
0 ─▶ 1 ─▶ 2 ─▶ 3 ─▶ 4 ─▶ 5 ─▶ 6
                       └──────▶ 7 (5 と並行可)
```

Phase 4 終了時点で、プロトタイプの主要ユースケース(サーバ + CLI クライアント)を置き換えられます。プロトタイプリポジトリは Phase 5 完了までアーカイブせず参照専用として残します。

## 各フェーズで作る文書

| Phase | 追加・更新する文書 |
|---|---|
| 0 | ADR-001 追記(spike 結果)、CI 構成 |
| 2 | 転送エンジン設計書のイベント / コマンド型を実コードの `rustdoc` と一致させる |
| 3 | サーバ機能設計書の設定キーを実装と一致させる。運用設計書のメトリクス一覧を確定 |
| 4 | クライアント機能設計書の終了コード表を確定 |
| 5 | 運用設計書 §6〜§8(バックアップ、定期作業、キャパシティ)を運用主体と埋める |
| 7 | 画面設計書のモックアップ、WASM 共有評価の結果 |
