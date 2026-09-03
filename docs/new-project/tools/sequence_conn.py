DOC_TYPE="sequence"; TITLE="接続確立(retry / ハンドシェイク / identity / 0-RTT ゲート)"; FILENAME="sequence-connection-setup.html"
ANSWERS={
"overview.name":"<p>接続確立シーケンス。クライアントの最初の Initial から、最初の要求が実行可能になるまで。</p>",
"overview.use-case":"<p><code>qftp-client</code> の接続(REPL / one-shot / ライブラリ利用)。</p>",
"overview.purpose":"<p>アドレス検証(retry)、TLS 1.3 ハンドシェイク、mTLS identity 解決、0-RTT 再開とそのゲートを、サーバとクライアントの両側で定める。</p>",
"overview.scope":"<p>開始: クライアントが UDP ソケットを bind して Initial を送る。終端: サーバが最初の 1-RTT 要求を ACL まで通す(要求の実行自体は Get / Put シーケンスなど)。</p>",
"preconditions.initial-state":"<ul><li>サーバは bind 済みで、TLS 材料と users.toml を読み込み済み。</li><li>クライアントは接続先(host:port、SNI)と信頼ポリシーを解決済み。0-RTT を使う場合は同一ホスト・同一フィンガープリントの有効チケットを持つ。</li></ul>",
"preconditions.inputs":"<ul><li>クライアント: 接続先、SNI、CA / known_hosts、クライアント証明書(任意)、チケット(任意)。</li><li>サーバ: <code>require_retry</code>、接続上限、Initial レートバケット、mTLS 設定、users。</li></ul>",
"preconditions.auth-state":"<p>未認証。mTLS 時は TLS ハンドシェイク完了で identity が確定する。それまでは anonymous 扱いで、early data は identity gate の対象。</p>",
"actors.actors":"<ul><li>クライアント(qftp-client-core)</li><li>サーバ(qftp-server)</li></ul>",
"actors.components":"<ul><li>クライアント: <code>Session::connect</code>、<code>TrustPolicy</code>、<code>TicketStore</code>、quiche クライアント接続。</li><li>サーバ: 受付(<code>accept</code>)、<code>RetryToken</code>、<code>ConnectionCounter</code>、<code>RateBuckets</code>、<code>ScidDeriver</code>、identity 解決(<code>qftp-core::identity</code>)、<code>ZeroRttGate</code>。</li></ul>",
"actors.roles":"<ul><li>受付: Initial の妥当性・レート・上限・retry を判定し接続を作る。</li><li>identity 解決: peer cert から候補を抽出し users に照合、cwd を home に設定。</li><li>ZeroRttGate: early data 中の要求を許可リストと identity gate で判定。</li><li>TrustPolicy: ハンドシェイク後、アプリケーションデータ送出前に検証。</li></ul>",
"steps.main-flow":"""<pre>
Client                                   Server
  │ Initial (SNI, ALPN qftp/1, [0-RTT])    │
  ├───────────────────────────────────────▶│ 1. DCID 長 8..=20 でなければ破棄
  │                                        │ 2. Initial レートバケット(per-IP)不足なら破棄
  │            Retry (token)               │ 3. require_retry かつ token なし → Retry 送出
  │◀───────────────────────────────────────┤
  │ Initial (token)                        │
  ├───────────────────────────────────────▶│ 4. token 検証(HMAC、60 s、addr、dcid)
  │                                        │ 5. 接続スロット取得(global / per-IP)
  │                                        │ 6. SCID = HMAC(seed, client_dcid)[..20]
  │                                        │ 7. quiche::accept、anonymous で登録
  │ ... TLS 1.3 ハンドシェイク ...            │
  │ [early data: Request on stream 0]      │ 8. early data 中の要求は ZeroRttGate へ
  │◀──────────────────────────────────────▶│
  │ HANDSHAKE_DONE                         │ 9. established: peer cert → identity 解決
  │                                        │    cwd = home。mTLS 必須で cert なし → close 0x101
  │ 10. TrustPolicy 検証(CA: ホスト名 / TOFU: pin)
  │     失敗 → close、データ未送出
  │ Request (1-RTT)                        │
  ├───────────────────────────────────────▶│ 11. 要求レートバケット → ACL → 実行
</pre>""",
"steps.sync-async":"<ul><li>全ステップは QUIC パケットの往復で駆動される非同期処理。サーバはイベントループ 1 ティック内で 1 パケットを処理する。</li><li>identity 解決(x509 解析)は同期(数十 µs)でループ上で行う。</li><li>接続確立後の要求はストリーム単位で独立。</li></ul>",
"steps.state-transitions":"""<table><tr><th>状態</th><th>遷移条件</th><th>次状態</th></tr>
<tr><td>(なし)</td><td>Initial 受理</td><td>HalfOpen(anonymous, created_at)</td></tr>
<tr><td>HalfOpen</td><td>5 s 経過</td><td>破棄</td></tr>
<tr><td>HalfOpen</td><td>established かつ identity OK</td><td>Established(user, cwd=home)</td></tr>
<tr><td>HalfOpen</td><td>established かつ identity NG</td><td>Closing(0x101)</td></tr>
<tr><td>Established</td><td>Quit / アイドル 30 s / シャットダウン</td><td>Closing</td></tr>
<tr><td>Closing</td><td>quiche が closed</td><td>reap</td></tr></table>""",
"steps.transaction-boundary":"<p>N/A(トランザクションなし。接続スロットは RAII で、接続の reap で解放される)。</p>",
"diagram.diagram-link":"<p>N/A(本文のテキスト図で代替。drawio は作成しない)</p>",
"diagram.diagram-summary":"<p>上のテキスト図は、retry を要求するサーバに対する初回接続(チケットなし)と、チケットありで early data を送った場合の両方を 1 本にまとめています。early data 中の要求は許可リスト(Cd / Pwd / Stat / Quit)かつ identity gate 非該当のときのみ実行され、それ以外は <code>Unsupported</code> で拒否されクライアントがハンドシェイク後に即時再送します。</p>",
"exceptional-flows.failure-cases":"""<ul><li>ALPN 不一致: ハンドシェイク失敗。クライアントは「サーバはこのバージョンを話さない」と報告(69)。</li><li>token 不正 / 期限切れ: 黙って破棄。クライアントは次の Initial で新しい Retry を受ける。</li><li>接続上限: 破棄 + <code>connections_rejected_caps</code>。</li><li>mTLS 必須で cert なし、未知 CN、複数ユーザ一致: close <code>0x101</code>。クライアントは 77。</li><li>TOFU 不一致: クライアントが close、77。</li><li>チケット拒否(サーバ側 0-RTT 不可): quiche が 1-RTT にフォールバック。チケットは破棄して再取得。</li><li>early data 中の不許可要求: <code>Unsupported</code>、クライアントは即時再送。</li></ul>""",
"exceptional-flows.timeout-retry":"<ul><li>クライアントのアドレスごとのハンドシェイク予算 8 s(最後のアドレスは quiche の idle 30 s)。</li><li>同一アドレスへの自動再試行はしない(watch のみ再接続ループ)。</li><li>サーバの half-open 5 s、アイドル 30 s。</li><li>retry token 有効 60 s。</li></ul>",
"exceptional-flows.compensation":"<p>N/A(状態を持たない。接続スロットとレートトークンは破棄時に返却される)。</p>",
"exceptional-flows.partial-failure":"<p>ハンドシェイク途中の切断は half-open reap で回収。identity 昇格前に early data で実行された許可リスト要求(anonymous のみ実行可能なサーバ)は読み取り専用で副作用がない。</p>",
"non-functional.latency":"<ul><li>初回接続(retry あり): 2 RTT + ハンドシェイク 1 RTT。</li><li>チケットあり: 0-RTT 再開で 1 RTT(early data を使わないため要求は 1-RTT 完了後)。</li></ul>",
"non-functional.idempotency":"<p>Initial の再送は SCID 導出により同一接続に収束する(重複接続を作らない)。early data は再生可能なため、許可リストは冪等・小応答の読み取りに限る。</p>",
"non-functional.concurrency":"<ul><li>接続スロットとレートバケットはイベントループ単一スレッドで扱い、ロックなし。</li><li>identity 昇格中に到着した要求は、昇格後のユーザで再評価する(昇格前に worker に投げた結果は破棄して <code>Unsupported</code> にする)。</li></ul>",
"non-functional.audit":"<ul><li>接続開始(peer addr、SCID、retry 有無)、identity 結果(候補、一致ユーザ / 拒否理由)、0-RTT 受理 / 拒否件数、close 理由をログとメトリクスに残す。</li><li>トークンやチケット内容はログに出さない。</li></ul>",
"references.related-docs":"<ul><li><a href=\"feature-server.html\">サーバ機能設計書</a></li><li><a href=\"feature-client.html\">クライアント機能設計書</a></li><li><a href=\"../10-protocol/qftp-protocol.md\">qftp-protocol.md</a>(0-RTT、retry、接続 ID 導出)</li></ul>",
"references.artifacts":"<p>N/A</p>",
}
