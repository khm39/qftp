DOC_TYPE="sequence"; TITLE="Get 転送(ダウンロード・再開・圧縮)"; FILENAME="sequence-get-transfer.html"
ANSWERS={
"overview.name":"<p>Get 転送シーケンス。</p>",
"overview.use-case":"<p>REPL の <code>get</code>、one-shot の <code>get</code>、再帰 get / mget、Web クライアントのダウンロード。</p>",
"overview.purpose":"<p>サーバのファイルをクライアントへ、再開可能かつ整合性検証つきで転送する。サーバ側は転送エンジンの <code>GetServer</code>、クライアント側は <code>GetClient</code> を、それぞれのホストが駆動する。</p>",
"overview.scope":"<p>開始: クライアントがローカル状態(既存ファイル長)から <code>offset</code> を決めてストリームを開く。終端: クライアントがトレーラを検証しローカルファイルを確定する(または削除する)。</p>",
"preconditions.initial-state":"<ul><li>接続確立済み、identity 解決済み。</li><li>ユーザに read 権限。</li><li>クライアントのローカル宛先は存在しないか regular file(再開)。</li></ul>",
"preconditions.inputs":"<p><code>Request::Get{path, offset, length, accept_encoding}</code>。<code>accept_encoding</code> は <code>[Zstd]</code>(<code>--no-compress</code> で空)。</p>",
"preconditions.auth-state":"<p>1-RTT。Get は early data で拒否される。</p>",
"actors.actors":"<ul><li>クライアント</li><li>サーバ</li></ul>",
"actors.components":"<ul><li>サーバ: ストリーム dispatch、パス解決(<code>spawn_blocking</code>)、<code>GetServer</code>、ブロッキングプール(ファイル I/O)、quiche ストリーム。</li><li>クライアント: <code>Session::get</code>、<code>GetClient</code>、ローカルファイル、quiche ストリーム。</li></ul>",
"actors.roles":"<ul><li>dispatch: 要求をデコードし、ACL とパス解決を通して <code>GetServer</code> を開始する。</li><li><code>GetServer</code>: FileReady、プレフィクス再ハッシュ、本体、トレーラを順に生成。</li><li><code>GetClient</code>: FileReady 検証、ローカルプレフィクスのハッシュ、本体書込、トレーラ照合。</li></ul>",
"steps.main-flow":"""<pre>
Client                                     Server
 1. offset = ローカル既存長(なければ 0)
 2. Get{path, offset, None, [Zstd]} ──────▶ 3. ACL(read) / パス解決 / temp 名拒否
                                            4. open O_NOFOLLOW|O_NONBLOCK, fstat: regular, ≤ max
                                            5. offset ≤ len ? else InvalidRange{Range}
                                            6. encoding = Zstd if ≥1024B && 非既圧縮 && 受理可
 7. ◀── FileReady{size,total,checksum=true,   7. Respond(FileReady)
        Blake3, encoding, plaintext_size}
 8. 検査: encoding 既知, size==plaintext(Zstd),
    offset+size == total_size
 9. ローカル [0,offset) をハッシュに畳む           9. ReadFile[0,offset) をチャンクで畳む(ワイヤ無)
10. ◀── body (identity | 単一 zstd frame) ──  10. ReadFile → hash → (encode) → Send
11. 書込 / 復号、平文カウンタ ≤ plaintext_size
12. ◀── trailer(32B) + FIN ────────────────  12. Send(trailer, fin)
13. hash == trailer ? 確定 : ローカル削除 (65)
</pre>""",
"steps.sync-async":"<ul><li>クライアントは要求を送ったあと、FileReady・本体・トレーラを 1 ストリーム上で順次受ける(非同期到着、エンジンは <code>Event::Bytes</code> で処理)。</li><li>サーバのファイル読み取りはブロッキングプールへの非同期要求。</li><li>クライアントのローカル書込は 初版では同期(ダウンロード側の HOL は単一要求のため問題にならない)。</li></ul>",
"steps.state-transitions":"""<table><tr><th>GetServer 状態</th><th>遷移</th></tr>
<tr><td>Start</td><td>検証 OK → Prefix(offset&gt;0) / Body(offset=0)</td></tr>
<tr><td>Prefix</td><td>ReadDone で残り 0 → Body</td></tr>
<tr><td>Body</td><td>読み取り済み == size かつ全送信 → Trailer</td></tr>
<tr><td>Trailer</td><td>Send(fin) 受理 → Done</td></tr>
<tr><td>任意</td><td>ReadFailed / Cancel → Failed(Reset)</td></tr></table>
<p>クライアント側は Requesting → Header → Prefix → Body → Trailer → Verified / Discarded。</p>""",
"steps.transaction-boundary":"<p>クライアントのローカルファイルは、トレーラ検証成功までは「未確定」。失敗時は削除する(再開用に残さない。次回は 0 から)。</p>",
"diagram.diagram-link":"<p>N/A(テキスト図)</p>",
"diagram.diagram-summary":"<p>ステップ 9 が再開の要です。両端が <code>[0, offset)</code> を再ハッシュするため、トレーラは常にファイル全体(または <code>length</code> 指定時は送出範囲まで)のダイジェストになり、サーバ側ファイルが同サイズで差し替わった場合も検出できます。</p>",
"exceptional-flows.failure-cases":"""<ul><li>NotFound / PermissionDenied / IsADirectory / FileTooLarge: FileReady の代わりに Err。</li><li>InvalidRange(ローカルの方が大きい、サーバ側で縮小): クライアントはローカルを削除し 0 から 1 回再試行(StalePartial)。</li><li>FileReady の不整合(<code>offset+size != total_size</code>、未知 encoding): プロトコルエラーとして中断、ローカル削除。</li><li>本体途中の FIN(短い本体): ローカル削除、65。</li><li>トレーラ不一致: ローカル削除、65。</li><li>サーバ側読み取り失敗(本体送出後): <code>ResetStream</code>。クライアントは reset を受けて中断、ローカルは削除。</li><li>zstd 復号失敗 / 平文超過: 中断、ローカル削除。</li></ul>""",
"exceptional-flows.timeout-retry":"<ul><li>要求単位のタイムアウトは設けない(QUIC アイドル 30 s に委ねる)。</li><li>StalePartial 再試行は 1 回。<code>RateLimited</code> は <code>RetryAfter</code> 後に 1 回。</li></ul>",
"exceptional-flows.compensation":"<p>ローカル側: 失敗時はファイル削除(flush 失敗のみ残す)。サーバ側: 状態を持たないため補償なし。</p>",
"exceptional-flows.partial-failure":"<p>途中で切断した場合、ローカルには受信済み分が残り、次回の <code>get</code> がその長さから再開する。プレフィクス再ハッシュにより、途中で壊れたローカルは最終的にトレーラ不一致で検出される。</p>",
"non-functional.latency":"<p>要求 → FileReady が 1 RTT + パス解決(<code>spawn_blocking</code> 往復)。再開時はプレフィクス再ハッシュ時間(ディスク読み取り速度に依存、ワイヤは待つ)が加わる。</p>",
"non-functional.idempotency":"<p>Get は読み取り専用で冪等。同じ <code>offset</code> の再送は同じ結果を返す。</p>",
"non-functional.concurrency":"<ul><li>同一ファイルへの並行 Get は許容(読み取りのみ)。</li><li>Put 中の temp は Get 対象外(temp 名を拒否)。最終ファイルは rename の原子性により、読み取り中に差し替わっても open 済み fd は旧内容を読む。</li></ul>",
"non-functional.audit":"<p>転送開始(ユーザ、パス、offset、encoding)、完了 / 失敗(理由、バイト数、所要時間)をログ。メトリクス: <code>downloads_completed_total</code>、<code>bytes_sent_total</code>、<code>transfer_duration_seconds</code>。</p>",
"references.related-docs":"<ul><li><a href=\"feature-transfer-engine.html\">転送エンジン</a></li><li><a href=\"../10-protocol/qftp-protocol.md\">qftp-protocol.md</a>(Get)</li><li><a href=\"../10-protocol/wire-format.md\">wire-format.md</a>(Body streaming)</li></ul>",
"references.artifacts":"<p>N/A</p>",
}
