DOC_TYPE="sequence"; TITLE="Put 転送(アップロード・再開・圧縮・コミット)"; FILENAME="sequence-put-transfer.html"
ANSWERS={
"overview.name":"<p>Put 転送シーケンス。</p>",
"overview.use-case":"<p>REPL / one-shot の <code>put</code>、再帰 put、sync、watch、Web クライアントのアップロード。</p>",
"overview.purpose":"<p>クライアントのファイルをサーバへ、再開可能・整合性検証つき・原子的コミットで転送する。</p>",
"overview.scope":"<p>開始: クライアントが再開 offset を決める(サーバの temp を Stat)。終端: サーバが temp を rename して <code>Ok</code> を返し、クライアントが結果を確定する。</p>",
"preconditions.initial-state":"<ul><li>接続確立済み、write 権限。</li><li>宛先の親ディレクトリが存在する(Put は親を作らない)。</li><li>クォータに余裕がある。</li></ul>",
"preconditions.inputs":"<p><code>Request::Put{path, size, mode, offset, hash_algorithm=Blake3, checksum=None, no_clobber, checksum_trailer=true, encoding, plaintext_size}</code>。</p>",
"preconditions.auth-state":"<p>1-RTT。Put は early data で拒否される。</p>",
"actors.actors":"<ul><li>クライアント</li><li>サーバ</li></ul>",
"actors.components":"<ul><li>サーバ: dispatch、パス解決(<code>resolve_parent</code>)、<code>UploadClaim</code>、クォータ予約、<code>PutServer</code>、ブロッキングプール(ファイル I/O)、コミット(rename + mode)。</li><li>クライアント: <code>Session::put</code>、<code>PutClient</code>、ローカルファイル、pacer(bwlimit)。</li></ul>",
"actors.roles":"<ul><li><code>UploadClaim</code>: 同一宛先への並行 Put を <code>AlreadyExists</code> で拒否。</li><li>クォータ予約: 予約→検査で並行 Put の競合を閉じる。</li><li><code>PutServer</code>: 本体 / トレーラ分類、復号、ハッシュ、検証、コミット指示、後始末規則。</li></ul>",
"steps.main-flow":"""<pre>
Client                              Server
 1. Stat(&lt;remote&gt;.qftp.partial) ─▶
    ◀─ FileStat{size=p} | NotFound
 2. offset = p if 0&lt;p≤local_len else 0
 3. encoding = Zstd if (len-offset)≥1024B
    &amp;&amp; 非既圧縮 &amp;&amp; compress
 4. Put{size=len-offset, offset,
        trailer=true, encoding,
        plaintext_size, no_clobber} ─▶  5. ACL(write) / resolve_parent / temp 名拒否
                                     6. no_clobber → lstat 既存なら AlreadyExists
                                     7. UploadClaim(final) else AlreadyExists
                                     ── ここまでホスト、以下は PutServer::start ──
                                     8. 検証必須形: offset&gt;0 or Zstd → checksum 必須
                                     9. Zstd: size == plaintext_size
                                    10. offset+size ≤ max_file_size
                                    11. temp open(0600, O_NOFOLLOW)
                                        fresh: truncate
                                        resume: len==offset else InvalidRange{Range}
                                    12. 予約 size → used+in_flight ≤ quota
                                        else QuotaExceeded
                                    13. resume: ReadFile[0,offset) をハッシュ、
                                        到着済み本体は保留
14. 待たずに本体送信へ(応答は並行監視)
15. ローカル [0,offset) をハッシュ
16. body(identity | zstd frame) ─▶ 17. 分類: body → (decode) → WriteFile
                                        trailer は蓄積
                                        平文カウンタ ≤ size、超過は UploadOverflow
18. trailer(digest_len) + FIN ───▶ 19. Fin: 不足 → UploadTruncated
                                    20. checksum = trailer(完備) | header | none
                                    21. mismatch → 削除・返金・ChecksumMismatch
                                    22. 祖先 symlink 再検査、no_clobber 再検査
                                    23. Commit: rename(temp→final), apply_mode(0o777 マスク)
                                    24. 会計: 予約 → used、file_count += 1
25. ◀─ Ok | Err ─────────────────── 25. Respond
</pre>""",
"steps.sync-async":"<ul><li>クライアントはヘッダ送出後、応答を待たずに本体を流し、同じストリームの受信側を並行して監視する。<code>Err</code> を受けたら送信を止めてストリームを reset する(ADR-009)。</li><li>サーバの WriteFile / Commit はブロッキングプールへの非同期要求。</li></ul>",
"steps.state-transitions":"""<table><tr><th>PutServer 状態</th><th>遷移</th></tr>
<tr><td>Start</td><td>検証 OK → Rehash(offset&gt;0) / Body(offset=0)</td></tr>
<tr><td>Rehash</td><td>ReadDone で残り 0 → Body(保留分を処理)</td></tr>
<tr><td>Body</td><td>本体完了 → Trailer(trailer あり) / Verify</td></tr>
<tr><td>Trailer</td><td>digest_len(BLAKE3 なら 32)バイト揃う → Verify</td></tr>
<tr><td>Verify</td><td>OK → Committing / NG → Failed(削除)</td></tr>
<tr><td>Committing</td><td>CommitDone → Done / CommitFailed → Failed(temp 保持)</td></tr></table>
<p>ディスク上: (なし | 旧 partial) → partial(書込中) → final(コミット)。</p>""",
"steps.transaction-boundary":"<p>コミット(rename)が単一の原子点。コミット前の失敗は final に影響しない。<code>no_clobber</code> は開始時とコミット直前の 2 回検査するが、rename 自体は上書きになるため、最終的な競合は「同一宛先の claim」で排他する。</p>",
"diagram.diagram-link":"<p>N/A(テキスト図)</p>",
"diagram.diagram-summary":"<p>再開(offset&gt;0)ではサーバが partial の <code>[0,offset)</code> を再ハッシュし(ステップ 13)、クライアントも同じ範囲をハッシュする(15)ため、トレーラはファイル全体のダイジェストになります。長さだけ一致する破損 partial は最終的に <code>ChecksumMismatch</code> になり、クライアントは 0 から再送します。</p>",
"exceptional-flows.failure-cases":"""<ul><li>Unsupported(検証必須形でチェックサムなし / 未知 encoding): クライアントは Identity かつトレーラありで 1 回再送。</li><li>AlreadyExists(no_clobber / 並行 Put): 上書き規則に従いスキップまたは報告。</li><li>InvalidRange(temp 長不一致)、ChecksumMismatch(再開時): クライアントは 0 から 1 回再送(StalePartial)。</li><li>QuotaExceeded / FileTooLarge: 65、再試行しない。</li><li>UploadTruncated(接続断): サーバは partial を残し、書けた分をクォータに計上。次回再開。</li><li>UploadOverflow / DecodeError: partial 削除。クライアントは 65。</li><li>Internal(書込 / コミット失敗): partial を残す。クライアントは 65。</li></ul>""",
"exceptional-flows.timeout-retry":"<ul><li>要求単位のタイムアウトなし(QUIC アイドルに委ねる)。接続がアイドル 30 s で切れる(QUIC の idle timeout は接続単位)。</li><li>再送は Unsupported / StalePartial とも各 1 回。</li></ul>",
"exceptional-flows.compensation":"<p>失敗分類ごとの temp / 会計規則は <a href=\"../40-reference/engine-api.html#put-server\">転送エンジン API 仕様 §4 の表</a>が正本。返金は「再開プレフィクス分」と「予約分」の 2 種類。</p>",
"exceptional-flows.partial-failure":"<p>本体途中で切断した場合、partial は残り、次回 Put が Stat で長さを取得して再開する。partial の中身が壊れていても長さ検査は通るが、トレーラで検出され 0 から再送される。</p>",
"non-functional.latency":"<p>Stat 1 往復 + 本体送出時間 + コミット + 応答 1 往復。早期拒否を待たないため(ADR-009)、Put 自体の往復は 1 回。小ファイル多数では Stat の往復が支配的になるため、再開の見込みがない場合(<code>--force</code>、fresh な宛先)は Stat を省略できる。</p>",
"non-functional.idempotency":"<p>同一内容の Put の再送は最終状態が同じ(上書き)。<code>no_clobber=true</code> のときは 2 回目が AlreadyExists。再開は offset により冪等。</p>",
"non-functional.concurrency":"<ul><li>同一宛先: <code>UploadClaim</code> で排他(AlreadyExists)。</li><li>異なる宛先の並行 Put: クォータ予約で合計を超えない。</li><li>Put 中の Get / Rm / Rename は temp を対象にできない。final は rename まで旧内容。</li></ul>",
"non-functional.audit":"<p>開始(ユーザ、パス、offset、size、encoding、no_clobber)、結果(理由、書込バイト数、所要時間)、コミット成功をログ。メトリクス: <code>qftp_uploads_completed_total</code>、<code>qftp_bytes_received_total</code>(平文)、<code>qftp_requests_failed_total</code>。</p>",
"references.related-docs":"<ul><li><a href=\"feature-transfer-engine.html\">転送エンジン</a></li><li><a href=\"../10-protocol/qftp-protocol.md\">qftp-protocol.md</a>(Put)</li></ul>",
"references.artifacts":"<p>N/A</p>",
}
