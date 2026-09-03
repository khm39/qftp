DOC_TYPE="operations"; TITLE="qftp-server 運用"; FILENAME="operations-qftp-server.html"
ANSWERS={
"overview.target-system":"<p>qftp-server(および同一ホストで併走する場合の qftp-web-bridge)。</p>",
"overview.scope":"<p>監視・アラート・障害対応・バックアップ・定期作業・キャパシティ。デプロイ方式(systemd / Docker)を含む。SLO と体制は運用主体が決めるため未記入。</p>",
"overview.team":"",
"service-levels.slo":"",
"service-levels.sla":"",
"service-levels.error-budget":"",
"monitoring.targets":"""<p><b>メトリクス(Prometheus テキスト、<code>metrics_bind</code>)</b></p>
<table><tr><th>名前</th><th>型</th><th>意味</th></tr>
<tr><td><code>qftp_connections_open</code></td><td>gauge</td><td>現在の接続数</td></tr>
<tr><td><code>qftp_connections_total</code></td><td>counter</td><td>受理した接続</td></tr>
<tr><td><code>qftp_connections_rejected_caps_total</code> / <code>_rate_total</code></td><td>counter</td><td>上限 / レートで拒否した Initial</td></tr>
<tr><td><code>qftp_initials_dropped_bad_dcid_total</code></td><td>counter</td><td>不正 DCID</td></tr>
<tr><td><code>qftp_retries_issued_total</code></td><td>counter</td><td>Retry 送出</td></tr>
<tr><td><code>qftp_requests_total</code> / <code>_failed_total</code> / <code>_rate_limited_total</code></td><td>counter</td><td>要求数 / Err 応答 / RateLimited</td></tr>
<tr><td><code>qftp_uploads_completed_total</code> / <code>qftp_downloads_completed_total</code></td><td>counter</td><td>転送完了</td></tr>
<tr><td><code>qftp_bytes_received_total</code> / <code>qftp_bytes_sent_total</code></td><td>counter</td><td>平文受信 / ワイヤ送信バイト</td></tr>
<tr><td><code>qftp_zero_rtt_accepted_total</code> / <code>_rejected_total</code></td><td>counter</td><td>early data の受理 / 拒否</td></tr>
<tr><td><code>qftp_io_queue_depth</code></td><td>gauge</td><td>ブロッキングプール待ち行列(新規)</td></tr>
<tr><td><code>qftp_transfer_duration_seconds</code></td><td>histogram</td><td>転送所要時間(新規)</td></tr>
<tr><td><code>qftp_ls_pages_total</code></td><td>counter</td><td>Ls ページ数(新規)</td></tr>
<tr><td><code>qftp_tls_cert_expiry_seconds</code></td><td>gauge</td><td>サーバ証明書の <code>notAfter</code>(Unix 秒、新規)</td></tr></table>
<p><b>ログ</b>: JSON(<code>log.format = "json"</code>)。接続 / identity / 要求 / 転送 / シャットダウンの各イベント。<b>ヘルス</b>: <code>/healthz</code>(200 = 受付ループ生存、503 = シャットダウン中)。<b>OS</b>: プロセス RSS、fd 数、UDP 受信ドロップ(<code>/proc/net/udp</code> の drops)、ストレージルートの空き容量。</p>""",
"monitoring.tools":"<p>Prometheus + Alertmanager を想定(任意のスクレイパで可)。ログは JSON を Loki / Datadog 等へ。ダッシュボードツールは運用主体が選定(未記入)。</p>",
"monitoring.dashboards":"",
"alerting.conditions":"""<table><tr><th>条件</th><th>重要度</th><th>意味</th></tr>
<tr><td><code>/healthz</code> が 2 回連続で非 200</td><td>高</td><td>プロセス停止 / ループ停止</td></tr>
<tr><td><code>rate(qftp_connections_rejected_caps_total[5m]) &gt; 0</code> が 10 分継続</td><td>中</td><td>接続上限到達(容量不足または攻撃)</td></tr>
<tr><td><code>rate(qftp_connections_rejected_rate_total[5m])</code> の急増</td><td>中</td><td>Initial フラッド</td></tr>
<tr><td><code>rate(qftp_requests_failed_total[5m]) / rate(qftp_requests_total[5m]) &gt; 0.2</code></td><td>中</td><td>エラー率上昇(権限設定ミス、ディスク障害)</td></tr>
<tr><td><code>qftp_io_queue_depth</code> &gt; 有効ブロッキングスレッド数(設定 0 のときは CPU × 2)× 4 が 5 分継続</td><td>中</td><td>ディスクが追いつかない</td></tr>
<tr><td>ストレージ空き &lt; 10 %</td><td>高</td><td>Put が Internal で失敗し始める</td></tr>
<tr><td><code>qftp_tls_cert_expiry_seconds - time() &lt; 14d</code></td><td>中</td><td>ローテーション期限</td></tr></table>""",
"alerting.escalation":"",
"alerting.silence-rules":"<p>計画メンテ時は Alertmanager の silence を使用。graceful shutdown 中の <code>/healthz</code> 503 は再起動時間(≤ <code>shutdown_timeout</code> + 起動時間)だけ静観。</p>",
"incident-response.severity-classification":"""<table><tr><th>区分</th><th>基準</th></tr>
<tr><td>Sev1</td><td>全クライアントが接続不能、またはデータ破損の疑い(トレーラ不一致の多発)</td></tr>
<tr><td>Sev2</td><td>一部ユーザの操作が失敗(権限 / クォータ / ディスク)、転送性能の著しい低下</td></tr>
<tr><td>Sev3</td><td>監視・ログの欠落、証明書期限接近、非機能の劣化</td></tr></table>""",
"incident-response.initial-response":"""<ol><li><code>/healthz</code> と <code>systemctl status</code> でプロセス状態を確認。</li><li>JSON ログで直近の close 理由・Err コードの分布を確認(<code>0x101</code> の多発は証明書 / users.toml、<code>Internal</code> はディスク)。</li><li>ディスク空き、fd 数、UDP ドロップを確認。</li><li>攻撃が疑われる場合は <code>limits.*</code> を引き下げて再起動(設定ファイル編集 → <code>--check-config</code> → restart)。</li><li>プロセス再起動は graceful(SIGTERM)。転送中のクライアントは partial から再開できる。</li></ol>""",
"incident-response.communication":"",
"incident-response.postmortem-policy":"",
"backup-restore.backup-targets":"<ul><li>ストレージルート(ユーザデータ)。頻度は運用主体が決める(未記入)。<code>*.qftp.partial</code> は除外可。</li><li><code>users.toml</code>、<code>tokens.toml</code>(秘密)、サーバ証明書 / 鍵、永続自己署名の state dir。</li><li>設定ファイル。</li></ul>",
"backup-restore.retention":"",
"backup-restore.restore-procedure":"<ol><li>同一 root パスにデータを復元し、所有者をサーバ実行ユーザに合わせる。</li><li>users.toml / 証明書 / 設定を復元。</li><li><code>--check-config</code> で検証後に起動。起動時に使用量がプライミングされ、24 h 超の partial は掃除される。</li></ol>",
"backup-restore.rto-rpo":"",
"routine-operations.recurring-tasks":"<ul><li>証明書ローテーション(期限前)。永続自己署名は期限切れで自動再生成されるがクライアントの pin は更新が必要。</li><li>tokens.toml のトークンローテーション(ブリッジ利用時)。</li><li>users.toml の棚卸し(不要ユーザの削除、クォータ見直し)。</li><li>ログ・メトリクスの保持期間管理。</li><li>依存の脆弱性確認(cargo-deny の定期実行)とアップデート。</li></ul>",
"routine-operations.automation":"<ul><li>自動: partial の掃除(起動時)、自己署名の再生成、メトリクス収集。</li><li>未自動: 証明書 / トークンのローテーション、users.toml 編集(<code>qftp-admin</code> で半自動)、ログ保持。</li></ul>",
"routine-operations.audit-records":"",
"capacity.current-usage":"",
"capacity.scale-up-criteria":"<ul><li><code>qftp_connections_open</code> が <code>max_connections</code> の 80 % を継続。</li><li><code>qftp_io_queue_depth</code> の恒常的な滞留。</li><li>CPU 1 コア(イベントループ)が飽和: 複数プロセス(別ポート / UDP LB)への分割を検討。</li></ul>",
"capacity.growth-forecast":"",
"references.related-docs":"<ul><li><a href=\"feature-server.html\">サーバ機能設計書</a></li><li><a href=\"architecture-qftp.html\">アーキテクチャ設計書</a></li><li><a href=\"../10-protocol/security-model.md\">security-model.md</a>(ハードニング一覧)</li></ul>",
"references.artifacts":"<p>デプロイ成果物(リポジトリに同梱予定): systemd unit(<code>DynamicUser=</code>、<code>/usr/bin/qftp-server --config /etc/qftp/server.toml</code>)、Dockerfile(distroless、<code>qftp-admin</code> 同梱、既定 CMD は自己署名で起動可能)、docker-compose 例(サーバ + ブリッジ + nginx、<code>--client-ca</code> を含む)。Runbook は本書 §5 を基に別途作成(未記入)。</p>",
}
