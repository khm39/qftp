from theme import page, table, code
OUT="/tmp/claude-0/-home-user-qftp/96263040-8562-5047-8304-4e5f08fbf7fd/scratchpad/qftp-design/40-reference/e2e-test-spec.html"
S=[]
def cases(rows): return table(["ID","前提","手順","期待"],rows)
S.append(("scope","位置づけとフィクスチャ",f"""
<p>本書は自動テストの受け入れ条件です。ID は実装のテスト名(<code>#[test] fn e2e_get_02_resume_prefix()</code> など)に対応させ、CI で全件が緑であることを各フェーズの完了条件とします。</p>
{table(["層","場所","実行方法"],[
 ["WIRE","<code>qftp-wire/tests/conformance.rs</code> + proptest","<code>cargo test -p qftp-wire</code>"],
 ["CORE","<code>qftp-core/tests/</code>(純メモリホスト <code>ScriptHost</code>)","<code>cargo test -p qftp-core</code>"],
 ["E2E","<code>qftp-server/tests/</code>(<code>test-util</code> フィクスチャ + <code>qftp-client-core</code>)","<code>cargo test -p qftp-server</code>"],
 ["CLI","<code>qftp-client/tests/</code>(バイナリを subprocess で起動、サーバは test-util)","<code>cargo test -p qftp-client</code>"],
])}
{code('''// qftp-server::test_util(feature = "test-util")
pub struct Fixture { pub addr: SocketAddr, pub root: TempDir, pub ca: Certs, /* … */ }
impl Fixture {
    pub async fn start(cfg: FixtureConfig) -> Fixture;   // 空きポートに bind、ready まで待つ
    pub async fn stop(self) -> ShutdownReport;           // graceful、残った partial の一覧を返す
    pub fn client(&self) -> ClientBuilder;               // CA / mTLS / TOFU / insecure を選べる
    pub fn write_file(&self, rel: &str, bytes: &[u8]);    // root 配下に直接置く
    pub fn read_file(&self, rel: &str) -> Vec<u8>;
    pub fn metrics(&self) -> Metrics;                    // /metrics を取得して解析
}
pub struct FixtureConfig { pub users: Option<&'static str>, pub mtls: bool, pub require_retry: bool,
    pub limits: Limits, pub anonymous_writable: bool }
pub fn random_bytes(n: usize) -> Vec<u8>;                // xorshift、圧縮されにくい''')}
"""))
S.append(("wire","WIRE: 符号化",cases([
 ["WIRE-01","全ベクタ","<code>wire_hex</code> を復号し JSON 値と比較、値を符号化しバイト列と比較","全 51 件で双方向一致"],
 ["WIRE-02","proptest","任意の <code>Request</code> / <code>Response</code> を生成 → 符号化 → 復号","元に戻る(10,000 ケース)"],
 ["WIRE-03","proptest","任意のバイト列を復号","panic しない。結果は Ok か <code>Malformed</code>"],
 ["WIRE-04","フレーム長 16 MiB + 1","復号","ペイロードを読まずに拒否"],
 ["WIRE-05","bool = 0x02、Option タグ = 0x02","復号","<code>Malformed</code>"],
 ["WIRE-06","未知の Request 判別子 13","復号","<code>Malformed</code>"],
 ["WIRE-07","ErrorCode = 499、FileType = 9、Encoding = 7","復号","<code>Unknown(n)</code>、フレームは成功。ErrorCode の class = client"],
 ["WIRE-08","FileReady の末尾 <code>encoding</code> / <code>plaintext_size</code> を欠いたフレーム","寛容デコード","Identity / 0 を既定値として受理(versioning.md の既定値表どおり)"],
 ["WIRE-09","path 4097 バイト、message 1025 バイト、DirListing 100,001 件","<code>validate</code>","拒否"],
 ["WIRE-10","DirEntry.name に <code>/</code>、<code>..</code>、NUL","<code>validate_response</code>","拒否"],
])))
S.append(("core","CORE: エンジンとサンドボックス",cases([
 ["CORE-PATH-01","root 配下に a/b、symlink s→a、symlink out→/tmp","<code>resolve</code> に <code>/a/b</code>、<code>a/../b</code>、<code>/..</code>、<code>s/b</code>、<code>out/x</code>","前 2 つは成功、後 3 つは <code>PermissionDenied</code>"],
 ["CORE-PATH-02","cwd = /x","相対 <code>./y</code>、<code>//y/</code>","<code>/x/y</code>"],
 ["CORE-USER-01","users.toml の各違反(入れ子 home、<code>..</code>、quota 0、重複名)","読込","それぞれエラー、メッセージに項目名"],
 ["CORE-USER-02","SAN に 2 ユーザ分の名前を持つ証明書","<code>resolve_identity</code>","<code>Ambiguous</code>"],
 ["CORE-LS-01","10,001 エントリのディレクトリ","<code>ls_page(None)</code> → <code>ls_page(cursor)</code>","2 ページ、重複・欠落なし、2 ページ目の <code>next_cursor = None</code>"],
 ["CORE-LS-02","不正カーソル(base64 でない、ソート順に矛盾)","<code>ls_page</code>","<code>Malformed</code>"],
 ["CORE-GET-01","file_len 1 MiB、offset 0、Identity","ScriptHost で ReadDone / SendCapacity を交互に与える","Send の合計 = 1 MiB + 32、最後の Send に fin、トレーラ = BLAKE3(全体)"],
 ["CORE-GET-02","offset 300 KiB","同上","Prefix で ReadFile [0,300K) が 2 回、ワイヤに出ない。トレーラ = BLAKE3(全体)"],
 ["CORE-GET-03","Zstd、圧縮されやすい 1 MiB","同上","Send の合計 &lt; 1 MiB + 32、復号すると元と一致、<code>size == plaintext_size</code>"],
 ["CORE-GET-04","offset &gt; file_len","<code>start</code>","<code>InvalidRange</code> + Range details"],
 ["CORE-GET-05","Body 中に ReadDone が短い","on_event","<code>ResetStream(0x52)</code>、<code>Done(Failed)</code>"],
 ["CORE-GET-06","SendCapacity が常に 0 → 後で増える","on_event","Send は容量が与えられるまで出ない。容量を超える Send がない"],
 ["CORE-PUT-01","fresh、Identity、trailer あり","Bytes を 7 バイト刻みで与え、最後に Fin","WriteFile の連結 = 本体、Verify 成功、<code>Commit</code>、<code>Account{release=size, used=+size, file=+1}</code>、<code>Respond(Ok)</code>"],
 ["CORE-PUT-02","再開 offset = 4096、temp_len = 4096、trailer あり","ReadDone(プレフィクス)→ Bytes","トレーラが全体ハッシュと一致して Commit"],
 ["CORE-PUT-03","再開だが temp_len = 4000","<code>start</code>","<code>InvalidRange</code> + Range{4096, 4000}、Abort{keep_partial:true}"],
 ["CORE-PUT-04","再開、チェックサムなし","<code>start</code>","<code>Unsupported</code>"],
 ["CORE-PUT-05","Zstd、<code>size != plaintext_size</code>","<code>start</code>","<code>Malformed</code>"],
 ["CORE-PUT-06","Zstd、復号結果が plaintext_size を超える","Bytes","<code>UploadOverflow</code>、Abort{keep_partial:false}"],
 ["CORE-PUT-07","Zstd、不正フレーム","Bytes","<code>DecodeError</code>"],
 ["CORE-PUT-08","本体の途中で Fin","Fin","<code>UploadTruncated</code> + Upload{received, declared}、Abort{keep_partial:true}、used += received"],
 ["CORE-PUT-09","トレーラ 31 バイトで Fin","Fin","<code>UploadTruncated</code>(ヘッダ checksum があっても)"],
 ["CORE-PUT-10","ヘッダ checksum とトレーラが異なり、トレーラが正","Fin","トレーラを採用して成功"],
 ["CORE-PUT-11","トレーラ不一致","Fin","<code>ChecksumMismatch</code>、Abort{keep_partial:false}、used −= offset(再開時)"],
 ["CORE-PUT-12","quota: used + in_flight + size &gt; limit","<code>start</code>","<code>QuotaExceeded</code>"],
 ["CORE-PUT-13","WriteFailed(StorageFull)","on_event","<code>Internal</code>、Abort{keep_partial:true}"],
 ["CORE-PUT-14","Body 中に Cancel","on_event","Abort{keep_partial:true}、Account(release, used += 書けた分)、<code>Done(Cancelled)</code>、以後の Event は無視"],
 ["CORE-PUT-15","in-flight write が 4 のとき Bytes","on_event","5 つ目の WriteFile は WriteDone 後に出る"],
 ["CORE-CLI-01","GetClient: FileReady で offset + size != total_size","on_event","<code>ProtocolError</code>、DeleteLocal"],
 ["CORE-CLI-02","GetClient: 再開でトレーラ不一致","Fin","DeleteLocal、Failed"],
 ["CORE-CLI-03","PutClient: 本体送信中に Err(PermissionDenied)","Bytes(応答)","<code>ResetStream</code>、<code>Done(Failed)</code>、以後 Send なし"],
 ["CORE-CLI-04","PutClient: Zstd で Unsupported","Bytes(応答)","<code>Done(UnsupportedEncoding)</code>"],
 ["CORE-ZSTD-01","window_log 24 のフレーム","デコーダ","<code>DecodeError</code>"],
])))
S.append(("e2e","E2E: サーバ + クライアントコア",cases([
 ["E2E-CONN-01","自己署名 + TOFU、known_hosts 空、<code>tofu_accept_new</code>","接続 → Pwd","<code>/</code>。known_hosts に 1 行追加、0600"],
 ["E2E-CONN-02","known_hosts に別の fingerprint","接続","データ未送出で失敗、<code>TrustError::Mismatch</code>"],
 ["E2E-CONN-03","CA モード、cert の SAN が server_name と不一致","接続","失敗(ホスト名検証)"],
 ["E2E-CONN-04","<code>require_retry</code>","接続 → Pwd","成功。<code>retries_issued_total == 1</code>"],
 ["E2E-CONN-05","mTLS 必須、cert なし","接続","close 0x101、<code>TrustError::Rejected</code>"],
 ["E2E-CONN-06","mTLS、CN = alice","Pwd、Put","home = /alice、write 可"],
 ["E2E-CONN-07","mTLS、CN が users にない","接続","close 0x101"],
 ["E2E-CONN-08","1 回目の接続で保存したチケット","2 回目の接続","<code>is_resumed()</code>、Pwd 成功。identity gate 有効(named users)なら early data を送っていないことを確認"],
 ["E2E-CONN-09","<code>max_connections = 2</code>","3 本目","確立しない(half_open で破棄)、<code>connections_rejected_caps_total == 1</code>"],
 ["E2E-CONN-10","アイドル 30 s(fixture では 2 s に短縮)","放置","切断。次の要求は <code>Unavailable</code>"],
 ["E2E-CONN-11","接続確立後、要求ストリームに STOP_SENDING","別接続で Pwd","サーバは生存、Pwd 成功"],
 ["E2E-CONN-12","転送中に <code>Fixture::stop</code>","—","新規接続は拒否、進行中の Put は完了して Ok、partial なし"],
 ["E2E-LS-01","12,000 ファイル","<code>Session::ls_all</code>","全件、名前順、重複なし、<code>ls_pages_total == 2</code>"],
 ["E2E-LS-02","<code>x.qftp.partial</code> がある","ls","非表示"],
 ["E2E-GET-01","1 MiB 乱数","get","一致、<code>verified</code>、<code>downloads_completed_total == 1</code>"],
 ["E2E-GET-02","ローカルに正しい先頭 300 KiB","get","300 KiB から再開、一致"],
 ["E2E-GET-03","ローカルに同じ長さの壊れた先頭","get","1 回目はトレーラ不一致でローカル削除、<code>StalePartial</code> → 呼び出し側の再試行で一致"],
 ["E2E-GET-04","ローカルがリモートより長い","get","<code>InvalidRange</code> → 0 から再試行"],
 ["E2E-GET-05","圧縮されやすい 1 MiB、accept zstd","get","<code>encoding = Zstd</code>、一致、<code>bytes_sent_total &lt; 1 MiB</code>"],
 ["E2E-GET-06","<code>.jpg</code> 名の乱数 1 MiB","get","<code>encoding = Identity</code>"],
 ["E2E-GET-07","0 バイト","get","0 バイトのローカル、verified、削除されない"],
 ["E2E-GET-08","ディレクトリを get","get","<code>IsADirectory</code>"],
 ["E2E-GET-09","8 MiB の Get を 1 本流しながら","別接続で Stat × 20","各 Stat が 100 ms 以内(HOL 解消の受け入れ条件)"],
 ["E2E-PUT-01","1 MiB 乱数","put","一致、mode 適用、partial なし、<code>uploads_completed_total == 1</code>"],
 ["E2E-PUT-02","サーバに正しい 300 KiB の partial","put","再開、一致、partial 消滅"],
 ["E2E-PUT-03","同じ長さの壊れた partial","put","<code>ChecksumMismatch</code> → 0 から再送、一致"],
 ["E2E-PUT-04","圧縮されやすい 1 MiB","put","Zstd で送信、一致、<code>bytes_received_total == 1 MiB</code>(平文)"],
 ["E2E-PUT-05","quota 1 MiB、既存 900 KiB、200 KiB を put","put","<code>QuotaExceeded</code>、partial なし、used 不変"],
 ["E2E-PUT-06","<code>no_clobber</code>、既存あり","put","<code>AlreadyExists</code>、既存不変"],
 ["E2E-PUT-07","同じ宛先へ並行 2 本","put × 2","片方 Ok、片方 <code>AlreadyExists</code>"],
 ["E2E-PUT-08","本体の途中で接続を切る","put → 切断 → Stat(partial)","partial の長さ = 送った分、used に計上。再接続して put で再開・一致"],
 ["E2E-PUT-09","write 権限なし(bob)","put(1 MiB)","<code>PermissionDenied</code> を本体送信中に受けて中断(ADR-009)、送信バイト &lt; 1 MiB"],
 ["E2E-PUT-10","<code>max_file_size = 1 MiB</code>、2 MiB","put","<code>FileTooLarge</code>、本体未送信"],
 ["E2E-PUT-11","宛先名が <code>x.qftp.partial</code>","put","<code>PermissionDenied</code>"],
 ["E2E-ACL-01","bob(read のみ)","Mkdir / Rm / Rename / Chmod / Put","すべて <code>PermissionDenied</code>、Ls / Stat / Get / Cd は成功"],
 ["E2E-ACL-02","権限ゼロのユーザ","Cd","<code>PermissionDenied</code>(ADR: Cd は read)"],
 ["E2E-FS-01","Mkdir → Put → Rename → Stat → Rm → Rmdir","一連","各成功、Quota の used / file_count が追随"],
 ["E2E-FS-02","root 外への symlink を root 内に置く","Ls / Get / Put 経由","<code>PermissionDenied</code>、外のファイルに触れない"],
 ["E2E-FS-03","Chmod 04755","Stat","suid が落ちて 0755"],
 ["E2E-LIMIT-01","<code>request_rate_burst = 3</code>","Pwd × 5 を連続","4 本目以降 <code>RateLimited</code> + RetryAfter、待って再試行で成功"],
 ["E2E-LIMIT-02","<code>initial_rate_burst = 1</code>","同時接続 3","1 本のみ確立、<code>connections_rejected_rate_total == 2</code>"],
 ["E2E-0RTT-01","anonymous のみのサーバ、チケットあり、early data で Pwd(テスト用フックで送る)","接続","<code>zero_rtt_accepted_total == 1</code>"],
 ["E2E-0RTT-02","同上で Ls / Put を early data","接続","<code>Unsupported</code>、1-RTT 後の再送で成功、<code>zero_rtt_rejected_total == 2</code>"],
 ["E2E-0RTT-03","名前付きユーザありのサーバ、early data で Pwd","接続","<code>Unsupported</code>(identity gate)"],
 ["E2E-OPS-01","<code>metrics_bind</code> 有効","GET /metrics、/healthz","全メトリクス名が存在、healthz 200。stop 中は 503"],
 ["E2E-OPS-02","起動時に 25 時間前の partial と 1 時間前の partial","起動","前者だけ削除"],
 ["E2E-OPS-03","<code>--check-config</code> で不正な users.toml","起動","終了コード 1、原因を stderr"],
])))
S.append(("cli","CLI: バイナリの振る舞い",cases([
 ["CLI-01","不正 URL","<code>qftp-client ls qftp://:bad</code>","64、stderr に理由"],
 ["CLI-02","接続不能ホスト","<code>get</code>","69"],
 ["CLI-03","TOFU 不一致","<code>-T get</code>","77、バナーに known_hosts パス"],
 ["CLI-04","bob で put","<code>put</code>","77"],
 ["CLI-05","<code>--batch</code> で 3 行目が失敗(fail_fast)","stdin","1〜2 行目のみ実行、失敗行の終了コード"],
 ["CLI-06","<code>--no-fail-fast</code>","同上","全行実行、65"],
 ["CLI-07","<code>ls --json</code>","one-shot","1 行 JSON、スキーマどおり、stderr は空"],
 ["CLI-08","空白を含むリモート名","<code>-e \"get 'a b.txt'\"</code>","取得できる"],
 ["CLI-09","<code>get</code> 中に SIGINT","subprocess に送る","65、ローカル partial が残る、サーバは生存"],
 ["CLI-10","非 Unix 相当(cfg テスト)","起動","70(ビルド時 cfg で代替)"],
 ["ADMIN-01","<code>add-user</code> → <code>set-quota</code> → <code>token add</code> → <code>check</code>","一連","サーバの検証器で読める、token の平文は stdout に 1 回、ファイルは sha256 のみ"],
 ["ADMIN-02","入れ子 home の <code>add-user</code>","実行","65、ファイル不変"],
])))
S.append(("bench","ベンチ(参考、CI 外)",f"""
{table(["名前","内容","記録"],[["throughput/put/{1M,16M,64M,256M,1G}","乱数ペイロード、圧縮なし / あり","MiB/s、圧縮あり時のワイヤ削減率"],["throughput/get/…","同上",""],["latency/stat","大転送中の Stat 応答時間","p50 / p99"]])}
<p><code>cargo bench -p qftp-server --bench throughput</code> で実行。<code>cargo test</code> からは <code>test = false</code> で除外。</p>
"""))
page("e2e テスト仕様","参照文書","作成日: 2026-09-03 / 対象: WIRE / CORE / E2E / CLI の各層の受け入れテスト",S,OUT)
