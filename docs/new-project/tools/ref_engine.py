from theme import page, table, code
OUT="/tmp/claude-0/-home-user-qftp/96263040-8562-5047-8304-4e5f08fbf7fd/scratchpad/qftp-design/40-reference/engine-api.html"
S=[]
S.append(("scope","位置づけと設計原則",f"""
<p><code>qftp-core::transfer</code> の公開 API を定義します。機能設計書(転送エンジン)の規則を型と契約に落としたもので、実装は本書の型名・意味に従います。名前の変更は本書の改訂を伴います。</p>
{table(["原則","内容"],[
 ["sans-I/O","エンジンはソケット・ファイル・時計に触れない。入力は <code>Event</code>、出力は <code>Vec&lt;Cmd&gt;</code> のみ"],
 ["決定的","同じ Event 列には同じ Cmd 列を返す。乱数・時刻を使わない(テストはスクリプトで再現できる)"],
 ["単一所有","1 エンジン = 1 ストリーム = 1 転送。<code>Send + 'static</code> だが内部同期なし。ホストが逐次に呼ぶ"],
 ["宣言サイズを信用しない","<code>size</code> / <code>plaintext_size</code> は事前拒否にだけ使い、バッファ確保には使わない。バッファはチャンク単位"],
 ["会計はコマンドで","クォータの増減は <code>Cmd::Account</code> で通知し、ホストが <code>User</code> に反映する。エンジンは共有状態を持たない"],
])}
"""))
S.append(("types","共通の型",f"""
{code('''use bytes::Bytes;
use qftp_wire::{Encoding, ErrorResponse, HashAlgorithm, Response};

/// ファイル I/O 要求の相関 ID。エンジンが採番し、完了イベントで返る。
pub type IoId = u32;

/// ホスト → エンジン
pub enum Event {
    /// ストリームから受信した本体 / トレーラのバイト列(空は禁止)
    Bytes(Bytes),
    /// ピアが FIN を送った(Bytes より後に 1 回だけ)
    Fin,
    /// 送信可能バイト数の「現在値」(差分ではない)。増減のたびに通知
    SendCapacity(usize),
    /// ReadFile の完了。data.len() < 要求 len は EOF を意味する
    ReadDone { id: IoId, data: Bytes },
    ReadFailed { id: IoId, error: IoError },
    WriteDone { id: IoId },
    WriteFailed { id: IoId, error: IoError },
    CommitDone,
    CommitFailed(IoError),
    /// 接続断・シャットダウン。以後ホストは他の Event を送らない
    Cancel,
}

/// エンジン → ホスト
pub enum Cmd {
    /// 制御フレームを送る(FileReady / Ok / Err)。FIN は立てない
    Respond(Response),
    /// 本体またはトレーラを送る。fin は最後のバイトに立てる
    Send { data: Bytes, fin: bool },
    /// 本体送出後に失敗した Get の通知(アプリケーションエラーコード)
    ResetStream(u64),
    /// pos から最大 len バイト読む
    ReadFile { id: IoId, pos: u64, len: usize },
    /// 現在位置に追記する(順序はエンジンが保証)
    WriteFile { id: IoId, data: Bytes },
    /// temp を final に原子的に rename し、mode を適用する
    Commit { mode: u32 },
    /// 後始末。keep_partial = true は再開用に temp を残す
    Abort { keep_partial: bool },
    /// クォータ会計(ホストが User に反映)
    Account(Accounting),
    /// 終了。以後エンジンは Event を受け付けない
    Done(Outcome),
}

pub struct Accounting {
    /// in_flight から解放する予約バイト
    pub release_reserved: u64,
    /// used_bytes に加算(正)または減算(負)
    pub used_delta: i64,
    /// file_count の増減
    pub file_delta: i32,
}

pub enum Outcome {
    Completed { plaintext_bytes: u64 },
    Failed(ErrorResponse),
    Cancelled,
}

/// io::ErrorKind の写し。エンジンは種類だけ見る(NotFound / PermissionDenied / StorageFull / Other)
pub enum IoError { NotFound, PermissionDenied, StorageFull, Other }

/// 共通の実装定義パラメータ
pub struct Limits {
    pub max_file_size: u64,      // 既定 1 GiB
    pub read_chunk: usize,       // 既定 256 KiB
    pub write_chunk: usize,      // 既定 64 KiB
    pub max_inflight_writes: u32,// 既定 4
    pub zstd_level: i32,         // 既定 3(送信側のみ)
}''')}
<p>ストリームのアプリケーションエラーコード(<code>ResetStream</code>)は実装定義で、参照実装は <code>0x51</code>(読み取り失敗)、<code>0x52</code>(サーバ側ファイル縮小)、<code>0x53</code>(取り消し)を使います。</p>
"""))
S.append(("get-server","GetServer",f"""
{code('''pub struct GetParams {
    pub offset: u64,
    pub length: Option<u64>,
    pub accept_encoding: Vec<Encoding>,
    /// ホストが open + fstat 済み(regular file であること)
    pub file_len: u64,
    /// 送信側ポリシー(拡張子ヒューリスティク等)。false なら Identity
    pub compressible: bool,
    pub limits: Limits,
}

pub struct GetServer { /* 非公開 */ }

impl GetServer {
    /// 検証に失敗した場合は Err(ErrorResponse)。ホストは Respond(Err) を送り、ストリームを閉じる。
    /// 成功時の Vec<Cmd> は [Respond(FileReady), ReadFile{..}] から始まる。
    pub fn start(p: GetParams) -> Result<(GetServer, Vec<Cmd>), ErrorResponse>;
    pub fn on_event(&mut self, ev: Event) -> Vec<Cmd>;
    pub fn state(&self) -> GetState;
}

pub enum GetState { Prefix, Body, Trailer, Done, Failed }''')}
<h3>開始時の検証(順序どおり)</h3>
{table(["条件","結果"],[
 ["<code>file_len &gt; limits.max_file_size</code>","<code>FileTooLarge</code>"],
 ["<code>offset &gt; file_len</code>","<code>InvalidRange</code> + <code>Range { offset, file_size }</code>"],
 ["<code>bytes = min(length, file_len - offset)</code>","本体長。<code>length</code> 未指定は EOF まで"],
 ["<code>encoding</code>","<code>compressible &amp;&amp; bytes ≥ 1024 &amp;&amp; accept_encoding.contains(Zstd)</code> なら Zstd、それ以外 Identity"],
 ["FileReady","<code>size = bytes</code>、<code>total_size = file_len</code>、<code>checksum_follows = true</code>(常に)、<code>plaintext_size = bytes</code>(Zstd)/ 0(Identity)"],
])}
<h3>状態表</h3>
{table(["状態","受け付ける Event","動作 / 発行する Cmd","遷移"],[
 ["Prefix(offset &gt; 0)","ReadDone","データをハッシュに畳む。残りがあれば次の ReadFile、なければ Body へ(初回の本体 ReadFile を発行)","Prefix / Body"],
 ["Prefix","ReadDone が短い(EOF)","ファイル縮小。<code>Respond(Err InvalidRange)</code>、<code>Done(Failed)</code>","Failed"],
 ["Body","ReadDone","ハッシュ更新 → (Zstd なら符号化) → 送信待ちバッファへ。SendCapacity の範囲で <code>Send</code>。バッファが read_chunk 未満なら次の ReadFile","Body / Trailer"],
 ["Body","SendCapacity(n)","待ちバッファから n バイトまで <code>Send</code>",""],
 ["Body","ReadDone が短い","ファイル縮小。<code>ResetStream(0x52)</code>、<code>Done(Failed)</code>","Failed"],
 ["Body","ReadFailed","<code>ResetStream(0x51)</code>、<code>Done(Failed)</code>","Failed"],
 ["Trailer","SendCapacity","トレーラ(digest_len バイト)を <code>Send{fin:true}</code>。送り切ったら <code>Done(Completed)</code>","Done"],
 ["任意","Cancel","<code>Done(Cancelled)</code>","Done"],
])}
<p>Identity で <code>bytes == 0</code> のときは本体フェーズを飛ばし、トレーラだけを送ります。Zstd で 0 のときは空の zstd フレームを送ってからトレーラを送ります。<code>Send</code> の合計は常に <code>SendCapacity</code> の現在値以下で、ホストは <code>Send</code> を必ず全量受理します。</p>
"""))
S.append(("put-server","PutServer",f"""
{code('''pub struct PutParams {
    pub req: PutRequest,          // qftp_wire::Request::Put のフィールド
    /// ホストが lstat した既存 partial の長さ(なければ None)
    pub temp_len: Option<u64>,
    pub quota: QuotaView,         // { used: u64, in_flight: u64, limit: Option<u64> }
    pub limits: Limits,
}

pub struct PutServer { /* 非公開 */ }

impl PutServer {
    /// 検証失敗時は Err((ErrorResponse, Vec<Cmd>))。Vec<Cmd> は後始末(Abort/Account)を含む。
    /// 成功時の Vec<Cmd> は予約の Account と、再開なら ReadFile(プレフィクス)から始まる。
    pub fn start(p: PutParams) -> Result<(PutServer, Vec<Cmd>), (ErrorResponse, Vec<Cmd>)>;
    pub fn on_event(&mut self, ev: Event) -> Vec<Cmd>;
    pub fn state(&self) -> PutState;
}

pub enum PutState { Rehash, Body, Trailer, Verify, Committing, Done, Failed }''')}
<h3>開始時の検証(順序どおり)</h3>
{table(["条件","結果"],[
 ["<code>hash_algorithm</code> が未対応、<code>encoding</code> が未対応","<code>Unsupported</code>"],
 ["<code>offset &gt; 0</code> または <code>encoding != Identity</code> で、<code>checksum == None &amp;&amp; !checksum_trailer</code>","<code>Unsupported</code>(検証必須形)"],
 ["<code>encoding == Zstd &amp;&amp; size != plaintext_size</code>","<code>Malformed</code>"],
 ["<code>checksum</code> の長さが digest_len と異なる","<code>Malformed</code>"],
 ["<code>offset + size &gt; max_file_size</code>","<code>FileTooLarge</code>"],
 ["<code>offset &gt; 0 &amp;&amp; temp_len != Some(offset)</code>","<code>InvalidRange</code> + <code>Range { offset, file_size: temp_len.unwrap_or(0) }</code>"],
 ["<code>quota.used + quota.in_flight + size &gt; limit</code>","<code>QuotaExceeded</code>。fresh なら <code>Abort{keep_partial:false}</code>"],
 ["成功","<code>Account { release_reserved: 0, used_delta: 0 }</code> は出さず、ホストが予約 <code>size</code> を in_flight に加える前提(<code>QuotaView</code> は予約前の値)。エンジンは終了時に必ず <code>release_reserved = size</code> を返す"],
])}
<p><code>no_clobber</code> の既存検査と <code>UploadClaim</code> は<strong>ホストの責務</strong>(パス解決と同じ段階)で、エンジンは claim 済み・temp open 済みで開始されます。</p>
<h3>状態表</h3>
{table(["状態","Event","動作 / Cmd","遷移"],[
 ["Rehash(offset &gt; 0)","ReadDone","プレフィクスをハッシュ。残りがあれば次の ReadFile。到着した Bytes は内部バッファに保留(上限 write_chunk × max_inflight_writes、超過分はホストの受信を止める <code>SendCapacity</code> 相当がないため、エンジンは保留を許容し続ける)","Rehash / Body"],
 ["Rehash","ReadDone が短い / ReadFailed","<code>Respond(Err InvalidRange)</code>、<code>Abort{keep_partial:true}</code>、Account、Done","Failed"],
 ["Body","Bytes","本体 / トレーラ / 超過に分類。本体は(Zstd なら復号し)平文カウンタを更新、<code>WriteFile</code> を発行(in-flight ≤ max_inflight_writes、超えたら内部に溜める)。超過は <code>UploadOverflow</code> + <code>Upload{received,declared}</code>","Body / Trailer / Failed"],
 ["Body","Bytes(Zstd 不正 / 窓超過)","<code>DecodeError</code>","Failed"],
 ["Body","Fin(本体不足)","<code>UploadTruncated</code> + Upload details","Failed"],
 ["Body / Trailer","WriteDone","in-flight を減らし、溜めた書込を発行",""],
 ["Body / Trailer","WriteFailed","<code>Internal</code>(StorageFull も Internal)。temp は残す","Failed"],
 ["Trailer","Bytes","digest_len まで蓄積。超過は <code>UploadOverflow</code>","Trailer / Verify"],
 ["Trailer","Fin(不足)","<code>UploadTruncated</code>","Failed"],
 ["Verify","(全 WriteDone 到着後)","ダイジェスト解決(トレーラ &gt; ヘッダ &gt; なし)。不一致は <code>ChecksumMismatch</code>、<code>Abort{keep_partial:false}</code>、返金。一致なら <code>Commit{mode}</code>","Committing / Failed"],
 ["Committing","CommitDone","<code>Account { release_reserved: size, used_delta: +size, file_delta: +1 (fresh) }</code>、<code>Respond(Ok)</code>、<code>Done(Completed)</code>","Done"],
 ["Committing","CommitFailed","<code>Internal</code>。temp は残す","Failed"],
 ["任意","Cancel","<code>Abort{keep_partial:true}</code>、書けた分を used に計上、予約解放、<code>Done(Cancelled)</code>","Done"],
])}
<h3>失敗時の後始末(Cmd の組)</h3>
{table(["失敗","Abort","Account","Respond"],[
 ["開始時検証失敗(fresh)","keep_partial=false","なし","Err"],
 ["開始時検証失敗(再開)","keep_partial=true","なし","Err"],
 ["UploadTruncated / Cancel / WriteFailed / CommitFailed","keep_partial=true","release_reserved=size、used_delta=+書けたバイト","Err(Cancel 以外)"],
 ["UploadOverflow / DecodeError / ChecksumMismatch / Malformed","keep_partial=false","release_reserved=size、used_delta=−offset(再開プレフィクスの返金)","Err"],
])}
"""))
S.append(("client","GetClient / PutClient",f"""
{code('''pub struct GetClientParams {
    pub path: String,
    /// ローカル既存 regular file の長さ(なければ 0)。再開 offset になる
    pub local_len: u64,
    pub accept_zstd: bool,
    pub limits: Limits,
}
pub enum ClientEvent {
    Bytes(Bytes), Fin, SendCapacity(usize),
    ReadDone { id: IoId, data: Bytes },   // ローカルプレフィクスの読み取り
    WriteDone { id: IoId }, WriteFailed { id: IoId, error: IoError },
    ResetReceived(u64), Cancel,
}
pub enum ClientCmd {
    Send { data: Bytes, fin: bool },      // 要求フレーム / Put 本体
    ReadLocal { id: IoId, pos: u64, len: usize },
    WriteLocal { id: IoId, data: Bytes }, // Get の本体書込(追記)
    TruncateLocal(u64),                   // 再開失敗時の 0 リセット等
    DeleteLocal,                          // トレーラ不一致・短い本体
    ResetStream(u64),
    Done(ClientOutcome),
}
pub enum ClientOutcome {
    Completed { plaintext_bytes: u64, verified: bool },
    Failed(ErrorResponse),                // サーバの Err
    ProtocolError(&'static str),          // FileReady 不整合など
    StalePartial,                         // 呼び出し側が 0 から 1 回再試行
    UnsupportedEncoding,                  // Put: Identity で 1 回再送
    Cancelled,
}
impl GetClient { pub fn start(p: GetClientParams) -> (GetClient, Vec<ClientCmd>); pub fn on_event(&mut self, ev: ClientEvent) -> Vec<ClientCmd>; }

pub struct PutClientParams {
    pub path: String, pub local_len: u64, pub mode: u32,
    /// Stat で得た partial 長(0 < p ≤ local_len のときだけ Some)
    pub resume_from: Option<u64>,
    pub no_clobber: bool, pub compress: bool, pub limits: Limits,
}
impl PutClient { pub fn start(p: PutClientParams) -> (PutClient, Vec<ClientCmd>); pub fn on_event(&mut self, ev: ClientEvent) -> Vec<ClientCmd>; }''')}
<h3>GetClient の検査</h3>
{table(["検査","結果"],[
 ["<code>FileReady.encoding</code> が Unknown、または accept していないコーデック","<code>ProtocolError</code>、DeleteLocal(0 から)"],
 ["Zstd で <code>size != plaintext_size</code>、または <code>plaintext_size &gt; max_file_size</code>","<code>ProtocolError</code>"],
 ["<code>offset + size != total_size</code>(length 未指定時)","<code>ProtocolError</code>"],
 ["再開なのに <code>checksum_follows == false</code>","<code>ProtocolError</code>"],
 ["サーバの <code>Err(InvalidRange)</code> で offset &gt; 0","<code>StalePartial</code>(呼び出し側が DeleteLocal 後に 0 から再試行)"],
 ["本体途中の Fin、トレーラ不一致、復号失敗","DeleteLocal、<code>Failed</code>"],
 ["<code>checksum_follows == false</code>(fresh)","受理するが <code>verified = false</code>"],
])}
<h3>PutClient の振る舞い</h3>
{table(["局面","動作"],[
 ["開始","<code>Send</code>(Put フレーム)。<code>encoding = Zstd</code> は <code>compress &amp;&amp; (local_len - offset) ≥ 1024 &amp;&amp; 既圧縮でない</code>。<code>checksum_trailer = true</code>、<code>checksum = None</code>"],
 ["再開","<code>ReadLocal</code> で <code>[0, offset)</code> をハッシュ、その後 offset から本体を <code>ReadLocal</code> → (符号化) → <code>Send</code>(SendCapacity の範囲)"],
 ["応答の並行監視(ADR-009)","本体送信中に <code>Bytes</code>(応答フレーム)を受けたら復号。<code>Err</code> なら <code>ResetStream(0x53)</code>、<code>Done(Failed)</code>。<code>Unsupported</code> かつ Zstd なら <code>Done(UnsupportedEncoding)</code>"],
 ["再開時の <code>ChecksumMismatch</code> / <code>InvalidRange</code>","<code>Done(StalePartial)</code>"],
 ["完了","トレーラ + fin を送り、<code>Ok</code> を受けて <code>Done(Completed)</code>"],
])}
"""))
S.append(("host","ホスト契約",f"""
{table(["#","契約"],[
 ["H1","ホストは 1 エンジンの <code>on_event</code> / <code>start</code> を同一タスク上で逐次に呼ぶ。返された <code>Vec&lt;Cmd&gt;</code> は<strong>順序どおり</strong>に実行する"],
 ["H2","<code>Event::Bytes</code> と <code>Event::Fin</code> はストリームの到着順。空の Bytes は送らない。Fin の後に Bytes を送らない"],
 ["H3","<code>SendCapacity(n)</code> は「今すぐ受理できるバイト数」の現在値。最初の値は <code>start</code> 直後に必ず 1 回送る。値が変わるたび(quiche の <code>stream_capacity</code> が増えたとき)に送る"],
 ["H4","<code>Cmd::Send</code> のデータは全量受理する。受理できない場合はホストの側でバッファし、以後 <code>SendCapacity</code> を 0 として報告し、バッファが空になってから実際の値を報告する"],
 ["H5","<code>ReadFile</code> / <code>WriteFile</code> は完了順が要求順と同じでなくてよいが、<strong>WriteFile の適用順は要求順</strong>(ホストは単一ワーカーまたは順序保証キューで実行する)。完了イベントの <code>id</code> は要求の id"],
 ["H6","<code>ReadDone.data.len() &lt; len</code> は EOF。エラーは <code>ReadFailed</code> で返し、panic させない"],
 ["H7","<code>Commit</code> は rename(temp → final)+ mode 適用 + 祖先 symlink 再検査 + <code>no_clobber</code> 再検査をホストが行い、いずれかの失敗を <code>CommitFailed</code> で返す"],
 ["H8","<code>Abort</code> はホストが temp を削除(keep_partial=false)または保持する。<code>Account</code> は <code>User</code> の atomics に反映する。どちらもエンジンからの順序で実行"],
 ["H9","接続断・シャットダウン・ストリーム reset 受信時は <code>Cancel</code> を 1 回送り、返された Cmd を実行してからエンジンを破棄する"],
 ["H10","<code>Done</code> の後にエンジンへ Event を送らない。送った場合エンジンは無視する(debug ビルドでは assert)"],
 ["H11","エンジンが <code>Respond(Err)</code> を返したら、ホストはそれをフレームとして送り、続く <code>Done(Failed)</code> まで Cmd を処理してストリームを FIN で閉じる"],
])}
<h3>quiche ホスト(サーバ)の擬似コード</h3>
{code('''// dispatch: ストリームごとの状態 = Engine + 送信待ちバッファ + in-flight I/O
loop {
    // 1. 受信: readable なストリームごとに stream_recv → Event::Bytes / Fin
    for sid in conn.readable() { while let Ok((n, fin)) = conn.stream_recv(sid, &mut buf) {
        cmds.extend(engine.on_event(Event::Bytes(buf[..n].into())));
        if fin { cmds.extend(engine.on_event(Event::Fin)); } } }
    // 2. I/O 完了: spawn_blocking の JoinHandle を select して Event::ReadDone 等
    // 3. 送信余地: writable なストリームで stream_capacity が変わったら Event::SendCapacity
    // 4. Cmd 実行
    for c in cmds.drain(..) { match c {
        Cmd::Send{data,fin} => { conn.stream_send(sid, &data, fin)?; }      // H4: 全量受理
        Cmd::ReadFile{id,pos,len} => { spawn_blocking(move || read_at(file, pos, len)) }
        Cmd::WriteFile{id,data} => { write_queue.push(id,data) }           // H5: 順序キュー
        Cmd::Respond(r) => send_message(conn, sid, &r)?,
        Cmd::Account(a) => user.apply(a),
        Cmd::Done(o) => { metrics.record(o); streams.remove(sid); }
        ... } }
    // 5. quiche のタイマーと egress(GSO)
}''')}
<h3>テスト用ホスト</h3>
<p><code>qftp-core/tests/engine_*.rs</code> は純メモリのホスト(<code>ScriptHost</code>)でエンジンを駆動します。ファイルは <code>Vec&lt;u8&gt;</code>、ストリームは <code>VecDeque&lt;Bytes&gt;</code>、送信余地は任意の数列を与えられます。各テストは「Event 列 → 期待 Cmd 列」の表で書き、状態表の全遷移を網羅します(e2e テスト仕様 CORE-* を参照)。</p>
"""))
page("転送エンジン API 仕様","参照文書","作成日: 2026-09-03 / 対象: qftp-core::transfer / 前提: 機能設計書「転送エンジン」、ADR-002 / ADR-005 / ADR-009",S,OUT)
