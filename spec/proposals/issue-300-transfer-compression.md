# Proposal: 転送圧縮 (zstd, オプトイン) — Issue #300 方針決定

ステータス: **方針提案 (spike/decision)** — 実装着手前のレビュー対象。
関連: Issue #300 / wire-freeze proposal ([qftp1-wire-freeze.md](qftp1-wire-freeze.md), #302) / spec-first 運用 (#298, #303)。

本ドキュメントは「圧縮のベストプラクティス再調査」を踏まえ、Issue #300 の推奨案(案C)を
**コードベースの実態で裏取りし、6つの要決定事項に根拠ある推奨を付け、ワイヤ凍結との整合を確定する**
ことを目的とする。調査は圧縮ベストプラクティス5観点 + 実コード検証4領域 + 敵対的批評で構成した。

---

## 0. 結論サマリ

- **方向性(案C)は妥当。** ALPN `qftp/1` 据え置き・平文ドメイン中核原則・`#[non_exhaustive]` Encoding は、
  既存パターン(numeric u32 enum + 末尾追加)と `spec/versioning.md` に整合する。
- **前提(2026-06-01 確定): 本プロジェクトはリリース前**。稼働中の旧peerが存在しないため、**圧縮を 1.0 ワイヤに
  最初から畳み込み、凍結ベースライン(test-vectors)ごと更新してよい**(#302 の「凍結」はリリース前の内部マイルストーン
  であり公開コミットではない)。これにより下記 §3 の bincode (B)方向問題は **本変更については発生しない**。
- 残る軌道修正は1点(下記 §2)。
  1. **Encoding/ErrorCode を positional derive enum ではなく、`HashAlgorithm` 流の hand-written numeric `u32` serde** にする
     (未知値を `Unknown(n)` 保存)。これは **リリース後**の codec/エラー追加(例 `lz4=2`)を forward-compatible にするための
     軌道修正で、(B)方向の制約が再来する将来のためのもの。**今(リリース前)の畳み込み自体には不要だが、入れ得**。
- **コーデック: zstd 単独。既定 level 3。窓 `window_log = 23` (8 MiB) を凍結値として wire-format に明記。**
- **伸長爆弾対策が本機能の最重要の追加実装。** 平文出力カウンタによる打ち切り + 平文基準 quota が確実な防御。

---

## 1. 推奨コーデック / レベル / 窓

| 項目 | 推奨 | 根拠 |
|---|---|---|
| コーデック | **zstd 単独** (v1) | 圧縮比/速度のパレート最前線を単一ダイヤルで支配。rsync 3.2 / borg / restic が既定採用。lz4 的高速域(負レベル)〜brotli 的高圧縮域(高レベル)を1コーデックで代替。 |
| 既定レベル | **level 3** | facebook 公式 / rsync `level0→3` / borg 既定 level3。転送の CPU/帯域トレードオフとして実務既定。 |
| 実装上限 | **level 12**、`>19` 禁止 | level 19 は level 3 比 ~280倍遅い(AWS 推奨も level≤12)。アーカイブ用途で 12 まで許容。 |
| レベルの位置づけ | **ワイヤ非ネゴ・送信側ローカルポリシー** | 復号はレベル非依存(窓のみに依存)。受信側はレベルを知る必要がない。 |
| 窓 (window_log) | **23 (8 MiB) を凍結値** | RFC 9659 の HTTP zstd と同値。デコーダのメモリ/爆弾耐性の上限。LAN/DC 用途の大窓(27)は将来オプション。 |
| 辞書 (dictionary) | **v1 非対応** (将来予約のみ) | 大ファイル単発が主用途で効果薄。辞書ID/配布/バージョニングが凍結済プロトコルを複雑化。 |
| 複数コーデック | **enum に並べない** | numeric enum なので将来 `lz4=2` 等を末尾追加するだけで forward-compatible。 |

> 実装ガード: エンコーダは **全レベルで `ZSTD_c_windowLog ≤ 23` を明示強制**(level 22 の既定窓は 27 なので、
> 設定し忘れると受信側 `window_log_max=23` で相互運用が壊れる)。デコーダは **`window_log_max = 23` を必ず明示設定**。

**crate**: `async-compression` (`features=["tokio","zstd"]`)。既存の tokio `AsyncRead`/`AsyncWrite` + `BufReader`/`BufWriter` な
QUIC ストリームに idiomatic に挿入でき、`zstd` crate の `Decoder::window_log_max` 相当(`DParameter`)を公開。
pure-Rust の `ruzstd` はエンコード非対応(experimental)なので本番不可だが、no-C 退避路として記憶に留める。
C ビルド依存(`zstd-sys`/vendored libzstd, `cc`)が増えるため **Phase 0 で musl/cross/Docker ビルド確認が必須**
(web-bridge は MSRV 1.88、他 crate 1.85 の差にも注意)。ライセンスは zstd=BSD-3/MIT で MIT 単独方針・`deny.toml` と整合。

---

## 2. 中核原則(平文ドメイン) — 確定

**平文をハッシュし、ワイヤ用に圧縮する。受信側は伸長してから伸長後ストリームをハッシュする。**

- `offset: u64` は**常に平文ドメイン**(Get=サーバが平文 offset へ seek、Put=`.partial` 長=平文byte)。
- 32byte BLAKE3 トレーラは**常に平文を被覆**(Get=post-offset/post-length、Put=フル平文)。完全性の意味は不変。
- `.partial` には**平文を書く**(decompress-on-write)。prefix 再ハッシュと `partial == offset` 不変条件は変更不要。
- 圧縮/伸長は**必ずストリーミング**(有界窓 zstd、whole-file バッファ禁止)。`BufReader`/`BufWriter` の間にコーデックを挟む。
- **各転送 = 独立完結 zstd フレーム**(resume 境界でコーデック状態を持ち越さない。平文 offset から post-offset 平文を新規圧縮ストリームとして送る)。

コード裏取り: `MAX_FILE_SIZE = 1 GiB` (`stream.rs:100`)、本体は frame length-prefix 対象外(`transport.rs`)、
quota は `used_bytes + in_flight_bytes` の reserve-before-check 型(`transfer_put.rs:291-312`)で全て確認済み。

---

## 3. bincode 前方互換は「一方向しか成立しない」(リリース前なので本変更は回避可)

> **前提更新(リリース前)**: 稼働中の旧peerが存在しないため、**圧縮を 1.0 ワイヤに最初から畳み込めば本問題は発生しない**
> (新旧peerの混在が起きない)。下記の (B)方向の落とし穴は **リリース後に field を足す場合にのみ再来する**。
> 従って本節は「§4-#2 で Encoding を numeric enum にする理由」「リリース後の field 追加で踏む罠」を記録するための
> 設計メモであり、**#300 を 1.0 リリース前に畳み込む限り、寛容デコードもマイナーALPNも実装不要**。
> 逆に **圧縮を 1.0 リリース後の minor 追加にする場合は、案①(寛容 tail-decode)が必須**になる。

### 事実(コード裏取り済み)

- bincode 1.3.3、`with_fixint_encoding().allow_trailing_bytes().with_limit(...)` (`transport.rs:537-543`)。
- デコードは `&stream_buf[4..4+msg_len]`(フレーム長ちょうどのスライス)を `deserialize` (`transport.rs:585`)。
- bincode は**自己記述でなく positional**。`allow_trailing_bytes()` は「**完全な値をデコードした後の余剰バイトを許す**」だけ。
- **`#[serde(default)]` は bincode 1.x の欠落末尾fieldを救わない**(serde_json 等の自己記述formatでのみ効く)。
- 既存の `Request`/`Response` は全 optional field が `#[serde(default)]`(`FileReady.total_size/checksum_follows/hash_algorithm` 等)。
  これらが今まで問題ないのは、**同一バージョンの peer 同士は常に全field を書く**から(#302 で現field集合ごと凍結済)。

### 帰結(非対称)

| 方向 | 動作 | 判定 |
|---|---|---|
| (A) **旧デコーダ × 新しい(長い)frame** | 既知fieldを読み終え残バイトを `allow_trailing_bytes` で無視 | ✅ 成立 |
| (B) **新デコーダ × 旧(短い)frame** | positional に新fieldを末尾で読みに行き payload 末尾で `UnexpectedEof` | ❌ **デコード失敗** |

### なぜ Get MVP で実害化するか

- 新client → 旧server: `Request::Get{...,accept_encoding}` を送る。旧server は (A) で `accept_encoding` を無視 ✅。
- 旧server → 新client: 旧 `FileReady`(`encoding`/`plaintext_size` 無し)を返す。**新client が読むと (B) で `UnexpectedEof` ❌**。

つまり **「古いpeerが未知fieldを無視して identity 縮退」は Get 応答方向では成立しない**。Issue 原案の前提が崩れる。
(既存fieldが無事なのは、すべて「新→旧」(A)方向の追加だったから。圧縮fieldは「旧server→新client」(B)が必須経路になる初の例。)

### 解決策(**要ユーザー判断 §9-Q1**)

- **案①: 寛容デコード (length-aware tail-decode)** — 推奨。transport層がフレーム長(`msg_len`)を知っているので、
  凍結 prefix をデコード → 残バイトがあれば拡張fieldをデコード / 無ければ default。bincode 1.x の `Deserializer` は
  読み取り位置を追跡できるため実装可能。ALPN `qftp/1` 据え置きのまま両方向が成立。conformance に
  **「旧frame(encoding無し)を新デコーダが読む」ケースを必ず追加**。実装はやや重いが凍結内で完結。
- **案②: マイナーALPN併存** — `qftp/1` と `qftp/1.1`(圧縮対応)を併存ネゴし、両peerが `qftp/1.1` を選んだときのみ
  圧縮field集合を前提化。field集合が混在しないので (B) 問題が構造的に消える。`qftp/2` メジャーバンプ(案A)より軽量。
  ただし wire-freeze proposal の Out of scope(in-band capability は qftp/2 送り)との整合解釈が必要。
- **案③: 詰めてから着手** — Phase 1 前に①の手動デコード方策を設計確定 + conformance ケースを先に用意。

> versioning.md:65-73 は既にこの非対称を MUST/MUST NOT で明文化済み(「sender は peer が後発field を埋めると仮定してはならない」)。
> 案①は spec が要求する「受信側がそれ無しで処理を進められる」をコーデック層で実現する唯一の方法。

---

## 4. 6つの要決定事項への推奨

| # | 論点 | 推奨 | 要点 |
|---|---|---|---|
| 1 | Put 能力発見 | **明示フォールバック**: 新server が未知 Encoding → `Unsupported(405)` 即拒否 → client は identity で1回再送。**圧縮Putは checksum 必須化**。 | ⚠️ 但し **真の旧server には 405 は来ない**(encoding を余剰バイトとして無視し圧縮byteを生で書く)。旧server経路の実効防御は **`ChecksumMismatch`(checksum必須化で必ず発火)**。両者は別経路。capability プローブ(別Request)は追加しない。 |
| 2 | コーデック/レベル | **zstd 単独 / level 3 / 辞書なし / numeric enum**。 | Encoding を `HashAlgorithm` 流 hand-written numeric `u32`(`Identity=0, Zstd=1, Unknown(n)`)。positional derive enum だと未知値が `Malformed` 拒否になり拡張時互換が劣る。**要ユーザー確認**。 |
| 3 | 伸長爆弾エラーコード | 出力打ち切り → 既存 **`UploadOverflow(423)`**、quota超過 → 既存 **`QuotaExceeded(430)`**、不正zstdフレーム/窓超過 → **新 `DecodeError`(4xx, 例431)追加**。 | `ErrorCode` は numeric u32 + `#[non_exhaustive]` + `Unknown(n)` 保存なので新コード追加は forward-compatible。新コードは PROTOCOL-CHANGELOG + test-vectors 追加が MUST。**要ユーザー確認**。 |
| 4 | 既定ポリシー | **決定: default-on + 既圧縮データ自動回避**(拡張子/magic or 先頭ブロック圧縮率閾値で Identity 縮退)。 | ユーザー決定(2026-06-01): ログ/JSON/ソース中心の用途で帯域/転送時間の削減を取る。既圧縮メディア(jpeg/zip/mp4)は自動回避で逆効果を防ぐ。攻撃表面はファイル本体のみ・per-file独立フレームで限定的(§5)。**送信側ローカル挙動でワイヤ互換には無関係**。 |
| 5 | web-bridge 二重圧縮 | **二択自体が前提誤り。** web-bridge は qftp-server プロキシではなく **共有 `qftp_protocol::handler` でローカルFSを直接サーブする独立サーバ**(中継しない)。圧縮責務を **アプリ層単一**に寄せ、WebTransport/HTTP3 content-encoding は使わない(Identity)。 | コード裏取り: `web-bridge/src/main.rs` が `qftp-protocol core` を駆動、`http.rs` は SPA静的配信専用。ブラウザSPA(`app.js`)は Rust crate を使えず JS側 codec(gzip/WASM zstd)が非対称になるため、**初期は web-bridge 経路を Identity 固定で MVP 範囲外**。 |
| 6 | quota 平文基準 | **確定(平文基準)**。受信側 disk/quota は**伸長後の平文byte**で判定。Put 要求に `plaintext_size` を持たせ、(a)伸長前 `declared > MAX_FILE_SIZE`/quota なら即拒否、(b)伸長中 `decompressed_written` カウンタが `min(declared, MAX_FILE_SIZE)` 超過で `UploadOverflow`、quota 超過で `QuotaExceeded` の二段ガード。 | 複数 CVE(file-type / Authlib / cpp-httplib)の共通根本原因=「圧縮byteで上限を数えた」。**`declared` はメモリ事前確保に使わない**(信用すると OOM)。実出力カウンタが唯一の確実な最終防御。 |

---

## 5. セキュリティ

- **完全性は不変**: BLAKE3 は常に平文を被覆。圧縮はトレーラの被覆対象を変えない。コーデックバグ/改竄で伸長結果が壊れても
  平文 BLAKE3 が必ず検出(Get=client ローカル削除、Put=`ChecksumMismatch` で temp 削除)。
- **伸長爆弾(本機能の最重要追加対策)**: §4-#6 の二段ガード + デコーダ `window_log_max=23` + `Read` を `take(MAX_FILE_SIZE)` で
  構造的に打ち切る。`window_log_max` は per-frame メモリのみ上限し**総出力は上限しない**(多数小フレームの streaming-bomb)ため、
  **出力カウンタが唯一の確実な最終ガード**。`declared`(=`ZSTD_CONTENTSIZE_UNKNOWN` もあり得る)は安価な事前却下専用で攻撃者には無力。
- **無検証Put穴**: `offset==0 && checksum_trailer==false && checksum==None` の経路は検証なし(`protocol.rs:514-516` 既存挙動)。
  ここでは `ChecksumMismatch` fail-safe が発火しない。→ **圧縮Put × no-checksum を `start_put` 入口で `Unsupported` 拒否**して塞ぐ。
- **CRIME/BREACH 非適用**: per-file 独立 zstd フレーム・秘密非混在・本体のみ圧縮という MUST で構造的に不成立(RFC 8878 §3.1/§8 と整合)。
  認証トークン/credential は本体に載らない(web-bridge は別系統 bearer)。compress-then-encrypt の**長漏洩**は
  ファイル転送ではサイズ既知で受容範囲。サイズ秘匿が要件化したら任意パディングを将来オプション。
- **0-RTT 不変**: 圧縮field は Get/Put/FileReady のみ。これらは元来 `request_is_replay_safe` 集合(Ls/Cd/Pwd/Stat/Quit のみ)外で
  1-RTT 必須。replay-safe 集合は本体を持たず圧縮field も持たないため **0-RTT 表面は一切増えない**。新 Request variant も追加しない。
- per-user ACL 不変。`required_op()` は未知 variant を fail-closed(`PermissionDenied`)に倒す(`handler.rs:334-350`)。

---

## 6. spec-first 手順(ワイヤ凍結 #302 との整合)

- 圧縮field/Encoding値/`DecodeError` 追加は **「末尾field追加」「numeric enum 値追加」に限定**すれば
  versioning.md が認める後方互換構造変更で、ALPN `qftp/1` 据え置き・メジャーバンプ不要。
  **新fieldが既存fieldの byte 意味を一切変えない(末尾追加のみ・型/幅/順序不変)ことが絶対条件。**
- **test-vectors は default 値でも必ず変わる**: bincode positional なので新field(`accept_encoding`=空Vec→u64長8byte、
  `encoding`=u32 4byte、`plaintext_size`=u64 8byte)が必ずシリアライズされ、全 Get/Put/FileReady の `wire_hex`/`payload_hex` が伸びる。
  CI(`ci.yml:52-55` の gen-vectors→`git diff --exit-code`)が**必ず検出**する(=「ワイヤが変わった」を捕捉する設計が正しく機能)。
- 更新対象(全て MUST): `spec/wire-format.md`(Get/Put/FileReady の field 表に末尾追記、Encoding を numeric enum として分類記載、
  ErrorCode 表に `DecodeError`)/`spec/versioning.md`/`spec/error-codes.md`/`PROTOCOL-CHANGELOG.md`/`SECURITY.md`(圧縮脅威モデル)/
  `conformance` の `request_samples`/`response_samples`(Identity と Zstd、`plaintext_size`、新ErrorCode、**旧frame→新デコーダ**ケース)。
  → `gen-vectors` 再生成 → diff ゲートを通す。順序は **spec → impl → vector**。

---

## 7. 段階的実装計画

- **Phase 0 — spec-first 凍結 + 依存検証**: 上記 §6 の spec/SECURITY/CHANGELOG を先に更新。
  `window_log=23` 凍結値、Encoding numeric enum、`DecodeError`、平文ドメイン中核原則、圧縮セキュリティ MUST を文書化。
  **`async-compression`+`zstd-sys` の musl/cross/Docker/MSRV(1.85) 検証**もここで。§3 の bincode 互換方策(①/②)を確定。
- **Phase 1 — Get 方向 MVP**: `qftp-common` に Encoding enum + `Request::Get.accept_encoding` + `Response::FileReady.{encoding,plaintext_size}`。
  サーバが `accept_encoding` から選び `FileReady.encoding` 確定(非対応/既圧縮は Identity)。受信側(client/web-bridge)は
  `window_log_max` 設定済み Decoder + `take(plaintext_size)` + 出力カウンタで伸長。BLAKE3/offset/size/`.partial` は全て平文ドメインのまま。
  圧縮は `stream_send`/`stream_recv` 直近にオンザフライ。**§3 の tail-decode と conformance 旧frameケースをここで実装・検証**。
- **Phase 2 — Put 方向**: `Request::Put.{encoding,plaintext_size}`、伸長爆弾二段ガードを `transfer_put.rs` の `drive_put` Phase A 書込みループ +
  `start_put` leftover/rehash 経路に挿入(`StreamState::ReadingFileData` に `decompressed_written:u64` 新設)、平文quota会計、
  無検証Put穴の封鎖(compressed+no-checksum を `Unsupported` 拒否)、`Unsupported`→identity 再送フォールバック。
  client `config.rs` に圧縮ポリシー(`compress`/`codec`/`level` の Option)を機械的追加。
- **Phase 3(任意)**: web-bridge JS側 codec 整合、辞書、複数コーデック(numeric追加)、長精度漏洩向け任意パディング、LAN向け大窓(27)。

クレート別着手順: `qftp-common`(protocol.rs) → `qftp-conformance`(samples+gen-vectors) → `qftp-protocol`(stream.rs 共有ヘルパ) →
`qftp-server`/`qftp-client`(Get→Put) → `qftp-web-bridge`(任意)。

---

## 8. 残リスク

- **(最大) bincode (B)方向**: 新client × 旧server の `FileReady` デコード。§3 の方策にコミットしないと Get MVP が壊れる。
- **無検証Put穴**: 圧縮Put × no-checksum を入口で拒否し忘れると無言破損/爆弾素通り。
- **平文offset × 圧縮器ステートフル性の非可換**: Get 部分送信の `seek_relative` 巻き戻し(`transfer_get.rs:356-382`)が圧縮器状態と非可換。
  「各転送=独立フレーム」でもフレーム内ストリーミング状態は stateful なので、**圧縮出力をバッファし「ワイヤ受理分だけ送る/未受理分は圧縮バッファに残す」再設計**が必要(現 `seek_relative` 前提コードの構造変更)。批評が過小評価を指摘した点。
- **`plaintext_size` 詐称**: 信用してメモリ事前確保すると OOM。`declared` は事前却下専用、実出力カウンタが主防御。
- **チャンクサイズ非対称 + `classify_put_chunk` の「ワイヤbody長=平文body長」前提**(`stream.rs:208`)が圧縮で崩れる。
  Put 受信の body/trailer split を**ワイヤ長基準**に作り替えるのが最も侵襲的でバグはトレーラ取り違え/破損に直結。
- **C ビルド依存 + MSRV 差**(web-bridge 1.88 / 他 1.85)。musl/cross/Docker 確認必須。
- **window 強制**: 高レベルで `ZSTD_c_windowLog ≤ 23` を全レベルに強制し忘れると相互運用が壊れる。
- **代表コーパス未実測**: window=23 と qftp 主用途(大ファイル単発)の相性を自前コーパスで実測する手順を計画に追加すべき。

---

## 9. 要ユーザー判断(open forks)

- **Q1: bincode (B)方向 — 解決済(リリース前)**。圧縮を 1.0 ワイヤに畳み込み、test-vectors を新ベースラインとして更新する
  (寛容デコード/マイナーALPN は不要)。**前提: 圧縮は 1.0 リリース「前」に入れる**(リリース後の minor 追加にするなら案①が必須)。
- **Q2: 既定ポリシー — 決定: default-on(自動回避付き)**(2026-06-01)。
- **Q3: 次アクション — 決定: Phase 0(spec-first)着手**(2026-06-01)。
- (確認のみ) Q-codec: zstd単独/level3/window23/辞書なし/numeric enum で確定してよいか。Q-err: `DecodeError` 新設 vs 既存再利用。

---

*本提案は spike/decision であり最終実装ではない。スキーマ・ワイヤ仕様は実装着手前のレビューで変更されうる。*
