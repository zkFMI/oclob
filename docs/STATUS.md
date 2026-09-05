# OCLOB実装状況と受入条件

## 判定

OCLOBは研究用MVPです。新しいCLI/Docker経路では、法人2社の実際の事前予約、7つの常駐MPCノードでの照合と共同zkPI、5つのAvalanche検証ノードによる匿名保有記録の決済を一続きに確認しました。事前予約の証明は法人が作り、注文を分割配送する前にDeFMIでの確定を読み直します。約定後に開く予約権限には注文原文を含めず、法人の追加署名も求めません。各Rust VMが証明全文と現在の予約状態を検証します。同じ決済の再送で二重適用がないこと、1検証ノードの再起動後も5ノードの台帳が一致することを確認済みです。

前段のDeFMI `33d0c97` を使った試験では、支出証明と一括決済口で、決済後の受取権3件の取込み、両法人の秘密残高の復元、返金された同じ保有記録を次の注文の資金へ使う従来経路を再確認しました。次の注文は7ノードでの受付までで、約定・決済はこの試験に含みません。再現方法は[ウォレットの実行手順](CORPORATE_WALLET_JA.md)です。現在の依存版は、取消専用の署名認可を加えた `4b07c2b` に固定しています。

さらに各MPCノードが、自分の照合記録と決済指図全文を、設定済みDeFMIの確定記録に照合してから板状態を進めるようにしました。7ノードすべての未確認・すり替え通知の拒否と、正常な決済から返金の再利用までを実試験しました。証拠は `artifacts/oclob_native_finality.json`、接続方法と信頼の範囲は[決済確認の説明](NATIVE_FINALITY_JA.md)です。取消・期限切れの実装後はSoftbank上で97件のRustテスト、整形、警告を許さない静的検査を通しています。

別シナリオでは、同じ売り法人の注文2件と買い注文1件から、60単位を100、30単位を101で約定させ、1取引で全件決済しました。各ノードが全約定の一覧を自分の結果から計算して署名し、指図の抜出し決済を拒否します。14件のノード別確定確認、共有保証枠の更新番号4/3、5バリデータの台帳一致と実再起動を確認しました。[複数約定の仕組みと限界](NATIVE_MULTIFILL_JA.md)、証拠は `artifacts/oclob_native_multifill.json` です。

さらに[継続取引](NATIVE_CYCLE_JA.md)では、上記2約定後の受取権5件と秘密残高を復元し、実際の返金330を次の買い注文の予約で消費しました。元の売り注文の秘密残数量30と再度照合し、1単位・価格101を別取引で決済、残数量29・予約更新番号2へ進めています。再度の復元後は受取権累計8件、両法人の保証枠更新番号5となり、5検証ノードの台帳一致と実再起動を確認しました。証拠は `artifacts/oclob_native_cycle.json` です。内部のDeFMI接続を正常応答後も保持して次回失敗する不具合を修正し、金融処理の自動再送は加えていません。

続いて[取消・期限切れ](NATIVE_LIFECYCLE_JA.md)では、残る29単位の取消、返却資産からの5単位の新規注文、実期限後の元資産回収を接続しました。両解放の7ノード別の確定確認、累計9受取権と保証枠更新番号8/5、7 MPCノードの実再起動前後の全保存状態一致、5検証ノードの台帳一致を確認済みです。証拠は `artifacts/oclob_native_lifecycle.json`、実行した59ファイルのハッシュは `artifacts/oclob_native_lifecycle_sources.json` です。

`artifacts/oclob_native_notes.json` と `artifacts/oclob_native_recovery.json` は、以前の依存版での接続・停止復旧の記録です。旧支出証明には[安全性上の欠陥](https://github.com/shukob/defmi/blob/153fe671e523ec573a6c6261f341423a49371f5d/docs/NOTE_PROOF_SECURITY_REVIEW_20260905.md)が見つかっており、旧正常系の成功を修正版の安全性の証拠として流用しません。

いずれも単一ホスト・少数注文での機能確認です。常駐ワーカー、取消・期限切れの無人復旧と同時更新、独立運営と本番APIは未受入です。各ノードは決済を自分で確認しますが、照合先のDeFMI接続サービスへの信頼は残ります。新しい支出証明の独立した暗号監査と、旧保存状態からの移行審査も残ります。従来の口座差分方式とブラウザ用の中央調整経路も残っており、新経路の保証をそのまま適用しません。

「実装済み」はsourceがあるだけではなく、repositoryのremote release gateで動かす対象になっていることを示します。「未受入」は設計や一部codeがあっても、本番の信頼境界または実環境で確認できていないことを示します。

## 機能別状況

| 領域 | 状況 | 現在の証拠 | 本番受入に残るもの |
|---|---|---|---|
| 秘密注文wire | 実装済み | 厳格encode/decode、commitment、署名test | schema version交渉、外部client互換試験 |
| GTC / IOC | 実装済み | coreとservice test | 長時間運転、restart recovery |
| 価格・時間優先 | 実装済み | clear referenceとMPC outputの一致test | WAN並行投入、fairness定義の形式化 |
| 部分・複数約定 | 実装済み | 最大8枠batch回路、原子的multi-fill | 8枠上限の拡張または分割規則 |
| 取消・期限切れ | 新経路で1ホスト機能確認済み | 元の注文専用鍵、5ノード以上の受付順、未決済約定の追越し拒否、現在の予約への3ノード署名、実期限による解放、全7ノードの台帳確認 | 公開API・常駐キューへの接続、失敗時の無人復旧 |
| 受付順5-of-7 | 実装済み・1ホスト受入済み | 7ノード投票、証明本体、連鎖、署名前の永続化、各MPCノードでの再検証、二重投票拒否 | HSM key、epoch交代、独立node/WAN、公平到着順の定義 |
| 法人側の注文分割と直接配送 | 実装済み・1ホスト受入済み | Pedersen検証付き3-of-7分割、ノード別暗号文、固定長mTLS通信、各ノードの署名付き保存受領証、7コンテナE2E | 別運営者WAN、鍵の個別生成・保管 |
| 注文別の決済鍵解放 | 実装済み・1ホスト受入済み | 注文ごとの乱数鍵、署名付き3-of-7 Shamir/Feldman分割、ノード別暗号保管、MPC結果永続化後の決済専用mTLS解放、2片・事前解放・未約定IOC・誤権限・改ざんの拒否 | 独立運営者での鍵生成、HSM、約定後の共同zkPI生成 |
| MP-SPDZ秘密照合と板持越し | 実装済み・1ホスト受入済み | 公式compilerとmalicious-shamir、1コンテナ1 party、各ノード72秘密値の板状態と最大8×616決済証明値を含む5000値のPersistence、DeFMI確定後だけ親状態を更新、次回照合でMaker残量shareを再利用 | 別host 7 party、秘密板の圧縮・取消・深い板、通信量・障害評価 |
| 平文fallback禁止 | 実装済み | binary不在・party失敗時fail closed | 運用SLOとbackpressure |
| DeKYX参加資格 | 実装済み | pinned `dekyx-core` adapter test | issuer governance、失効配布、HSM |
| 法人単位の枠合算 | 実装済み | DeKYX entity単位reservation test | CCP/DeFMI外部設定、権限・更新監査 |
| 共同zkPI/DvP証明 | 実装済み・1ホスト機能確認済み | 7ノードが各自の616秘密値から共同証明を生成。実際の照合結果・予約条件・暗号化情報に結び付けた専用の決済文を3ノードが署名。事前予約証明は法人側で生成 | 独立証明者、全ての署名用乱数の世代整合、悪意ある暗号化断片の検出・復旧 |
| DeFMI原子的DvP | 新形式で1ホスト機能確認済み | 両法人の匿名予約を消費。2約定の一括決済、その後の実約定、残り注文の取消・期限切れまで接続。5検証ノードの一致、二重適用なし、検証ノード再起動を確認 | 同時注文、独立検証者、再編、暗号監査と旧状態の移行審査 |
| MPC側の決済確定確認 | 新経路で1ホスト機能確認済み | 7ノード各自の読み取り専用mTLS、署名済み照合・指図・確定記録の一致、未確認・すり替えの拒否、同じ記録の再送で状態不変。全約定がそろうまで板更新を拒否 | 接続サービスへの信頼を減らす合意証明、委員会登録履歴、旧版で進めた板の明示的な再照合、独立運営・障害試験 |
| 法人ウォレット・返金の再利用 | 新経路で1ホスト機能確認済み | 2約定後の返金330から次の約定を行い、残り29単位の取消から5単位の新規注文・期限切れを実行。累計9受取権、両法人の枠更新番号8/5、未約定の元資産の回収を確認 | 長時間の連続取引、同時更新、保存領域全体の巻戻し、鍵交代 |
| 暗号化耐久queue | 実装済み | AEAD、idempotency、順序、cover slot test | 鍵永続化、世代整合restart、HA |
| 公開板 | 実装済み | price level aggregateのみ | 差分漏洩測定、公開頻度・粒度の市場実験 |
| React Flowデモ | 実装済み・研究用受入済み | OmenX Docker runtimeをIABの1440×1000/390×844で操作。売りGTC 100口、買いIOC 40口、残60口、参加者別残高、5/7受付、7-process MPC、閾値zkPI、DeFMI高さ3を確認。横overflow 0、console error/warn 0 | 認証済み本番APIとの接続、継続的a11y試験 |
| 分離MPCコンテナ | 実装済み・1ホスト受入済み | 一node一暗号化share、一container一party、mTLS、署名済み同一結果、再実行防止 | 別運営主体、一party一host、独立鍵生成・KMS/HSM |
| 実Avalanche L1 | 1ホスト受入済み | AvalancheGo 1.14.2、5 validator、非EVM Rust VM、RPC finality、readback、1 validator再起動復旧 | 独立host/運営者、WAN、reorg、HSM鍵 |
| 本番HTTP/API | 部品実装・未受入 | 新しいDeFMI接続口は相互TLS、固定した接続者と役割、許可したAPIだけの転送、通信量上限を実装。ブラウザは従来のデモAPI | 本番の法人登録、認可・監査、送信頻度制限、運用管理、画面との接続 |
| 形式安全性証明 | 未受入 | property/unit test | security definition、proof、査読 |
| 統計的性能比較 | 未受入 | rough E2E一件 | preregistered cohort、CI、throughput/latency gate |

## crate別の責務

- `oclob-core`: 注文、commitment、公開板、価格・時間優先の基準状態機械。
- `oclob-dekyx`: DeKYX匿名法人資格を注文用途へ結合するadapter。
- `oclob-ordering`: 受付番号、5-of-7 certificate、連鎖、二重投票拒否。
- `oclob-edge`: 法人端末で注文と決済鍵を分割し、各ノード向け固定長暗号文と公開manifestを作る。
- `oclob-node`: 自ノードの暗号文保管、受付順投票、MP-SPDZ実行、秘密板shareの保存、DeFMI確定後の親状態更新、署名済み実行結果へ固定した共同証明寄与、結果永続化後の署名付き鍵片解放。
- `oclob-mpc`: MP-SPDZ回路生成、公式compile、7 party実行、公開output一致確認、ノード別秘密状態と約定別決済証明shareの書出し。
- `oclob-proofs`: 受付証明、MPC出力、板の前後root、fillを一つの遷移statementへ結合。
- `oclob-settlement`: 法人枠、reservation、共同zkPI/DvP証明、受取人別暗号化opening、原子的multi-fill DeFMI DvP。
- `oclob-service`: 下流失敗時にbook/ordering/settlementをcommitしない調整、暗号化queue。
- `oclob-demo`: outcome-first E2E受領証とReact Flow HTTPデモ。

## 研究用MVPの完了条件

次が同じ固定commitで通ることを条件にします。

1. 全Rust crateのformat、clippy、release test。
2. React Flowのtypecheckとproduction build。
3. 公式MP-SPDZ checkoutと `malicious-shamir-party.x` を使う。
4. 7 partyが同じMPC outputへ合意する。
5. resting GTCとarriving IOCが価格・時間優先で部分約定する。
6. threshold zkPIが金額・価格範囲を証明する。
7. DeFMIが資金・証券を一つのbatchで更新する。
8. canonical readbackとreceipt digestが一致する。
9. 同じ指図を二重適用しない。新経路では同じ送信への応答を再利用する。
10. 公開板、参加法人、自社portfolio、MPC、zkPI、DeFMIを実browserで確認する。
11. 約定前には決済権限を開けず、正しいMPC結果の永続化後だけ3ノード以上の鍵片で開ける。
12. 各約定の共同証明が、7ノードの秘密共有と同じ署名済みMPC公開結果へ固定される。

## P0: 本番移行を止める課題

予約証明の監査で確認した、台帳参照からの売買方向漏洩、要約値の一致による照合、
証明再発行や注文削除後の予約再利用は、[予約証明の情報分離](RESERVATION_PRIVACY.md)に
R1〜R6として列挙しています。受付証明の分離、要約値の秘密乱数の変更、市場の固定、
予約固有の永続的な使用記録を実装し、実Avalanche上の匿名ノート予約から
決済までを1ホストで確認しました。以下は、その結果だけでは閉じない本番受入条件です。

### P0-1 注文を中央プロセスへ平文で渡さない — 分散経路で実装済み

`oclob-edge` と `oclob-node` を使う分散経路では、法人側が注文を検証可能な7分割へ変換し、ノードごとに別々に暗号化して直接送ります。調整役はcommitment（注文の要約値）、受付証明、署名付き公開結果だけを扱います。OmenX上の7コンテナ受入では、調整役へ平文注文を渡さずに40口を価格100で約定し、同一ラウンドの再送で二度目の計算を起動しないことを確認しました。

各MPCノードは、保存した注文要約値、永続状態の世代、保存状態の要約値を自分の鍵で署名します。参加法人から引き継いだ受領証は、コンテナ停止後でも7ノードの公開鍵に対して検証できます。公開要約の署名には注文ごとの使い捨て鍵を用い、法人の長期application keyは調整役へ渡しません。各ノードは受付票を返す前に同じ通番への投票を永続化し、MPC起動前には5票以上の証明本体、対象注文、前証明との連続性を自分で再検証します。

照合回路は固定8枠と到着注文について、有効状態、売買方向、価格、残量を `sint.write_to_file` で各partyのPersistenceへ書きます。各ノードは自分のファイルだけを0600で保存し、署名済み受領証にはファイルの要約値と使用した親状態の要約値だけを載せます。DeFMIの正本受領証と高さが確定した後に限り、そのファイルを次回照合の親へ進めます。OmenXの受入では、Makerの7つの秘密残量を確定後にTaker照合へ引き継ぎ、40口約定後の20口を中央で復元せず保持しました。

一方、React Flowの単体デモが使う `OclobService::submit` は、従来どおり `SecretOrder` を受けてから7入力を作ります。したがって、中央非開示の保証は分散経路だけに適用します。

残る変更:

- React Flowデモと公開APIを分散経路へ切り替え、中央経路を研究用互換モードへ限定する。
- 法人CLIの保存・再送、複数約定後の資産回復、次の約定、残り注文の取消・期限切れまで接続済み。次は常駐ワーカーと同時更新時の無人復旧をつなぐ。新経路の決済権限に注文原文は含めない。

### P0-2 7 partyを独立運営する

1コンテナ1ノード、ノード別保存領域、相互TLS、ノード署名までは実装しました。ただし受入環境は同じhost・同じ管理者で、検証用の鍵も一つのlab作成器が生成します。k-of-nの暗号条件と、現実の独立性は別です。

必要な変更:

- 一party一hostとし、7運営者がそれぞれ鍵を生成する。
- 独立KMS/HSM、管理者、監査log、障害領域。
- mTLS、固定peer identity、epoch設定。
- WAN latency、packet loss、partial outage、selective abort試験。
- party omissionとequivocationを公開情報だけで追跡するreceipt。

### P0-3 分散MPCから実DeFMI/Avalancheまで一つに接続する — 匿名ノート経路も1ホストで確認済み

DeFMIを先に起動し、法人2社が所有権・予約可能額・DeKYX参加資格の証明を送ります。専用の接続口が証明を検証し、台帳で確定した予約にだけ受付証明を発行します。法人自身も同じ予約を読み直してから、7ノードへ注文の断片を渡します。法人の鍵・資金の秘密値は調整役やDeFMI接続口のファイルへ渡しません。

7ノードは自分の秘密共有から共同zkPIを作り、各署名者は自分が実行した照合結果、正しい予約、完成した証明、暗号化した受領情報を確認します。決済担当は成立した注文の予約権限だけを開き、共同証明を作り直さず `issueApplicationNoteFill` へ送ります。各Rust VMが共同証明全文、予約の更新番号、資産の対応と二重消費を検証します。約定後の法人署名は不要です。

単一ホストの実行で、価格100・数量40の約定、Makerの残り予約の維持、Takerの予約終了、差し替えたMPC結果の拒否、同一決済の二重適用防止、5検証ノードの台帳一致と再起動復旧を確認しました。詳細な証拠と旧方式との境界は[実行手順](NATIVE_PRETRADE_DEMO.md)に記載しています。

必要な変更:

- 法人側の自動再試行と同時注文を新しい予約・決済経路へ接続して確認する。複数約定、取消・期限切れの正常系、CLIの保存済み要求による再開は確認済み。
- 正常系では受領した権利を保有記録へ変換し、同じ返金を次の予約へ使うところまで確認済み。悪意ある暗号化断片、ノード停止、複数約定をまたぐ継続復旧は残る。
- MPCノードが秘密板の状態を進める境界でも、正本の決済受領証を独立に検証する。
- 独立host/運営者のvalidator、WAN、timeout、reorg相当を試験する。
- zkPI verifier、asset schema、participant moduleをgenesis/configから固定する。
- consensus receiptと認証済みOCLOB API/画面の確定表示を結合する。

### P0-4 永続状態と鍵を同じ世代で復旧する — 秘密板の単一世代更新は実装済み

秘密板については、実行受領証が入力親と出力ファイルを結び、同じDeFMI確定通知の再送を同一結果にし、古い親からの確定で新しいheadを上書きしない仕組みを実装しました。一方、participant wallet、committee key、共同証明nonceを含む全体snapshotは未完成です。queueや秘密板だけ残したrestartを、本番復旧完了とは扱えません。

必要な変更:

- versioned snapshotとwrite-ahead log。
- HSM/KMS key referenceとrotation epoch。
- queue、book、reservation、used nullifier、canonical heightのcheckpoint。
- crash pointごとのrestart test。
- backup、restore、disaster recovery runbook。

### P0-5 本番の認証・運用制御

demo APIは閉域可視化用です。viewerはquery parameterであり、node toggleにも管理認証がありません。

必要な変更:

- 法人mTLSとrequest署名。
- RBAC/ABAC、tenant isolation、operator separation。
- secret-free structured audit log。
- rate limit、queue capacity、DoS protection。
- vulnerability handling、dependency/SBOM/signing。

## P1以降

- P1: 8枠を超える深い板の回路戦略、複数market、cross-DeFMI DvP/PvP。
- P1: 公開板の更新頻度、数量bucket、差分漏洩、dummy処理の経済評価。
- P1: MPC preprocessing、program cache、parallel market partitionによる性能改善。
- P2: ZKで検証可能な全遷移、query-oblivious accountability、selective abort slashing。
- P2: DPを使う公開統計と法人単位privacy budget。
- P2: post-quantum署名・commitment・transportへの段階移行。
- P3: 市場参加者を含む経済実験、front-running成功率、spread、depth、MM損益比較。

## 新規性を主張するときの境界

OCLOBは、MPC、threshold encryption、暗号化DEX、price-time CLOBの各要素を初めて発明したとは主張しません。研究差分候補は、非バッチ連続CLOBにおいて、次を一つの検証可能な状態遷移として結ぶ設計と実証です。

- 内容を見せずに受付順を確定する。
- 秘密のprice-time matchingを行う。
- 公開板はprice-level aggregateだけを出す。
- 参加法人の事前承認と法人合算枠を使う。
- 約定後の再署名を不要にする。
- threshold zkPIでDeFMIの原子的DvPへ直結する。
- MPC停止時も平文fallbackせず、暗号化queueで順番を保持する。

先行研究との詳細なclaim boundaryは [RELATED_WORK.md](RELATED_WORK.md) を参照してください。
