# OCLOB実装状況と受入条件

## 判定

OCLOBは、研究用MVPとして、法人側の注文分割、注文別の3-of-7決済鍵、7 MPCノードの秘密照合、ノードごとの秘密板の持越し、Maker予約、Taker予約とDvP、5検証者の非EVM DeFMI Avalanche L1確定までを一続きに実装し、1ホスト上で受入済みです。約定前に全注文を開ける単一の決済鍵と、次回照合のために中央で平文板を持つ必要は廃止しました。ただし、本番移行可能と判定できる段階ではありません。特に、独立したMPC/validator運営者、鍵・証明nonceを含む世代整合、本番APIの認証・運用制御、約定後も注文全文を一か所へ復元しない共同zkPI生成がP0です。

「実装済み」はsourceがあるだけではなく、repositoryのremote release gateで動かす対象になっていることを示します。「未受入」は設計や一部codeがあっても、本番の信頼境界または実環境で確認できていないことを示します。

## 機能別状況

| 領域 | 状況 | 現在の証拠 | 本番受入に残るもの |
|---|---|---|---|
| 秘密注文wire | 実装済み | 厳格encode/decode、commitment、署名test | schema version交渉、外部client互換試験 |
| GTC / IOC | 実装済み | coreとservice test | 長時間運転、restart recovery |
| 価格・時間優先 | 実装済み | clear referenceとMPC outputの一致test | WAN並行投入、fairness定義の形式化 |
| 部分・複数約定 | 実装済み | 最大8枠batch回路、原子的multi-fill | 8枠上限の拡張または分割規則 |
| 取消・期限切れ | 実装済み | authority、遷移proof、予約解放test | 公開API、外部clock/epoch運用 |
| 受付順5-of-7 | 実装済み・1ホスト受入済み | 7ノード投票、証明本体、連鎖、署名前の永続化、各MPCノードでの再検証、二重投票拒否 | HSM key、epoch交代、独立node/WAN、公平到着順の定義 |
| 法人側の注文分割と直接配送 | 実装済み・1ホスト受入済み | Pedersen検証付き3-of-7分割、ノード別暗号文、固定長mTLS通信、各ノードの署名付き保存受領証、7コンテナE2E | 別運営者WAN、鍵の個別生成・保管 |
| 注文別の決済鍵解放 | 実装済み・1ホスト受入済み | 注文ごとの乱数鍵、署名付き3-of-7 Shamir/Feldman分割、ノード別暗号保管、MPC結果永続化後の決済専用mTLS解放、2片・事前解放・未約定IOC・誤権限・改ざんの拒否 | 独立運営者での鍵生成、HSM、約定後の共同zkPI生成 |
| MP-SPDZ秘密照合と板持越し | 実装済み・1ホスト受入済み | 公式compilerとmalicious-shamir、1コンテナ1 party、各ノード36秘密値のPersistence、DeFMI確定後だけ親状態を更新、次回照合でMaker残量shareを再利用 | 別host 7 party、秘密板の圧縮・取消・深い板、通信量・障害評価 |
| 平文fallback禁止 | 実装済み | binary不在・party失敗時fail closed | 運用SLOとbackpressure |
| DeKYX参加資格 | 実装済み | pinned `dekyx-core` adapter test | issuer governance、失効配布、HSM |
| 法人単位の枠合算 | 実装済み | DeKYX entity単位reservation test | CCP/DeFMI外部設定、権限・更新監査 |
| 閾値zkPI | 実装済み | 金額・価格3-of-7共同range proof | 独立prover、distributed nonce管理 |
| DeFMI原子的DvP | 実装済み・統合1ホストL1受入済み | 分散MPC結果後の3-of-7鍵解放からMakerのDeKYX紐付け＋予約を確定し、TakerのDeKYX紐付け＋予約＋DvPを単一遷移で確定。5 validator root一致、replay拒否、再起動復旧 | 約定後の共同zkPI生成、独立validator、reorg試験、note方式 |
| 暗号化耐久queue | 実装済み | AEAD、idempotency、順序、cover slot test | 鍵永続化、世代整合restart、HA |
| 公開板 | 実装済み | price level aggregateのみ | 差分漏洩測定、公開頻度・粒度の市場実験 |
| React Flowデモ | 実装済み・研究用受入済み | OmenX Docker runtimeをIABの1440×1000/390×844で操作。売りGTC 100口、買いIOC 40口、残60口、参加者別残高、5/7受付、7-process MPC、閾値zkPI、DeFMI高さ3を確認。横overflow 0、console error/warn 0 | 認証済み本番APIとの接続、継続的a11y試験 |
| 分離MPCコンテナ | 実装済み・1ホスト受入済み | 一node一暗号化share、一container一party、mTLS、署名済み同一結果、再実行防止 | 別運営主体、一party一host、独立鍵生成・KMS/HSM |
| 実Avalanche L1 | 1ホスト受入済み | AvalancheGo 1.14.2、5 validator、非EVM Rust VM、RPC finality、readback、1 validator再起動復旧 | 独立host/運営者、WAN、reorg、HSM鍵 |
| 本番HTTP/API | 未実装 | demo APIのみ | mTLS、認可、OpenAPI、rate limit、audit |
| 形式安全性証明 | 未受入 | property/unit test | security definition、proof、査読 |
| 統計的性能比較 | 未受入 | rough E2E一件 | preregistered cohort、CI、throughput/latency gate |

## crate別の責務

- `oclob-core`: 注文、commitment、公開板、価格・時間優先の基準状態機械。
- `oclob-dekyx`: DeKYX匿名法人資格を注文用途へ結合するadapter。
- `oclob-ordering`: 受付番号、5-of-7 certificate、連鎖、二重投票拒否。
- `oclob-edge`: 法人端末で注文と決済鍵を分割し、各ノード向け固定長暗号文と公開manifestを作る。
- `oclob-node`: 自ノードの暗号文保管、受付順投票、MP-SPDZ実行、秘密板shareの保存、DeFMI確定後の親状態更新、結果永続化後の署名付き鍵片解放。
- `oclob-mpc`: MP-SPDZ回路生成、公式compile、7 party実行、公開output一致確認とノード別秘密状態の書出し。
- `oclob-proofs`: 受付証明、MPC出力、板の前後root、fillを一つの遷移statementへ結合。
- `oclob-settlement`: 法人枠、reservation、threshold zkPI、原子的multi-fill DeFMI DvP。
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
9. 同じinstructionの再実行を拒否する。
10. 公開板、参加法人、自社portfolio、MPC、zkPI、DeFMIを実browserで確認する。
11. 約定前には決済権限を開けず、正しいMPC結果の永続化後だけ3ノード以上の鍵片で開ける。

## P0: 本番移行を止める課題

### P0-1 注文を中央プロセスへ平文で渡さない — 分散経路で実装済み

`oclob-edge` と `oclob-node` を使う分散経路では、法人側が注文を検証可能な7分割へ変換し、ノードごとに別々に暗号化して直接送ります。調整役はcommitment（注文の要約値）、受付証明、署名付き公開結果だけを扱います。OmenX上の7コンテナ受入では、調整役へ平文注文を渡さずに40口を価格100で約定し、同一ラウンドの再送で二度目の計算を起動しないことを確認しました。

各MPCノードは、保存した注文要約値、永続状態の世代、保存状態の要約値を自分の鍵で署名します。参加法人から引き継いだ受領証は、コンテナ停止後でも7ノードの公開鍵に対して検証できます。公開要約の署名には注文ごとの使い捨て鍵を用い、法人の長期application keyは調整役へ渡しません。各ノードは受付票を返す前に同じ通番への投票を永続化し、MPC起動前には5票以上の証明本体、対象注文、前証明との連続性を自分で再検証します。

照合回路は固定8枠と到着注文について、有効状態、売買方向、価格、残量を `sint.write_to_file` で各partyのPersistenceへ書きます。各ノードは自分のファイルだけを0600で保存し、署名済み受領証にはファイルの要約値と使用した親状態の要約値だけを載せます。DeFMIの正本受領証と高さが確定した後に限り、そのファイルを次回照合の親へ進めます。OmenXの受入では、Makerの7つの秘密残量を確定後にTaker照合へ引き継ぎ、40口約定後の20口を中央で復元せず保持しました。

一方、React Flowの単体デモが使う `OclobService::submit` は、従来どおり `SecretOrder` を受けてから7入力を作ります。したがって、中央非開示の保証は分散経路だけに適用します。

残る変更:

- React Flowデモと公開APIを分散経路へ切り替え、中央経路を研究用互換モードへ限定する。
- 約定後も一つの決済プロセスへ注文全文を復元しない共同zkPI生成を追加する。

### P0-2 7 partyを独立運営する

1コンテナ1ノード、ノード別保存領域、相互TLS、ノード署名までは実装しました。ただし受入環境は同じhost・同じ管理者で、検証用の鍵も一つのlab作成器が生成します。k-of-nの暗号条件と、現実の独立性は別です。

必要な変更:

- 一party一hostとし、7運営者がそれぞれ鍵を生成する。
- 独立KMS/HSM、管理者、監査log、障害領域。
- mTLS、固定peer identity、epoch設定。
- WAN latency、packet loss、partial outage、selective abort試験。
- party omissionとequivocationを公開情報だけで追跡するreceipt。

### P0-3 分散MPCから実DeFMI/Avalancheまで一つに接続する — 1ホスト統合受入済み

5検証者の実AvalancheGo上へRust DeFMI VMを載せ、法人側分割、7ノードMP-SPDZ照合、DeKYX検証、Maker事前予約、Taker予約＋DvP、root/height/readback、二重送信拒否、1検証者再起動後のroot復旧までを同じ実行で確認しました。EVMは使っていません。MPCで使う売買方向・指値・数量・注文種別・期限・板残留可否の6項目は、Pedersen VSSの定数項と決済権限内の値の一致を検査します。

現在、注文ごとの決済暗号鍵は3-of-7でMPCノードへ分散されます。各ノードは、その注文が約定した、またはGTCとして板へ正式掲載されるというMPC結果を自分の永続領域へ記録した後だけ、決済専用の相互TLS接続へ署名付き鍵片を返します。二片、結果前、未約定IOC、別権限、別round、別outputでは開きません。統合受入では、各注文について7件の有効な鍵片を検証し、三片以上で注文別鍵を復元しました。

必要な変更:

- 約定後に一つの決済プロセスが注文別鍵と注文全文を復元する段階を、MPC内の共同zkPI生成へ移す。
- 独立host/運営者のvalidator、WAN、timeout、reorg相当を試験する。
- zkPI verifier、asset schema、participant moduleをgenesis/configから固定する。
- 正本を匿名commitment口座から、口座を持たないnote方式へ移す。
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
