# OCLOB実装状況と受入条件

## 判定

OCLOBは、研究用MVPとして一続きの経路を実装しています。本番移行可能と判定できる段階ではありません。特に、注文のedge sharing、独立した7 MPC運営者、実Avalanche L1、永続状態の世代整合、認証・鍵管理がP0です。

「実装済み」はsourceがあるだけではなく、repositoryのremote release gateで動かす対象になっていることを示します。「未受入」は設計や一部codeがあっても、本番の信頼境界または実環境で確認できていないことを示します。

## 機能別状況

| 領域 | 状況 | 現在の証拠 | 本番受入に残るもの |
|---|---|---|---|
| 秘密注文wire | 実装済み | 厳格encode/decode、commitment、署名test | schema version交渉、外部client互換試験 |
| GTC / IOC | 実装済み | coreとservice test | 長時間運転、restart recovery |
| 価格・時間優先 | 実装済み | clear referenceとMPC outputの一致test | WAN並行投入、fairness定義の形式化 |
| 部分・複数約定 | 実装済み | 最大8枠batch回路、原子的multi-fill | 8枠上限の拡張または分割規則 |
| 取消・期限切れ | 実装済み | authority、遷移proof、予約解放test | 公開API、外部clock/epoch運用 |
| 受付順5-of-7 | 実装済み | quorum、連鎖、二重投票拒否test | HSM key、epoch交代、独立node/WAN |
| MP-SPDZ秘密照合 | 実装済み | 公式compilerとmalicious-shamir 7 process E2E | edge sharing、別host 7 party、traffic評価 |
| 平文fallback禁止 | 実装済み | binary不在・party失敗時fail closed | 運用SLOとbackpressure |
| DeKYX参加資格 | 実装済み | pinned `dekyx-core` adapter test | issuer governance、失効配布、HSM |
| 法人単位の枠合算 | 実装済み | DeKYX entity単位reservation test | CCP/DeFMI外部設定、権限・更新監査 |
| 閾値zkPI | 実装済み | 金額・価格3-of-7共同range proof | 独立prover、distributed nonce管理 |
| DeFMI原子的DvP | 実装済み | in-process canonical state machine、readback、replay拒否 | 実Avalanche L1とfinality/reorg試験 |
| 暗号化耐久queue | 実装済み | AEAD、idempotency、順序、cover slot test | 鍵永続化、世代整合restart、HA |
| 公開板 | 実装済み | price level aggregateのみ | 差分漏洩測定、公開頻度・粒度の市場実験 |
| React Flowデモ | 実装済み・研究用受入済み | OmenX Docker runtimeをIABの1440×1000/390×844で操作。売りGTC 100口、買いIOC 40口、残60口、参加者別残高、5/7受付、7-process MPC、閾値zkPI、DeFMI高さ3を確認。横overflow 0、console error/warn 0 | 認証済み本番APIとの接続、継続的a11y試験 |
| 独立MPCコンテナ | 未受入 | 設計文書のみ | 一node一share、一party一host、mTLS |
| 実Avalanche L1 | 未受入 | DeFMI state machineのみ | validator deployment、RPC、finality証拠 |
| 本番HTTP/API | 未実装 | demo APIのみ | mTLS、認可、OpenAPI、rate limit、audit |
| 形式安全性証明 | 未受入 | property/unit test | security definition、proof、査読 |
| 統計的性能比較 | 未受入 | rough E2E一件 | preregistered cohort、CI、throughput/latency gate |

## crate別の責務

- `oclob-core`: 注文、commitment、公開板、価格・時間優先の基準状態機械。
- `oclob-dekyx`: DeKYX匿名法人資格を注文用途へ結合するadapter。
- `oclob-ordering`: 受付番号、5-of-7 certificate、連鎖、二重投票拒否。
- `oclob-mpc`: MP-SPDZ回路生成、公式compile、7 party実行、output一致確認。
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

## P0: 本番移行を止める課題

### P0-1 注文を中央プロセスへ平文で渡さない

現在の `OclobService::submit` は `SecretOrder` を受け、`MpcRunner` がその値から7 party用inputを作ります。これはMPC計算自体は実行していても、調整サービスが注文を読めることを意味します。

必要な変更:

- 法人参加モジュールで秘密分散する。
- 7 nodeへ各shareを直接mTLS送信する。
- nodeは自分のshare以外を受け取らない。
- commitment、署名、DeKYX資格、shareが同じ注文を指すことを証明する。
- coordinatorはcommitment、受付証明、party receipt、公開outputだけを扱う。

### P0-2 7 partyを独立運営する

現在は同じhost、同じprocess owner、同じfilesystemで7 MP-SPDZ processを起動します。k-of-nの暗号条件と、現実の独立性は別です。

必要な変更:

- 一party一containerまたは一host。
- 独立KMS/HSM、管理者、監査log、障害領域。
- mTLS、固定peer identity、epoch設定。
- WAN latency、packet loss、partial outage、selective abort試験。
- party omissionとequivocationを公開情報だけで追跡するreceipt。

### P0-3 実DeFMI/Avalancheへ接続する

現在のDeFMIは正本状態機械、原子性、root、height、readbackを実行しますが、実validator consensusではありません。

必要な変更:

- Rust VM/moduleをAvalanche L1へ組み込む。
- 5 validator以上で起動する。
- zkPI verifier、asset schema、participant moduleをgenesis/configから固定する。
- submit、finality待ち、readback、timeout、reorg相当、二重送信を試験する。
- consensus receiptとOCLOBの確定表示を結合する。

### P0-4 永続状態と鍵を同じ世代で復旧する

現在のdemoはqueue fileを永続化できますが、participant wallet、committee key、DeFMI state、nonceを起動時生成します。queueだけ残したrestartは安全に受入できません。

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
