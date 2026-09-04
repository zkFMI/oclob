# OCLOBデモAPI

## 1. 位置づけ

このAPIは、OCLOBの研究用MVPを画面と自動試験から操作するための最小HTTP境界です。本番の法人接続APIではありません。現在はTLS、利用者認証、テナント認可、rate limit、schema version negotiationを持ちません。閉じたPoC環境以外へ直接公開しないでください。

すべての応答は `Cache-Control: no-store` を含みます。JSON応答の共通形は次です。

成功:

```json
{
  "ok": true,
  "data": {}
}
```

業務上の拒否または入力不正:

```json
{
  "ok": false,
  "error": "理由"
}
```

現在のデモ実装は、業務拒否をHTTP `400 Bad Request`で返します。運用APIでは、schema error、認証失敗、競合、枠不足、一時停止、内部障害を別のstatus/codeへ分ける必要があります。

## 2. `GET /health`

プロセスがHTTP要求を受けられることだけを確認します。MPC、DeFMI、queueのreadinessを保証しません。

```json
{
  "status": "ok"
}
```

## 3. `GET /api/state?viewer=...`

### 3.1 viewer

- `operator`: 市場運営者向け。参加法人の自社注文、資金、在庫、キューは返さない。
- `maker`: デモの売り手企業向け。自社の注文とportfolioだけを返す。
- `taker`: デモの買い手企業向け。自社の注文とportfolioだけを返す。

現在のviewerは認証された主体ではなくquery parameterです。これは投影内容を確認するデモであり、アクセス制御ではありません。

### 3.2 主な応答項目

| field | 公開範囲 | 意味 |
|---|---|---|
| `market` | 全viewer | 市場ID |
| `phase` | 全viewer | `ready`, `queued`, `waiting_for_mpc`, `settled`などのデモ状態 |
| `privacy` | 全viewer | 現MVPの表示境界、平文受信点、実行形態を明記した状態 |
| `book` | 全viewer | 価格帯ごとの合計数量。個別注文者は含めない |
| `own` | maker/takerだけ | 自社portfolio、自社注文、暗号化queue指標 |
| `mpc_nodes` | 全viewer | 障害待機を再現する7個の模擬health flag。実processを停止しない |
| `defmi_validators` | 全viewer | 正本更新のquorum不足を再現する5個の模擬health flag。実validatorではない |
| `defmi` | 全viewer | canonical heightと三つのroot |
| `last_execution` | 全viewer | 最新の受付・MPC・proof・settlement要約 |
| `events` | 全viewer | 秘密値を含まない画面用event |

`own.portfolio`:

```json
{
  "securities": 10000,
  "cash": 100000000,
  "reserved_securities": 100,
  "reserved_cash": 0,
  "available_securities": 9900,
  "available_cash": 100000000
}
```

`book.levels`は、実際の型が返す価格帯配列です。値の意味は `(side, price, aggregate_quantity)` で、注文件数は公開しません。

`privacy`は、画面で隠すことと計算基盤から隠すことを区別します。現在値は次の意味です。

- `operator_projection_contains_pending_order=false`: operator向けJSONに未処理注文を含めない。
- `participant_projection_contains_only_own_orders=true`: maker/taker向けJSONの注文は自社分だけ。
- `coordinator_receives_plain_order_before_secret_sharing=true`: 現MVPのHTTP serverとserviceは、秘密分散を作る前に平文の注文objectを受け取る。
- `mpc_topology=seven_processes_on_one_host`: 7社独立運営ではなく、同一host上の7 MP-SPDZ process。
- `defmi_topology=in_process_state_machine`: Avalanche validator consensusではなく、RustのDeFMI正本状態機械を同一process内で実行する。

## 4. `POST /api/order`

デモ参加者として注文を作り、署名し、DeKYX提示を生成し、暗号化queueを通してOCLOBへ送ります。

### 4.1 request

```json
{
  "actor": "maker",
  "side": "sell",
  "price": 100,
  "quantity": 100,
  "time_in_force": "good_til_cancelled"
}
```

制約:

- `actor`: `maker` または `taker`。
- `side`: `buy` または `sell`。
- `price`: 1以上の64-bit unsigned integer。市場のtick単位。
- `quantity`: 1以上の64-bit unsigned integer。市場のlot単位。
- `time_in_force`: `good_til_cancelled` または `immediate_or_cancel`。
- 未知fieldは拒否する。

### 4.2 response

`data.queued`は、秘密注文の公開可能な受付情報です。

```json
{
  "request_id": "hex commitment",
  "request_digest": [0, 1],
  "sequence": 1,
  "expires_at": 1234567890,
  "already_present": false
}
```

`data.worker`は、同じ呼出しでqueue workerが観測した結果です。

- `idle`
- `waiting_for_mpc`
- `dummy_cover`
- `expired`
- `executed`
- `retryable_failure`
- `rejected`

`executed`はHTTP用に絞った次の情報だけを返します。

- 要求IDと受付番号。
- 公開可能になった約定価格・数量と未約定数量。
- 受付署名数、MPC参加数、閾値zkPIの有無、約定後の追加署名数。
- DeFMI正本の受領証要約値と高さ。

内部の研究受領証全体は返しません。そこにはDeKYXの法人単位無効化値や予約記録が含まれるためです。`QueueWorkerResult`自体にもJSON直列化を実装せず、HTTP層が誤って内部受領証を丸ごと公開できないようにしています。

## 5. `POST /api/nodes/toggle`

画面上の障害シナリオ用flagを切り替えます。実コンテナ、実MP-SPDZ party、実Avalanche validatorを停止するAPIではありません。

MPC例:

```json
{
  "group": "mpc",
  "index": 0
}
```

DeFMI例:

```json
{
  "group": "defmi",
  "index": 4
}
```

- `mpc` index: 0から6。
- `defmi` index: 0から4。
- 呼出すたびonline/offlineを反転する。

本番管理APIとして使ってはいけません。認証なしにnode状態を変えられるためです。

## 6. `POST /api/queue/pump`

指定したデモ法人の暗号化queueから、最古の処理可能要求を一つ進めます。

```json
{
  "actor": "maker"
}
```

MPC healthが不足していれば、平文処理へ切り替えず `waiting_for_mpc` を返します。再試行可能な下流失敗はqueueへ残ります。同じ要求IDの重複送信は、queue digestとDeFMI nullifierで二重処理を拒否します。

## 7. 秘密情報の境界

次をoperator向けstateへ追加してはいけません。

- pending orderのside、price、quantity。
- participant handleとDeKYX subject nullifierの対応。
- credential、opening、署名秘密鍵。
- reservation openingまたは秘密口座参照。
- 暗号化queueの復号本文。
- MPC party input。

公開してよいのは、市場規則で合意した価格帯合計、受付commitment、quorum数、MPC program hash、proof要約、約定結果、DeFMI canonical root/height/receiptです。ただし、公開板差分と時刻だけでも推測が生じるため、「公開可能」と「情報漏洩がゼロ」は同じではありません。

## 8. 本番APIへ移行するときの必須変更

1. 法人ごとのmTLSと署名付きrequest envelope。
2. schema version、request id、idempotency key、有効期限を必須化。
3. 注文平文を中央APIへ送らず、法人端末でshare化して7 nodeへ直接送る。
4. commitmentと各shareの結合証明、全nodeのreceiptを導入する。
5. 認証主体からviewerを決め、query parameterで権限を切り替えない。
6. 業務error code、retryability、監査ID、canonical receipt参照を固定する。
7. body/header上限、timeout、rate limit、backpressureを定義する。
8. TLS終端後も秘密payloadをaccess log、APM、traceへ記録しない。
9. OpenAPIまたは同等schemaを生成し、後方互換性試験を置く。
10. node toggleのようなデモ管理機能をproduction binaryから除外する。
