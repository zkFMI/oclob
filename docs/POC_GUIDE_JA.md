# 企業向けOCLOB PoC導入手順

この文書は、企業の技術・市場・決済・リスク管理担当者が、OCLOBの研究用MVPを自社環境で再現し、次の判断に必要な証拠を集めるための手順です。

- 注文内容を公開前に読ませず、価格・時間優先で連続照合できるか。
- 約定後の再署名なしに、事前承認の範囲内だけ決済できるか。
- 同じ法人から複数注文が同時に来ても、資金・在庫・保証枠を合算して超過を止められるか。
- MPCが止まったとき、平文照合へ切り替えず、暗号化キューから順番を保って再開できるか。
- 公開板、参加法人の自社画面、市場運営画面で、見えてよい情報だけが見えるか。

現在の配布物は研究用MVPです。実資産を扱う本番システムではありません。統合受入経路では、法人側が注文を7分割して7つのMPCコンテナへ別々に暗号化して直接送ります。約定後は各ノードの秘密共有だけから共同zkPI/DvP証明を作り、価格・数量・予約額を証明担当へ復元せず、同じ共同zkPI、一回限りの番号、DvP packageの要約を5検証者のAvalanche DeFMI正本命令へ直接固定します。ただし、受入済み構成は一台のLinuxホスト上であり、7つの独立運営者を証明するものではありません。また到着注文の事前予約を認可するため、照合結果を保存した後に注文別の決済権限を開く処理は残っています。共同証明全文は現在、Avalanche VMではなくVM投入前のOCLOB決済アプリが検証し、実験用DeFMI承認鍵も同じプロセスにあります。ブラウザ用の単体デモも、調整サービスが注文を一時的にメモリへ持つ従来経路です。

## 1. PoCの範囲を先に固定する

最初のPoCでは、次の一市場だけに限定してください。

| 項目 | 標準値 | 意味 |
|---|---:|---|
| 市場 | `JGB10Y-JPY` | 円資金と10年国債相当数量のDvP例 |
| 価格単位 | 整数tick | 小数丸めを市場規則へ持ち込まない |
| 数量単位 | 整数lot | 約定・予約・決済を同じ単位で照合する |
| 注文 | GTC / IOC | 板に残す注文と即時取消注文を比較する |
| 一回の照合上限 | 8 resting orders | 固定MPC回路の上限。超過は受付前に拒否する |
| 受付順 | 7台中5台 | 最大2台の不正または相違を想定する |
| 秘密照合 | 7 party / corruption threshold 2 | MP-SPDZ malicious Shamir |
| 決済鍵の解放 | 3-of-7 | 注文別鍵。MPC結果を永続化したノードだけが決済roleへ鍵片を返す |
| zkPI/DvP共同証明 | 7 party、3-of-7署名 | 金額・価格範囲、数量×価格、決済後残高を秘密共有から証明する |
| DeFMI決済 | 原子的DvP | 資金legと証券legを同時に成功または失敗させる |

この標準値を変える場合は、注文wire、MPC回路、閾値、DeFMIマニフェスト、性能測定を一緒に再受入してください。UIだけの変更で市場規則を変えてはいけません。

## 2. 役割

PoC責任者は、最低でも次の担当を分けます。同じ人が兼務しても構いませんが、受入記録では役割を明記します。

1. **市場規則担当**: tick、lot、価格・時間優先、GTC/IOC、取消、期限、公開板の粒度を承認する。
2. **参加法人担当**: 注文署名鍵、DeKYX資格、暗号化送信キュー、資金・在庫の自社表示を確認する。
3. **MPC担当**: MP-SPDZの固定commit、7 party設定、ログ、停止時の扱いを確認する。
4. **決済担当**: zkPIの事前承認範囲、予約、DeFMIの前後root、再実行拒否を確認する。
5. **セキュリティ担当**: 秘密値が画面、HTTP応答、ログ、artifact、クラッシュダンプへ出ないことを確認する。
6. **監査担当**: ソースcommit、コンテナdigest、テスト結果、E2E受領証を保存する。

## 3. 必要な機材

### 3.1 現在の一台構成を再現する場合

検証用Linuxホスト一台に、次を推奨します。これは保証性能ではなく、依存コンパイルと7 partyの同時実行に余裕を持たせるためのPoC目安です。

- x86_64 Linux。Debian 12相当。
- 物理または仮想CPU 16 core以上。
- RAM 32 GiB以上。C++最適化コンパイル時のピークに余裕を持たせる。
- 空きSSD 80 GiB以上。MP-SPDZ、Docker layer、Rust target、npm cacheを含む。
- Docker EngineとBuildKit。
- GitHub、crates.io、npm、Debian mirrorへ出られるHTTPS経路。
- 初回イメージ作成中にMac側の作業を圧迫しないよう、ビルドはOmenXまたはSoftBankで行う。

### 3.2 独立運営者PoCへ進む場合

現在の標準ランナーだけでは、この構成の安全性を受入できません。次の機材は移行設計の目安です。

- MPC運営者ごとに別の管理境界を持つLinuxノード7台。
- DeFMI検証者を別の管理境界で5台。
- 法人参加モジュールを参加法人ごとに1台以上。署名鍵はKMS/HSMを推奨。
- 監視、時刻同期、証明保管、バックアップを実行系と分離。
- 全ノード間の遅延、packet loss、帯域を測定し、同一リージョン値をWAN値として流用しない。

同じクラウドアカウント、同じ管理者、同じKMS配下で7コンテナを動かしても、7つの独立運営者を置いたことにはなりません。

## 4. ソースと依存の固定

```bash
git clone https://github.com/zkFMI/oclob.git
cd oclob
git rev-parse HEAD
```

監査記録には、少なくとも次を残します。

- OCLOBのcommit SHA。
- `Cargo.lock` のSHA-256。
- `docker/Dockerfile` のSHA-256。
- DeKYXの固定commit。
- QOMM/zkPI/DeFMI SDKの固定commit。
- MP-SPDZの固定commit。
- 生成したDocker imageのdigest。

Dockerfileは、公式MP-SPDZの `compile.py` を含む上流ツリーを固定commitから構築します。OCLOBがPythonで実装されているわけではありません。プロジェクト所有の実装、実験、サーバ、状態機械はRustです。`compile.py` はMP-SPDZ公式回路コンパイラとしてだけ使います。

## 5. OmenXまたはSoftBankでの一括受入

Macではコンパイルやテストを実行しません。次のゲートは、ソースをリモート一時領域へ転送し、終了時にその領域を削除します。

初回:

```bash
make release-gate \
  REMOTE_TEST_HOST=omenx_ubuntu_zerotier \
  REMOTE_TEST_REUSE_IMAGE=0
```

固定イメージを再利用する二回目以降:

```bash
make release-gate \
  REMOTE_TEST_HOST=omenx_ubuntu_zerotier \
  REMOTE_TEST_REUSE_IMAGE=1
```

SoftBankを使う場合:

```bash
make release-gate \
  REMOTE_TEST_HOST=softbank-l40s \
  REMOTE_TEST_REUSE_IMAGE=0
```

ゲートが確認する内容は独立しています。

1. `cargo fmt --check`: 形式差分がない。
2. `cargo clippy -- -D warnings`: 全Rust targetに警告がない。
3. `cargo test --workspace --release`: crate単体、結合、拒否経路が通る。
4. `npm ci`: lockfileどおりのReact依存を復元する。
5. `tsc --noEmit`: React Flow画面の型検査が通る。
6. `vite build`: サーバへ埋め込むbundleを生成する。
7. `oclob-demo`: DeKYX、受付順、実MP-SPDZ、遷移証明、zkPI、DeFMI、readback、再実行拒否を一続きで実行する。

成功しても、その一回だけで性能や安全性を保証しません。生成された `artifacts/oclob_rough_e2e.json` はsmoke evidenceです。

### 5.1 市場運営者へ注文を渡さない分散経路

```bash
make remote-distributed-e2e \
  REMOTE_TEST_HOST=omenx_ubuntu_zerotier
```

このゲートは次を実際に行います。

1. MakerとTakerを別プロセスとして起動する。
2. 各参加者が注文を7分割し、ノードごとに別々に暗号化する。
3. 相互TLSで各ノードへ一つずつ届け、各ノードの署名付き保存受領証を集める。
4. 7つのノードコンテナが、自分の分割値だけを使ってMP-SPDZを起動する。
5. 7つの署名付き結果が同じプログラム、同じ約定、同じ公開出力を指すことを確認する。
6. 同じラウンドを再送しても、保存済みの同じ受領書が返り、計算を二度行わないことを確認する。

結果は `artifacts/oclob_distributed_e2e.json` に保存されます。`operator_hosts` が `1`、`independent_operators_claimed` が `false` であることを必ず確認してください。このゲートだけを根拠に「7社で独立運用済み」「WAN検証済み」「Avalanche決済済み」と記載してはいけません。

### 5.2 非EVM DeFMI Avalanche L1経路

```bash
make remote-avalanche-e2e \
  REMOTE_TEST_HOST=omenx_ubuntu_zerotier
```

このゲートは、1台のLinuxホスト上で5つのAvalancheGo validatorとRust DeFMI VMを起動し、次を確認します。

1. Maker最大在庫の閾値zkPI予約を確定してから注文を板へ載せる。
2. Taker最大資金の予約、約定、未使用予約の解放、資金・証券DvPを一つの正本遷移にする。
3. 5 validatorのstate rootが一致する。
4. 同じ遷移の再送を拒否する。
5. validator 1台を再起動し、確定rootまで復旧する。

結果は `artifacts/oclob_avalanche_acceptance.json` に保存されます。`environment` と `non_claims` を必ず併記してください。これは従来の照合サービスとの互換経路を単独で確認する補助ゲートです。

### 5.3 法人側分割からAvalanche決済までの統合経路

```bash
make remote-integrated-e2e \
  REMOTE_TEST_HOST=omenx_ubuntu_zerotier
```

このゲートは、5.1と5.2を同じ注文要約値で接続します。

1. MakerとTakerが別プロセスで注文分割、注文別の決済鍵7片、固定長の決済権限暗号文を作る。
2. 7 MPCノードが保存受領証へ署名し、二つの照合ラウンドを実行する。
3. 各ノードが同じroundの結果を永続化した後、決済専用の相互TLS接続へ署名付き鍵片を返す。
4. 決済担当が三片以上を検証して注文別鍵を復元し、DeKYX提示とMPCへ分割した6項目との一致を検証する。
5. Makerの法人紐付けと最大在庫予約を一つのDeFMI遷移で確定してからTakerの照合へ進む。
6. Takerの法人紐付け、予約、40口・価格100のDvPを一つの正本遷移で確定する。
7. 同一遷移の再送拒否、5検証者のroot一致、1検証者再起動後の復旧を確認する。

結果は `artifacts/oclob_distributed_avalanche_acceptance.json` に保存されます。これは中央調整役に平文注文を渡さず、約定前の単一復号鍵も置かない一続きの機能証拠です。ただし、`non_claims` にあるとおり、1ホスト、照合後に一つの決済プロセスへ復元する構成、研究用鍵という制限があります。

### 5.4 旧ノード状態から更新するとき

注文別3-of-7決済鍵を含む現在の通信・保存形式はversion 2です。旧versionで受け付けた注文には決済鍵片がないため、保存file自体は読み込めても、現在の決済経路では開けません。更新前に旧注文を失効または取消しし、全7ノードが同じ最終受付番号まで到達したことを確認してください。更新後は、参加法人から注文を再送して7件の新しい保存受領証を取得します。旧注文と新注文を同じ板で混在させたまま切り替えてはいけません。

## 6. デモサーバの起動

イメージをLinux側で作ります。

```bash
docker build \
  --file docker/Dockerfile \
  --target oclob-server \
  --tag oclob-server:local \
  .
```

キュー暗号化用の秘密は、シェル履歴へ直接書かず、Docker secret、KMSで復号した一時file、または運用基盤のsecret injectionから渡してください。以下は環境変数名だけを示す例です。

```bash
docker volume create oclob-state
docker run --rm --name oclob \
  --publish 18800:18800 \
  --env OCLOB_QUEUE_PASSPHRASE \
  --volume oclob-state:/var/lib/oclob \
  oclob-server:local
```

現在のHTTPサーバには本番認証、TLS終端、rate limit、WAF連携がありません。PoCでも `127.0.0.1` または閉域のreverse proxy内だけで公開してください。インターネットへ直接公開しないでください。

## 7. 画面で行う標準シナリオ

### 7.1 正常な部分約定

1. 売り手画面を選ぶ。
2. 売り100口、価格100、GTCを送る。
3. 公開板に「売り 100 / 合計100」が見え、運営者画面に注文者が出ないことを確認する。
4. 買い手画面を選ぶ。
5. 買い40口、価格101、IOCを送る。
6. 受付番号が前後せず、約定価格100、数量40となることを確認する。
7. 売り板の合計が60へ減ることを確認する。
8. 買い手の資金と売り手の証券が同じDeFMI高さで更新されたことを確認する。
9. 「約定後の利用者署名」が0であることを確認する。

### 7.2 MPC停止と再開

1. MPCノードを一台停止表示にする。
2. 注文を送る。
3. 画面が平文照合へ切り替わらず、「MPC復旧待ち」になることを確認する。
4. 自社の暗号化キュー件数が増え、運営者画面に指値・数量が出ないことを確認する。
5. ノードを再開し、キュー処理を実行する。
6. 最初に受け付けた要求から処理されることを確認する。

画面のノード停止操作は障害制御のデモです。実際に別コンテナを停止しているわけではありません。独立ノード障害試験の代用にしないでください。

### 7.3 DeFMI検証者不足

1. DeFMI検証者を3台未満のonline状態にする。
2. 注文を送る。
3. 正本更新が開始されず、注文が再試行可能な状態に残ることを確認する。
4. 検証者を戻し、同じ要求IDを処理する。
5. 決済が一度だけ行われることを正本高さと受領証で確認する。

### 7.4 法人合算枠の超過

1. 同じ法人から、資金または在庫の全量に近いGTC注文を送る。
2. その注文が未約定のまま予約を保持している状態で、同じ法人から追加注文を送る。
3. 二件目が「法人全体の資金・在庫・保証枠を超える」として拒否されることを確認する。
4. 現MVPでは同じDeKYX法人識別子を別の決済handleへ結び直す要求が拒否され、同一枠を二重に作れないことを確認する。複数ウォレットを同じ法人枠へ安全に束ねるroutingは未実装である。
5. 取消または期限切れ後、予約が解放されてから再注文できることを確認する。

### 7.5 IOC、取消、期限切れ、再送

- IOCが約定しない場合、板へ残らず予約が解放される。
- GTC取消は、対象注文の事前権限を検証し、取消遷移と予約解放を同時に行う。
- 期限切れは、受付順証明を伴う市場遷移として処理される。
- 同じ注文commitment、要求digest、zkPI nullifierを再送しても、板・残高・正本高さが二重に進まない。

IOCと再送は現在の画面/APIから確認できます。取消と期限切れの状態遷移はRust APIとrelease testの対象ですが、研究デモHTTPにはまだ操作endpointがありません。

## 8. APIで行う場合

デモAPIの完全な形は [API.md](API.md) を参照してください。最低限のreadiness確認:

```bash
curl --fail http://127.0.0.1:18800/health
curl --fail 'http://127.0.0.1:18800/api/state?viewer=operator'
```

注文例:

```bash
curl --fail-with-body \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{"actor":"maker","side":"sell","price":100,"quantity":100,"time_in_force":"good_til_cancelled"}' \
  http://127.0.0.1:18800/api/order
```

これはデモ用APIです。法人署名鍵やDeKYX credentialをHTTP bodyで受ける本番APIではありません。デモサーバ内の参加者が注文を作り、署名し、提示を生成します。

## 9. 受入時に保存する証拠

各runについて、次を一組で保存します。

- 実行日時、担当者、ホスト、OCLOB commit、依存commit。
- Docker image digestと `docker inspect` の設定要約。
- release gateのexit codeと完全log。
- `artifacts/oclob_rough_e2e.json`。
- デスクトップ幅と狭い幅の画面capture。
- 正常、MPC停止、DeFMI不足、枠超過、IOC、再送の観測結果。
- DeFMIの前後root、高さ、canonical receipt digest。
- 注文別の決済鍵閾値、各注文の有効な解放数、解放したノード番号。鍵片そのものは保存しない。
- 想定値と観測値の差、および未解決事項。

秘密の注文wire、署名秘密鍵、credential opening、キュー暗号鍵、個人口座識別子は証拠へ含めません。

## 10. ログと監視

PoCでも、次を別の指標として扱います。

- 受付件数、拒否件数、期限切れ件数。
- 受付証明を作れなかった回数。
- MPC実行時間、compile時間、party不一致、timeout。
- キュー深さ、最古要求年齢、再試行回数。
- DeFMI拒否、canonical readback不一致、replay拒否。
- 予約総額、利用可能枠、枠超過拒否。ただし法人の秘密残高を公開監視へ出さない。

現在のデモは構造化された監視export、OpenTelemetry、監査ログ署名を未実装です。本番移行前に必要です。

## 11. 障害復旧上の注意

暗号化キューfileは永続化できますが、現在のデモは起動時に参加者wallet、委員会鍵、DeFMI状態を再生成します。そのため、古いキューだけを新しいプロセスへ持ち越すrestart recoveryは受入済みではありません。PoC中にプロセスを再起動する場合は、state volumeのbackupを取ったうえで、キューと鍵・credential・正本snapshotが同じ世代であることを確認してください。

本番候補では次を一つの復旧単位にします。

1. 法人署名鍵とDeKYX walletのversion。
2. 暗号化キューとその鍵version。
3. 受付順委員会のepochと公開鍵集合。
4. MPCプログラムhashとshare epoch。
5. DeFMI canonical height、root、zkPI nullifier集合。

## 12. 本番移行の停止条件

次のいずれかが残る間は、実資産を扱う本番へ進めません。

- 調整サービスが秘密分散前の注文を読める。
- 7 MPC partyが独立した障害・管理境界で動いていない。
- shareと注文commitmentの結合を検証できない。
- ordering key、participant key、DeFMI keyがデモ固定値またはプロセスメモリだけにある。
- restart後にキュー、予約、板、nullifier、正本を一貫して復旧できない。
- TLS、相互認証、認可、rate limit、監査ログ、鍵交代がない。
- 分散MPCから実Avalanche L1までの1ホスト統合経路と注文別3-of-7鍵解放は受入済みだが、照合後の単一決済プロセス、独立validator、WAN、再編を解消していない。
- 代表的負荷でlatency、throughput、失敗率を統計的に確認していない。
- 通信量・時刻・板差分を含む漏洩評価を終えていない。
- 第三者暗号レビュー、運用レビュー、法務・市場規則レビューが未完了である。

現在の達成状況は [STATUS.md](STATUS.md) に整理しています。
