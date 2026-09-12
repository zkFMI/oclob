# native台帳に接続したブラウザと暫定方式

## 対象

HTTPブラウザの共同証明・暫定方式は、どちらも5台のDeFMI native検証ノードへ送る。HTTP注文からin-processのローカル決済へ進む経路を削除し、native受理とreadbackを確認するcallbackを必須にした。サービスライブラリの独立実験用APIは残るが、HTTP障害時のfallbackには使わない。

以下は2026-09-12の統合作業ツリーによる観測。既存の未公開UI改修を含むため、文書のcommitとデモバイナリの配備versionを同一視しない。合成資金と合成証券を用いた隔離ネットワークのsmoke観測であり、本番の金融取引ではない。

## 起動と停止

Rustビルド・テスト・native実行には、このリポジトリの `make remote-test` を使う。Softbank L40S向けに `REMOTE_TEST_HOST=softbank-l40s`、必要なら `REMOTE_TEST_SSH_OPTIONS='-o BatchMode=yes -J omenx_ubuntu_zerotier'` を指定する。ローカルコンパイルは行わない。

scripts/native-browser.sh（統合作業ツリーの ../scripts/native-browser.sh） は5台のnativeネットワークとHTTPサーバーを起動する。先に同じ依存versionで `oclob-server` と `oclob-avalanche-vm` をrelease buildし、runner、AvalancheGo、適合するMP-SPDZとhybrid TLS依存を備えたremote imageで実行する。

remoteコマンド内で研究専用の `OCLOB_QUEUE_PASSPHRASE` を秘密として読み込み、`scripts/native-browser.sh /absolute/path/to/a-new-session` を起動する。passphraseをログやcommitへ入れない。既存のstate directoryは再利用せず保持する。

| 環境変数 | 既定値・役割 |
|---|---|
| `OCLOB_SERVER_BIN` | `/var/cache/oclob/target/release/oclob-server` |
| `OCLOB_VM_BIN` | `/var/cache/oclob/target/release/oclob-avalanche-vm` |
| `MP_SPDZ_ROOT` | 適合する実エンジンのcheckout。実行では `/opt/MP-SPDZ` |
| `OCLOB_HTTP_PORT` | `18814`、loopbackのみ |
| `OCLOB_RUNNER_PORT` / `OCLOB_RUNNER_GATEWAY_PORT` | `18818` / `18819`。既存runnerと競合しない値 |
| `AVALANCHE_NETWORK_RUNNER` / `AVALANCHEGO_BIN` | `/usr/local/bin/` 配下の対応バイナリ |

スクリプトは研究用policy・鍵・合成資金を明示的に有効化する。VM plugin wrapperにも検証者設定を渡す。終了時は自身が起動したrunnerとserverだけを停止する。`make remote-test` の一時checkoutは終了時に消えるため、必要なnative状態・証跡は終了前に専用の保存先へ退避する。稼働中の既存ネットワークを停止する手順ではない。

## 注文から受渡しまで

1. 企業の画面で売買、価格、数量、GTC/IOCを入力する。現在の研究用HTTPサーバーは平文要求を受けてから暗号化する。
2. 暗号化outboxに保存し、5署名の受付順を確定する。
3. 7プロセスのMP-SPDZで注文を照合し、候補の板・資金・証券状態を計算する。この段階では公開板や確定残高へcommitしない。
4. 共同証明では既存の証明付きnative account settlementを送る。暫定方式では署名付きclaimをnativeへ提案し、期限・challenge・応答を追う。
5. 暫定方式でも金融証明は保持する。Finalized後にnative account settlementを送り、5台のroot、受理statement、口座commitment、sequenceを照合する。
6. canonical acceptanceが確認できて初めて、ローカルの板と残高をcommitし、注文を処理完了と表示する。

注文者だけに暫定約定の価格と数量を送る。運営者向けJSONにはその暫定明細を追加しない。方式変更中は注文送信を無効化し、未処理要求がある間は方式変更を拒否する。

## challengeが証明するもの

QOMMのquote計算証明とOCLOBの照合結果に対するattestationは同じ証明ではない。OCLOBの今回のchallenge応答は、元のmarket transitionに対する登録委員会の5-of-7 attestationを検証する。この署名の閾値を数学的なMPC計算証明と呼ばない。金融側のzkPI証明、注文との束縛、native finalityは別途残る。

Pending中だけchallengeを送れる。正しい応答はProvenとなるが元の期限までは未決済。期限切れの未応答や検証に通る矛盾応答はRejected。不正な証明bytesは検証エラーであり、即時の決済やslashとは異なる。

## 不確実な結果と再起動

native呼出しが失敗して結果が不明な場合は、通常の再試行可能エラーや未確保の取消しに置き換えない。outboxを手動照合待ちへ移し、新しい送信とqueue pumpを停止する。台帳を先に照合する必要がある。

このHTTPサーバーの秘密板はまだ永続復旧に対応していない。起動時に `native-browser-session` を排他的に作り、同じstate directoryでの再起動を拒否する。空のローカル板を既存台帳に接続して残高を再初期化することを防ぐためであり、復旧機能が実装済みという意味ではない。

## ブラウザとnative台帳で観測した結果

新しいlauncherを使ったr4実行では、売り100口・100円・GTCを置いた後、買いを指値101円・IOCで送信した。各約定価格は100円。

| 操作 | 買い手の資金 | 買い手の在庫 | native height |
|---|---|---|---|
| 初期状態 | 100,000,000 | 10,000 | — |
| 共同証明で20口 | 99,998,000 | 10,020 | 16 |
| 暫定方式、challengeなしで40口 | 99,994,000 | 10,060 | 20 |
| 暫定方式、challengeありで20口 | 99,992,000 | 10,080 | 26 |

390px画面でPendingの「100円 × 20口」と残り期限を確認してchallengeをクリックし、決済完了まで進んだ。最終receiptは `6938a6b95defc8cb9b61ed6dedb8cec66db4e8ccd6ec59d50f50260779740bbe`。claim `3196e3c86c5b9d46f0f3f4d38897344d015589718e023347e2df1ba3daa74965` はproof digestを持つFinalizedだった。

chain `bavr1tZbx6fZB3aptF1hYaT9T1JvBazjARY4mb11UftK9VKo4` の5台全てから、height 26とroot `90fe52b30d1baa63c9c61b53e7dbf9aea00c331bfa8c1079c57e33ddd0a07b07` を読み直した。[検証JSON](verification/OPTIMISTIC_BROWSER_20260912.json) に入力、表示結果、native readback、実行imageとソースhashを記録する。

## 実装と詳しい技術文書

- [HTTP境界](../rust/oclob-demo/src/server.rs)、native接続（統合作業ツリーの ../rust/oclob-demo/src/server/native.rs）、native gateway（統合作業ツリーの ../rust/oclob-settlement/src/avalanche/optimistic.rs）
- [queueと候補状態](../rust/oclob-service/src/lib.rs)
- [暫定方式](https://zkfmi.com/ja/docs/optimistic.html)、[予約から決済・回収まで](https://zkfmi.com/ja/docs/settlement-lifecycle.html)

単一ホスト上の検証であり、独立運営者間の可用性、本番鍵管理、challengerの監視運用、経済的な担保額、秘密板の永続復旧は未確認または未実装である。

## r5での再確認

最新HTTP実装と起動スクリプトを使い、同じ売り100口、共同証明の買い20口、challengeなし40口、challengeあり20口を再実行した。最終残高は99,992,000円、在庫10,080口。5台ともheight 26、root 8d00522d763d20f9b6df2230e6047ce5914f0de824d8a9061871ce7c68747c72だった。

Pending中に実際のAPIパラメータ viewer=taker / viewer=operator で読み分け、買い手だけに100円×20口のprovisionalがあり、運営者にはprovisionalフィールドも私有残高もないことを照合した。従来のroleパラメータによる取得はoperatorへ既定化されるため、私有ビューの確認には使用しない。画面でも390px幅でchallengeを送り、決済後の資金・在庫を確認した。

最終receiptは0f4663b2e4f24cbfabce7eab4e71c63007db4c668d6210678bb229bf02b0819a、claimは13dc2dae2e1d7c06ca63e83e9012fdc9fddba3cabbef14f12d1bfc0bf511e78e。[r5の観測記録](verification/OPTIMISTIC_BROWSER_R5_20260912.json) にバイナリhash、入力、保留中と確定後の残高、5台のreadbackを記録した。不確実なnativeエラーからの手動復旧運用は別の未確認事項である。
