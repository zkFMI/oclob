# 既存研究・既存プロダクトとの差分

## 結論

「秘密注文をMPCで照合するDEX」自体は新しくありません。Rialto、P2DEX、Renegadeは明確な先行例です [1][2][3]。暗号化して順番確定後に復号する方式、TEE内でCLOBを動かす方式、バッチで先回りを薄める方式、公開CLOBを分散運用する方式もあります [4]–[10]。

したがってOCLOBは、暗号部品単体の発明を主張しません。研究差分の候補は、次を一つの状態機械として実装・定義・測定する点です。

1. バッチ清算ではなく、一件ずつ連続処理するCLOB。
2. 指値だけでなく、可変数量、部分約定、複数約定、GTC、IOC、取消、期限切れを秘密状態で処理。
3. 注文内容を開かずに5-of-7で受付順を先に確定し、同価格の時間優先へ結び付ける。
4. 個別注文は秘密のまま、値決めに必要な価格帯別合計板だけを継続公開。
5. 匿名法人資格、法人全体の資金・在庫予約、閾値zkPI、DeFMIでの原子的DvPを結び付け、約定後の追加署名を不要にする。
6. 選択的停止、二重順序、枠超過、再送、公開板からの情報漏洩を、暗号性能だけでなく市場結果と一緒に比較する。

これは有望な差分ですが、形式的な新規性主張は関連文献調査と安全性定義が完成してからに限定します。

## 比較

### Rialto

Rialtoは、注文価格・口座残高・注文者対応を隠し、MPCで注文を照合し、オンチェーン決済と価格発見を行う分散市場です [1]。本研究に最も近い先行研究の一つです。価格・時間優先の考え方も扱い、未約定注文を次のroundへ持ち越します。

差分候補は、Rialtoが一定間隔のroundで単位数量注文を扱うのに対し、OCLOBは非バッチの連続処理、可変数量、部分・複数約定、受付順証明、GTC/IOC/取消、法人予約、zkPIからDeFMI DvPまでを一つの実行経路にする点です。Rialtoを無視して「初の秘密CLOB」とは主張しません。

### P2DEX

P2DEXは、複数サーバーが秘密分散注文をMPC照合し、不正時の補償と処罰を含むクロスチェーンDEXです [2]。実装評価ではSPDZ2kを使い、価格で買い・売りを並べます。ただし評価用アルゴリズムは固定数量、価格中心で、未約定注文を捨て、時刻優先や可変数量は将来拡張としています。

OCLOBはP2DEXの秘密照合を先行研究として正面から引用し、連続板の状態更新、可変数量、部分約定、受付順、匿名法人枠、事前承認決済を具体化します。P2DEXのUC安全性や不正サーバー補償はOCLOBより進んでおり、OCLOB側の未完課題です。

### Renegade

Renegadeは、relayer間の2者MPCと共同ZK証明で匿名注文をmidpoint価格でcrossする実装済みdark poolです [3]。relayerは自分が管理する注文を平文で見ますが、relayer間では暗号化状態を使います。

OCLOBはmidpoint dark poolではなく、公開された価格帯別板へ流動性を残す価格・時間優先CLOBです。複数relayer間の私的crossというRenegadeの中心設計と、全注文を共通受付順へ載せるOCLOBの中心設計は異なります。一方、MPCと共同証明を結ぶ実装技術は重要な比較対象です。

### Tesseract

TesseractはIntel SGX等のTEE内でリアルタイム取引所を動かし、先回りと盗難を抑える設計です [4]。低遅延が長所ですが、ハードウェア製造者のattestation鍵とTEE実装を信頼し、サイドチャネルや実際に正しいenclaveが動いたことの確認を信頼境界へ入れます。

OCLOBはTEEを使わず、7ノードのMPCと公開検証へ信頼を分散します。この違いは速度との交換条件として測定すべきであり、「TEEは競合ではない」だけで済ませません。

### Penumbra / Injective / FairTraDEX

Penumbraはブロックごとのbatch swapで注文を集約し、将来のsealed-bid方式も説明しています [5]。InjectiveはオンチェーンCLOBとFrequent Batch Auctionを提供します [6]。FairTraDEXはFBAによりextractable valueを抑える形式的設計です [7]。

これらは同一時間帯の注文をまとめることで順番競争を弱めます。OCLOBは価格・時間優先を維持する非バッチ方式なので、同じ安全性や価格形成を当然には得ません。比較実験ではバッチ方式を別市場設計として扱います。

### Shutter

Shutterはthreshold encryptionにより、commitmentを記録した後、時刻またはイベント条件で復号鍵を出します [8]。汎用の暗号化メモリプールとして先回りを抑えられます。

OCLOBは注文を後から全員へ復号せず、秘密のまま照合して必要な約定結果だけを出します。Shutterは受付前漏洩を抑える強い部品候補ですが、連続板、価格・時間優先、匿名法人枠、DvPを単独で実装するものではありません。

### dYdX Chain / Hyperliquid

dYdX Chainは各validatorがoff-chainのin-memory orderbookとmatching engineを持つ分散CLOBです [9]。HyperliquidはL1状態に価格・時間優先板を持ち、block proposerがカテゴリ内順序を決めます [10]。両者は高い処理性能と通常の板取引体験を重視しますが、注文価格・数量をMPCで隠すことが中心ではありません。

OCLOBはこの操作感に近づけつつ、未処理注文の内容を順序決定者から隠すことを狙います。性能差が大きい可能性が高く、暗号方式だけでなく受入可能な注文レートを比較します。

### Aequitas系の公平順序

Aequitasは、Byzantine環境で完全な受信順公平性が不可能であることを示し、達成可能な弱い順序公平性を定義します [11]。OCLOBの5-of-7連鎖署名は、これらの一般的な公平順序protocolと同等の保証をまだ証明していません。

論文では「最初にネットワークへ届いた注文を必ず先にする」と書かず、受付証明が保証する範囲、検閲、遅延、同時到着の扱いを形式化します。

## 論文で解くべき問い

1. **秘密受付順**: 注文内容を隠したまま、どの弱い到着順公平性を達成できるか。
2. **継続状態**: 以前の秘密注文を残したまま、一件ごとのMPC照合と取消を安全に続けられるか。
3. **公開板漏洩**: 価格帯合計と約定公開から、個別注文をどの程度推測できるか。
4. **選択的停止**: ノードが結果の一部を知った後だけ停止する攻撃を、秘密を漏らさず検出・処罰できるか。
5. **匿名枠管理**: 複数ウォレットを持つ一法人を公開せず、合計予約枠だけを正しく制限できるか。
6. **自動DvP**: 注文時の事前承認から作ったzkPIが、約定後の署名なしで資金・証券を安全に同時決済できるか。
7. **実用性**: 公開CLOB、復号型、MPC型、バッチ型を同じ注文列で比べ、遅延・処理量・攻撃利益・流動性にどの差が出るか。

## 参考文献

1. K. Govindarajan et al., “Privacy-Preserving Decentralized Exchange Marketplaces (Rialto),” IEEE ICBC 2022. <https://arxiv.org/abs/2111.15259>
2. C. Baum, B. David, T. K. Frederiksen, “P2DEX: Privacy-Preserving Decentralized Cryptocurrency Exchange,” ACNS 2021. <https://eprint.iacr.org/2021/283>
3. Renegade, implementation repository and whitepaper. <https://github.com/renegade-fi/renegade> / <https://whitepaper.renegade.fi/>
4. I. Bentov et al., “Tesseract: Real-Time Cryptocurrency Exchange Using Trusted Hardware,” CCS 2019. <https://eprint.iacr.org/2017/1153>
5. Penumbra Protocol, “Batch Swaps.” <https://protocol.penumbra.zone/main/dex/swap.html>
6. Injective, “Exchange” and its Frequent Batch Auction description. <https://docs.injective.network/developers-native/injective/exchange> / <https://injective.com/blog/injective-exchange-upgrade-a-novel-order-matching-mechanism>
7. P. McMenamin et al., “FairTraDEX: A Decentralised Exchange Preventing Value Extraction.” <https://arxiv.org/abs/2202.06384>
8. Shutter Network, threshold-encryption API overview. <https://docs.shutter.network/docs/protocol/api>
9. dYdX, decentralized off-chain orderbook architecture. <https://www.dydx.xyz/blog/dydx-chain>
10. Hyperliquid, price-time order-book documentation. <https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/order-book>
11. M. Kelkar et al., “Order-Fairness for Byzantine Consensus.” <https://eprint.iacr.org/2020/269>
