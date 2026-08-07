---
layout: guide
title: GitHubで利用者とStarを増やす運用ガイド
description: ai-auditの利用開始、信頼、継続改善を通じてOSSを育てる実務ガイド
permalink: /github-growth-guide.html
---

# GitHubで利用者とStarを増やす運用ガイド

Starは直接集めるものではなく、訪問者が「自分の問題を解決できる」「後で使いたい」「更新を追いたい」と判断した結果です。短期的な宣伝より、利用開始の摩擦、信頼、継続改善を優先します。

## 現在の優先順位

1. 10秒で用途が分かるREADME
2. 5分で再現できるサンプル
3. 実案件で使える具体的な成果物
4. 誤解しない限界説明
5. Issueから参加しやすい導線
6. 定期的なリリースと変更履歴
7. 対象利用者がいる場所での事例共有

## 1. リポジトリの入口を整える

GitHubはREADMEをリポジトリ訪問者が最初に見る情報として案内し、目的、利用価値、使い方を説明する場所としています。

READMEの最初の画面で次を伝えます。

- 何をするシステムか
- 誰のためか
- 何が成果物として残るか
- 5分で試すリンク
- 公開マニュアルとサンプル
- CI、ライセンス、バージョン
- StarとIssueへの自然な導線

長い背景説明は詳細マニュアルへ分離します。

## 2. デモを「本当に再現可能」にする

- コピー可能なコマンド
- 追加課金なしで動く最小サンプル
- 期待する出力
- 意図的な不合格例
- 修正前後の差分
- CIで同じ検証を実行

ai-auditでは、サンプルが`not-acceptable`である理由も価値になります。都合のよい合格例より、証拠不足を正しく止める動作を見せられます。

## 3. Topicsとリポジトリ情報

GitHubはTopicsを、目的・分野・コミュニティ等でリポジトリを分類し、他の人がプロジェクトを発見・貢献しやすくする機能と説明しています。

候補:

- `ai-audit`
- `software-audit`
- `software-quality`
- `application-security`
- `secure-development`
- `codex`
- `claude-code`
- `owasp-masvs`
- `ios-security`
- `supply-chain-security`

Topicsは広すぎる一般語を大量に付けず、実際の機能と一致させます。リポジトリの説明とWebサイト欄には、短い価値説明と公開マニュアルURLを設定します。

## 4. SNS共有画像

GitHubは、リポジトリのリンクをSNSで共有したときに表示する画像を設定できます。

画像には次だけを入れます。

- `ai-audit`
- `Evidence-backed audit for AI-built software`
- `Requirements → Tests → Evidence → Decision`
- 過度な保証を避けた短い補足

細かい表や長文はSNS上で読めません。1280×640程度の横長画像を用意し、GitHubのリポジトリ設定から登録します。

## 5. コミュニティ参加の入口

GitHubのコミュニティプロフィールは、README、LICENSE、SECURITY、CONTRIBUTING、行動規範、Issueテンプレート等を確認対象にしています。

最低限用意するもの:

- `CONTRIBUTING.md`
- 不具合報告テンプレート
- 監査範囲の追加提案テンプレート
- `good first issue`候補
- セキュリティ脆弱性は公開Issueへ書かない案内

最初の貢献依頼は小さくします。

- 誤字・リンク修正
- 別OSでのインストール確認
- 匿名化した検査観点の追加
- サンプルテストの追加
- English translation

## 6. リリースを作る

GitHub Releasesは、特定タグの版を利用者向けにまとめ、リリースノートやダウンロードリンクを提供する機能です。

リリースノートには次を含めます。

- 誰に関係する更新か
- 何ができるようになったか
- 互換性を壊す変更
- 移行手順
- 検証結果
- 既知の制限

Preview版はプレリリースとして公開し、安定版へ移行する条件を明記します。

## 7. 発信内容

宣伝文だけを繰り返さず、利用者が保存したくなる内容を出します。

### 良い題材

- AI生成testが誤りを見逃す例と逆向き検証
- `not-tested`と`not-applicable`の違い
- iOS Privacy Manifestを証拠化する方法
- 顧客へ渡す未検証面台帳の例
- 監査後の変更で封印が失効するデモ
- 架空IDや証拠使い回しを検証器が拒否する例

### 投稿の型

1. 困っている場面
2. よくある弱い対応
3. ai-auditでの確認方法
4. 出力サンプル
5. 限界
6. リポジトリと再現手順

## 8. 日本語と英語

日本語マニュアルは差別化になります。一方、GitHub上の発見範囲を広げるには、README冒頭の英語要約、英語Quick Start、英語Issueテンプレートを段階的に追加します。

最初から全マニュアルを機械翻訳で複製すると保守負担が増えます。まずREADME、Quick Start、リリースノートから始めます。

## 9. 30日運用例

### 1週目

- README、マニュアル、Topics、Webサイト欄を整える
- v1.2 Previewリリースを作る
- SNS共有画像を設定する

### 2週目

- 5分デモ動画またはGIFを作る
- iOSサンプルの監査例を1件追加する
- 3件の`good first issue`を作る

### 3週目

- 監査の失敗例を1本公開する
- 利用者へ「分からなかった箇所」を聞く
- FAQとインストール手順を更新する

### 4週目

- Issue、clone、Pages閲覧、Starの変化を確認する
- 反応の弱い発信をやめ、保存・質問された題材へ集中する
- 次のリリース対象を公開Issueで示す

## 10. 見る数字

Starだけで判断しません。

- ユニーク訪問者数
- clone数
- サンプル実行に関するIssue
- 文書に関する質問
- 初参加者数
- リリース閲覧・ダウンロード数
- 実案件での再利用報告
- StarからIssue/利用へ進んだ割合

Starが増えても利用者が動かなければ、製品としての証拠は弱いままです。

## 11. やらないこと

- 相互Starや購入したStar
- 無関係なリポジトリへの宣伝Issue
- 過度なタグ付け
- 「完全」「認証済み」等の誇張
- 顧客情報を事例として公開
- 使えない状態で大量拡散
- 更新予定を守れないのにロードマップを約束

## 参考：GitHub公式情報

- [About READMEs](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes)
- [Classifying a repository with topics](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics)
- [Customizing your repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository)
- [Setting up a project for healthy contributions](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions)
- [Managing releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
