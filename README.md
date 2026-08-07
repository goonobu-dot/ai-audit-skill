# ai-audit

[![Validate audit skill](https://github.com/goonobu-dot/ai-audit-skill/actions/workflows/validate.yml/badge.svg)](https://github.com/goonobu-dot/ai-audit-skill/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Manual](https://img.shields.io/badge/Manual-日本語-0017c1)](https://goonobu-dot.github.io/ai-audit-skill/)

AIで作ったアプリや業務システムについて、**何を基準に、どこまで検証し、何が未検証か**を、要求IDと証拠付きで説明するためのClaude Code / Codex向け技術監査スキルです。

個人開発者・副業開発者が企業へ提案・納品するときに、口頭の「確認しました」ではなく、セキュリティ担当・品質担当・外部専門家が追跡できる監査成果物を作ります。

> English: Evidence-backed technical audit workflow for AI-built software. It maps versioned requirements to tests, evidence, findings, limitations, and release approvals.

**[詳しい日本語マニュアル](https://goonobu-dot.github.io/ai-audit-skill/)** · **[5分で始める](https://goonobu-dot.github.io/ai-audit-skill/getting-started.html)** · **[副業・受託での使い方](https://goonobu-dot.github.io/ai-audit-skill/freelance-playbook.html)** · **[監査内容の詳しい備考](https://goonobu-dot.github.io/ai-audit-skill/audit-notes.html)**

役に立った場合は、リポジトリ右上の **Star** で応援してください。実際の案件で不足した検査や分かりにくい点は、個人情報・顧客情報・秘密情報を除いて[Issue](https://github.com/goonobu-dot/ai-audit-skill/issues)へ共有してください。

## このシステムの目的

このシステムは、AI開発を「安全だと宣言する」ためのものではありません。次の説明責任を、再確認できる形にすることが目的です。

1. 監査対象をコミットとハッシュで固定する
2. 参照した品質・セキュリティ基準の名称と版を記録する
3. 要求ごとに、適用判断・試験方法・期待値・実測値・証拠を結ぶ
4. 未実施、対象外、残余リスクを隠さず残す
5. コード変更後に古い監査結果を使い回せないよう封印する
6. 外部提出時は、人間の承認を顧客管理の公開鍵で検証する

## 得られるメリット

| 利用場面 | メリット |
|---|---|
| 企業への提案 | 「AIで作りました」だけでなく、採用基準、検査範囲、未検証事項を示せる |
| 納品・検収 | 要求・テスト・証拠・指摘対応の対応関係を渡せる |
| セキュリティ説明 | CWE、OWASP、NIST等の共通語彙で専門担当へ引き継げる |
| 外部診断の依頼 | 未検証面台帳を診断範囲や見積もりの入力にできる |
| 品質改善 | AIが書いた実装とテストを追認せず、逆向き検証や別系統レビューを行える |
| 継続保守 | ソース変更で封印が失効するため、再監査の必要性を判断しやすい |

## どのような監査をするか

| 監査領域 | 主な確認内容 | 主な証拠 |
|---|---|---|
| スコープ・同一性 | 対象コミット、作業ツリー、対象外、生成物 | Git状態、`seal.json` |
| 情報保護 | 秘密値、個人情報、外部送信、ログへの露出 | マスキング済み検査結果 |
| 仕様適合 | 要求漏れ、仕様外機能、受入条件、禁止事項 | 仕様、UAT、要求マトリクス |
| セキュリティ | 入力検証、認証認可、依存脆弱性、暗号、通信 | SAST/SCA結果、CWE、試験ログ |
| 挙動・副作用 | 通知、課金、削除、外部API、再試行、重複実行 | 副作用一覧、不変条件、隔離試験 |
| 品質特性 | 機能、性能、互換性、信頼性、保守性、安全性等 | ISO品質分類、測定結果 |
| モバイル | MASVS、端末保存、通信、認証、プライバシー | MASVS行、Privacy Manifest等 |
| 供給網・来歴 | 依存元、版固定、ライセンス、生成記録 | lockfile、依存一覧、来歴記録 |
| 保守・運用 | ログ、監視、復旧、引継ぎ、再監査条件 | 運用手順、復元試験、code-atlas |
| 監査プロセス | 権限境界、別系統レビュー、未検証、承認 | 調書、台帳、署名承認記録 |

詳細な検査目的、判断方法、証拠例、誤解しやすい点は[監査内容の詳しい備考](https://goonobu-dot.github.io/ai-audit-skill/audit-notes.html)にまとめています。

## 5分で試す

前提はPython 3、Git、Claude CodeまたはOpenAI Codex CLIです。

```bash
git clone https://github.com/goonobu-dot/ai-audit-skill.git
cd ai-audit-skill

# 付属サンプルとガードを検証
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s examples/memo-tool/tests -v
python3 scripts/audit_guard.py validate-bundle examples/memo-tool
```

スキルを配置します。

```bash
# Claude Code
cp -R skills/ai-audit ~/.claude/skills/
cp -R skills/code-atlas ~/.claude/skills/

# Codex
cp -R skills/ai-audit ~/.agents/skills/
cp -R skills/code-atlas ~/.agents/skills/
```

対象プロジェクトで、次のように依頼します。

```text
このプロジェクトをai-auditで読み取り専用監査してください。
対象は現在のコミット、用途は企業への納品前確認です。
秘密情報や個人情報を成果物へ保存せず、未検証事項も明記してください。
```

初回利用、実案件、外部提出の手順は[スタートガイド](https://goonobu-dot.github.io/ai-audit-skill/getting-started.html)を参照してください。

## 標準成果物

| ファイル | 用途 |
|---|---|
| `quality-profile.json` | 対象、参照基準と版、主張レベル、技術評価結論 |
| `requirements-matrix.csv` | 要求・適用性・試験・証拠・判定・制限・責任者 |
| `audit-report.md` | 経営要約、重要指摘、残余リスク、利用条件 |
| `audit-workpaper.md` | 再実行コマンド、環境、マスキング済み証拠 |
| `unverified-ledger.md` | 実施できなかった検査と追加対応 |
| `seal.json` | 監査対象ソースの変更・削除・追加を検出する封印 |

外部提出時は、これらに人間の署名付き承認記録を追加し、`validate-release`で監査成果物一式を検証します。

## 副業・受託開発での使い方

本システムは「監査済みだから絶対安全」と売る道具ではありません。**検証範囲と限界を説明できる納品工程**として使います。

- 提案時：品質確認の工程と提出予定の成果物を示す
- 要件定義時：発注者と合否条件・禁止事項・対象外を合意する
- 開発中：要求マトリクスを更新し、未検証を先送りしない
- 納品前：監査、修正、再検証、封印を実施する
- 納品時：報告書、未検証台帳、再実行手順を説明する
- 保守時：変更差分を監査し、古い結論を失効させる

営業文例、案件メニュー、見積もり条件、禁止表現は[副業・受託活用ガイド](https://goonobu-dot.github.io/ai-audit-skill/freelance-playbook.html)にあります。

## ドキュメント

- [Web版・詳細マニュアル](https://goonobu-dot.github.io/ai-audit-skill/)
- [5分で始める・実案件の進め方](https://goonobu-dot.github.io/ai-audit-skill/getting-started.html)
- [監査内容の詳しい備考](https://goonobu-dot.github.io/ai-audit-skill/audit-notes.html)
- [副業・受託開発での活用](https://goonobu-dot.github.io/ai-audit-skill/freelance-playbook.html)
- [公開前プライバシーチェック](https://goonobu-dot.github.io/ai-audit-skill/privacy-checklist.html)
- [GitHubで利用者とStarを増やす運用](https://goonobu-dot.github.io/ai-audit-skill/github-growth-guide.html)
- [品質プロファイル仕様](skills/ai-audit/references/quality-profile.md)
- [iOS品質プロファイル](skills/ai-audit/references/ios-quality-profile.md)
- [安全関連・OT境界](skills/ai-audit/references/safety-critical-boundary.md)
- [監査基準](skills/ai-audit/references/audit-standards.md)
- [再現可能なサンプル](examples/memo-tool/)

## 重要な境界

> Status: v1.2 Preview

これは限定範囲の技術的検証です。認証、第三者保証、法定検査、App Store承認、契約検収、運転許可、安全性の保証を意味しません。

安全関連、産業制御、規制対象では、案件固有の法令・専門規格・安全分類・ハザード分析・FAT/SAT・独立V&V・責任者承認が別途必要です。本ツール単独では`acceptable-within-scope`を出しません。

## プライバシー

公開リポジトリには、作者の勤務先、職歴、顧客名、案件名、実在人物の氏名、メールアドレス、端末パスを記載しません。監査成果物を公開する場合も、実データではなく架空データを使い、秘密値・個人情報・顧客情報を除去してください。

[公開前プライバシーチェック](https://goonobu-dot.github.io/ai-audit-skill/privacy-checklist.html)と`scan-artifacts`を使用してください。

## コントリビューション

利用者の実案件で見つかった不足を、一般化したテスト・チェックリスト・文書改善として歓迎します。顧客情報や脆弱性の詳細を公開Issueへ書かないでください。

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [セキュリティポリシー](SECURITY.md)
- [変更履歴](CHANGELOG.md)

## License

MIT
