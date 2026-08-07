# Contributing to ai-audit

ai-auditへの改善提案を歓迎します。初めての方は、文書の分かりにくい箇所、別環境での導入結果、匿名化した監査観点から始めてください。

## 共有してはいけない情報

- 顧客名、案件名、担当者名
- 実在人物の個人情報
- 非公開ソースコード、内部URL、ログ
- APIキー、トークン、パスワード、秘密鍵
- 未公開脆弱性の悪用可能な詳細
- 勤務先や職歴を特定できる情報

セキュリティ問題は公開Issueに書かず、[SECURITY.md](SECURITY.md)に従ってください。

## Issue

Issueには次を記載してください。

- 何をしようとしたか
- 期待した結果
- 実際の結果
- OS、Python、Git、利用エージェントのバージョン
- 個人情報・秘密情報を除いた最小再現例

監査項目の追加提案では、対象、リスク、期待する証拠、公知の一次資料を示してください。特定顧客だけの要求は、一般化できる形にしてください。

## Pull request

1. Issueまたは明確な目的を決める
2. 小さな変更単位にする
3. 動作変更にはテストを追加する
4. マニュアルとテンプレートの整合を確認する
5. 公開前スキャンと全テストを実行する

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s examples/memo-tool/tests -v
python3 scripts/audit_guard.py validate-bundle examples/memo-tool
git diff --check
```

PRには、変更理由、利用者への影響、検証結果、残る制限を書いてください。

## 良い最初の貢献

- 誤字、リンク、曖昧な説明の修正
- macOS/Linux環境でのインストール確認
- English Quick Start
- 公開サンプルの追加
- 個人情報を含まないテストケース
- 公式標準のバージョン更新確認

## 設計原則

- 証拠がないことを確認済みにしない
- 未検証を隠さない
- 認証・第三者保証を主張しない
- 監査と修正を分離する
- 個人情報と秘密情報を公開しない
- fail-closedの機械的な判定ゲートを弱めない
