# Security Policy

## Reporting a vulnerability

公開Issueへ秘密情報、個人情報、未修正の悪用手順を投稿しないでください。GitHubのリポジトリ画面にPrivate vulnerability reportingが表示される場合は、その経路を使用してください。利用できない場合は、秘密値を除いた最小限の概要だけをIssueで知らせ、非公開の連絡方法を確認してください。

監査ログを添付する場合は、`python3 scripts/audit_guard.py redact < raw.log > redacted.log` でマスキングし、共有前に内容を目視確認してください。
