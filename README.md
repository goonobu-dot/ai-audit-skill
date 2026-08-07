# ai-audit

AIが作ったシステムを、別系統のAIと機械検査で読み取り専用監査し、証拠付きの監査報告書を作るClaude Code / Codex向けスキルです。

> Status: v1.1 Preview。監査結果は限定的保証であり、法令上の保証、認証、人間の専門家による監査の代替ではありません。

## v1.1で守ること

- 既定は `audit-only`。明示承認なしにコード、仕様、設定、Git状態を変更しません。
- 本番環境では欠陥注入、架空データ投入、外部副作用を伴う能動的試験を実行しません。
- 秘密値の生出力を保存せず、SHA-256指紋付きでマスキングします。
- Codex再検証は正確なセッションIDを指定します。
- 封印は生成物を除く監査範囲内の全追跡ファイルを対象にし、未追跡・変更・削除を検出します。

## インストール

```bash
git clone https://github.com/goonobu-dot/ai-audit-skill.git
cd ai-audit-skill

# Claude Code
cp -R skills/ai-audit ~/.claude/skills/
cp -R skills/code-atlas ~/.claude/skills/

# Codex（個人スキル）
cp -R skills/ai-audit ~/.agents/skills/
cp -R skills/code-atlas ~/.agents/skills/
```

前提はOpenAI Codex CLI、Git、Python 3です。追加スキャナーは任意で、未導入の検査は代替または未検証として明記します。

## 検証

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s examples/memo-tool/tests -v
python3 scripts/audit_guard.py validate-bundle examples/memo-tool
python3 scripts/audit_guard.py verify-seal examples/memo-tool examples/memo-tool/audit/seal.json
```

静的な `seal.json` やHTMLが自動で失効表示へ変わるわけではありません。再利用・公開・納品前に検証コマンドを実行し、非ゼロ終了なら監査意見を失効扱いにします。

## 実例とマニュアル

- [再現可能なmemo-tool監査例](examples/memo-tool/)
- [詳細マニュアル](docs/index.html)
- [監査基準](skills/ai-audit/references/audit-standards.md)

実例には最終コード、受入テスト、隔離fixtureでの逆向き検証、マスキング済みCodexプロンプト/出力、封印が含まれます。

## Security

監査成果物を公開する前に必ず秘密情報と個人情報を再検査してください。脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。

## License

MIT
