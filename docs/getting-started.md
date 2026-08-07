# ai-audit スタートガイド

このガイドは、初めて使う人が最初の5分でサンプル確認を始め、「自分の案件の監査 → 修正 → 納品前確認」まで進めるための手順書です。

## 1. 最初に理解すること

ai-auditは、対象コードを自動的に合格させるツールではありません。監査対象、基準、試験、証拠、未検証事項を固定し、説明可能な成果物を作るためのワークフローです。

既定は`audit-only`です。明示承認がない限り、対象コード、設定、Git状態を変更しません。監査結果を受けて修正する場合は、監査と修正を分けて承認します。

## 2. 必要なもの

- Python 3
- Git
- Claude CodeまたはOpenAI Codex CLI
- 監査対象のローカルGitリポジトリ
- 用途、主要機能、禁止事項、扱うデータの説明

任意のSAST/SCAツールは、導入済みで安全に読み取り専用実行できる場合だけ使います。未導入の検査は、代替または未検証として記録します。

## 3. インストール

```bash
git clone https://github.com/goonobu-dot/ai-audit-skill.git
cd ai-audit-skill

# Claude Code
cp -R skills/ai-audit ~/.claude/skills/
cp -R skills/code-atlas ~/.claude/skills/

# Codex
cp -R skills/ai-audit ~/.agents/skills/
cp -R skills/code-atlas ~/.agents/skills/
```

更新時はリポジトリで`git pull`した後、同じコピー操作を行います。ローカルで変更したスキルを上書きしたくない場合は、先に差分を退避してください。

## 4. 付属サンプルを検証する

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s examples/memo-tool/tests -v
python3 scripts/audit_guard.py validate-quality \
  examples/memo-tool/audit/quality-profile.json \
  examples/memo-tool/audit/requirements-matrix.csv \
  examples/memo-tool/audit
python3 scripts/audit_guard.py validate-report \
  examples/memo-tool/audit/quality-profile.json \
  examples/memo-tool/audit/audit-report.md
python3 scripts/audit_guard.py validate-bundle examples/memo-tool
python3 scripts/audit_guard.py verify-seal \
  examples/memo-tool examples/memo-tool/audit/seal.json
```

サンプルの結論は意図的に`not-acceptable`です。過去の粗い証拠を、新しい要求粒度の証拠として水増ししない例になっています。コマンドが`valid`になることと、対象システムが合格判定になることは別です。

## 5. 監査前に準備する情報

次の内容を1ページ程度で準備します。分からない項目は推測せず「未確定」とします。

| 項目 | 記載例 |
|---|---|
| 業務目的 | 予約情報を端末内で整理する |
| 利用者 | 契約した事業者の担当者 |
| 主要機能 | 登録、検索、PDF出力 |
| 扱うデータ | 架空データ、個人情報、認証情報の有無 |
| 外部通信 | API、クラウド、メール、通知 |
| 禁止事項 | 無断送信、自動課金、物理削除 |
| 合否条件 | 必須シナリオ、性能値、対応OS |
| 対象外 | 実機試験、外部侵入診断など |
| 変更権限 | 監査のみか、修正も許可するか |

## 6. 読み取り専用監査を依頼する

対象リポジトリで、次の依頼文を調整して使います。

```text
このプロジェクトをai-auditで読み取り専用監査してください。

目的: 企業への納品前に、品質・セキュリティ・未検証事項を説明できるようにする。
対象: 現在のGitコミットと追跡ファイル。
対象種別: iOSアプリ。
成果物出力: audit/への新規出力を承認する。
禁止: 対象コード、設定、依存、Git index、履歴を変更しない。
能動的試験: 外部送信、通知、課金、データ更新を伴う試験は実行しない。
情報保護: 秘密値、個人情報、顧客情報を成果物へ保存しない。
不明事項: 推測で合格にせず、未検証面台帳へ記録する。
```

`audit/`も対象コードの一部として扱うプロジェクトでは、成果物をプロジェクト外の一時ディレクトリへ出してください。

## 7. 初回監査の確認ポイント

監査結果を受け取ったら、結論だけでなく次を確認します。

1. 対象コミットと監査対象範囲が正しいか
2. `quality-profile.json`の対象種別・基準・版が正しいか
3. Critical/Importantの未試験や不合格があるか
4. `unverified-ledger.md`に実施できなかった検査が残っているか
5. 証拠がマスキングされ、実在の秘密値や個人情報がないか
6. 利用条件と失効条件が現実の運用に合っているか

## 8. 修正を依頼する

修正は監査とは別の`remediation`として、対象を限定して承認します。

```text
初回監査の指摘ID AA-2.2、AA-4.1、QA-IOS-003だけを修正してください。
変更対象はアプリのソースとテストです。
外部API、通知、課金、本番データには接続しないでください。
修正後は同じ監査セッションで全対象を再検証し、解消・残存・新規を報告してください。
```

修正後は、前回指摘だけでなく全体を再検証します。新しい変更が別の問題を作っていないか確認するためです。

## 9. 納品前の機械検証

```bash
SKILL_DIR="$HOME/.agents/skills/ai-audit"
OUTPUT_DIR="/path/to/project/audit"
TARGET_ROOT="/path/to/project"

python3 "$SKILL_DIR/scripts/audit_guard.py" validate-quality \
  "$OUTPUT_DIR/quality-profile.json" \
  "$OUTPUT_DIR/requirements-matrix.csv" \
  "$OUTPUT_DIR"
python3 "$SKILL_DIR/scripts/audit_guard.py" validate-report \
  "$OUTPUT_DIR/quality-profile.json" \
  "$OUTPUT_DIR/audit-report.md"
python3 "$SKILL_DIR/scripts/audit_guard.py" scan-artifacts "$OUTPUT_DIR"
python3 "$SKILL_DIR/scripts/audit_guard.py" verify-seal \
  "$TARGET_ROOT" "$OUTPUT_DIR/seal.json"
```

いずれかが非ゼロ終了なら提出しません。`valid`はファイル構造と宣言の整合を示すもので、認証や無欠陥を示しません。

## 10. 外部提出

`validate-quality`と`validate-report`はドラフトでも成功します。外部提出のゲートは`validate-release`です。

外部提出には、顧客側が管理するOpenSSH公開鍵と、権限を持つ人間が署名した承認記録が必要です。秘密鍵は開発者、監査bundle、リポジトリ、AIプロンプトへ渡しません。

```bash
python3 "$SKILL_DIR/scripts/audit_guard.py" validate-release \
  "$OUTPUT_DIR/quality-profile.json" \
  "$OUTPUT_DIR/requirements-matrix.csv" \
  "$OUTPUT_DIR/audit-report.md" \
  "$OUTPUT_DIR" \
  "$TARGET_ROOT" \
  "$OUTPUT_DIR/seal.json" \
  "/customer-controlled/allowed_signers"
```

署名記録の形式は[品質プロファイル仕様](../skills/ai-audit/references/quality-profile.md)と[テンプレート](../skills/ai-audit/templates/release-approval-record-template.json)を参照してください。

## 11. 再監査が必要な条件

- ソース、設定、依存、ビルド条件が変わった
- OS、SDK、外部API、審査要件が変わった
- 新しい脆弱性が公表された
- 利用目的、利用者、扱うデータが変わった
- 未検証だった実機・負荷・外部診断を実施した
- 報告書の有効期限を超えた

差分が小さくても、`verify-seal`が失敗した時点で以前の結論をそのまま使いません。

## 12. 困ったとき

- コマンドやテンプレートの問題：[GitHub Issues](https://github.com/goonobu-dot/ai-audit-skill/issues)
- 脆弱性や秘密情報：[SECURITY.md](../SECURITY.md)に従い、公開Issueへ書かない
- 監査内容が分からない：[監査内容の詳しい備考](audit-notes.md)
- 企業案件への組み込み：[副業・受託活用ガイド](freelance-playbook.md)
