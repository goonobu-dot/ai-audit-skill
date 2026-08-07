# ai-audit

AIが作ったシステムを、別系統AIレビューと機械検査で読み取り専用評価し、要求事項と証拠を追跡できる技術監査報告書を作るClaude Code / Codex向けスキルです。

個人開発者・副業開発者が企業へ提案・納品するときに、「何を基準に、どこまで検証し、何が未検証か」をセキュリティ担当や第三者の確認者へ説明できる形にします。

> Status: v1.2 Preview。これは限定範囲の技術的検証であり、認証、第三者保証、法定検査、人間の専門家による監査、安全性の保証を意味しません。

## v1.2の要点

- `quality-profile.json` に対象、規格名・版、適用レベル、結論を機械可読で固定します。
- `requirements-matrix.csv` で要求ID、適用性、重要度、検証方法、証拠、結果、未解決事項を1行ずつ追跡します。
- AI-AUDITの53統制、ISO品質9特性、NIST SSDF v1.1の47 task ID、iOS時のMASVS v2.1.0全24統制とApple検査群を版付き母集団として照合し、行の省略・架空ID・重要度の格下げを拒否します。
- pass系の判定には期待値・実測値・非空証拠・SHA-256を要求し、Critical/必須の非適用はownerとは別の承認者を要求します。
- 同一の元要求IDの重複と、同じ証拠ID・パス・ハッシュの要求間使い回しを拒否します。
- ISO/IEC 25010:2023、ISO/IEC/IEEE 29119-2/-3:2021、NIST SP 800-218 SSDF v1.1を共通の参照軸にします。
- iOS/AndroidではOWASP MASVS v2.1.0を追加し、iOSではさらにAppleのPrivacy Manifest、Entitlements、署名・配布成果物を確認します。
- 結論は行単位の判定から決定論的に導出し、必須の未試験や重大な不合格があるのに合格扱いできないようにします。
- 安全関連、OT、規制対象を申告した案件は、専門規格・独立した人間のレビュー・発注者承認がなければ一般IT用テンプレートだけで合格にできません。
- 自由記述の意味を正規表現だけで保証しません。報告書は既定で外部提出不可です。外部提出には、顧客管理の公開鍵で検証できる人間の署名付き承認記録を要求し、報告書、プロファイル本体、要件マトリクス、証拠を含む監査bundle、ソース封印を結びます。

既定は `audit-only` です。明示承認なしにコード、仕様、設定、Git状態を変更せず、本番環境で欠陥注入や外部副作用を伴う能動的試験を行いません。秘密値の生出力は保存せず、封印は監査範囲内の追跡ファイルの変更・削除・未追跡追加を検出します。

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
python3 scripts/audit_guard.py validate-quality \
  examples/memo-tool/audit/quality-profile.json \
  examples/memo-tool/audit/requirements-matrix.csv \
  examples/memo-tool/audit
python3 scripts/audit_guard.py validate-report \
  examples/memo-tool/audit/quality-profile.json \
  examples/memo-tool/audit/audit-report.md
python3 scripts/audit_guard.py validate-bundle examples/memo-tool
python3 scripts/audit_guard.py verify-seal examples/memo-tool examples/memo-tool/audit/seal.json
```

外部提出では上記に加え、OpenSSHで署名した`release-approval.json.sig`と、監査対象bundle外で顧客が管理する`allowed_signers`を使います。

```bash
python3 scripts/audit_guard.py validate-release \
  audit/quality-profile.json audit/requirements-matrix.csv audit/audit-report.md \
  audit . audit/seal.json /customer-controlled/allowed_signers
```

`validate-quality`や`validate-report`のexit 0はドラフト内部検証にも使うため、外部提出許可を意味しません。外部提出の機械ゲートは`validate-release`だけです。サンプルは意図的にドラフトなので、このコマンドは通りません。

静的な `seal.json` やHTMLが自動で失効表示へ変わるわけではありません。再利用・公開・納品前に検証コマンドを実行し、非ゼロ終了なら技術評価結論を失効扱いにします。

## 成果物

標準成果物は、技術監査報告書、監査調書、未検証台帳、証拠封印に加え、`quality-profile.json` と `requirements-matrix.csv` の6点です。発注者が先に品質条件を提示する場合は、[品質要求仕様テンプレート](skills/ai-audit/templates/quality-requirements-template.md)も使えます。

- [再現可能なmemo-tool監査例](examples/memo-tool/)
- [詳細マニュアル](docs/index.html)
- [品質プロファイル](skills/ai-audit/references/quality-profile.md)
- [iOS品質プロファイル](skills/ai-audit/references/ios-quality-profile.md)
- [安全関連・OT境界](skills/ai-audit/references/safety-critical-boundary.md)
- [監査基準](skills/ai-audit/references/audit-standards.md)

## 安全関連案件の境界

発電所、産業制御、機能安全などの安全関連システムでは、このスキル単体の判定を採用・運転許可・安全証明に使わないでください。ハザード分析、安全要求、構成ベースライン、FAT/SAT、独立V&V、逸脱管理、責任者承認を案件固有の専門規格と法令に従って追加し、その証拠を要求事項単位で結びます。

## Security

監査成果物を公開する前に必ず秘密情報と個人情報を再検査してください。脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。

## License

MIT
