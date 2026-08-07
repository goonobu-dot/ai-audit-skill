# ai-audit Quality Profile v1.2.0

## 目的

規格名を並べるだけでなく、`要求ID → 適用判断 → 試験方法 → 証拠 → 判定 → 制限 → 責任者`を追跡する。これは独自の技術検証プロファイルであり、認証、法的保証、適合性評価機関による第三者監査ではない。

## 主張レベル

| 値 | 意味 | 必要条件 |
|---|---|---|
| `referenced` | 分類・工程・文書様式の参考 | 版、公式URL、参照日を記録 |
| `mapped` | 外部基準の要求IDへ対応付け | `requirements-matrix.csv`に同じ出典・版の行がある |
| `verified` | 対応付けた適用要求をすべて試験 | 適用未確定・未試験がなく、結果と証拠がある。合格を意味しない |

`certified`は使用しない。外部認証がある場合も、このプロファイルの判定とは分離し、発行機関、証明書番号、対象範囲、有効期限を別紙で示す。

## 共通基盤

| source_id / 版 | 役割 | 公式情報 |
|---|---|---|
| `AI-AUDIT` / `1.2.0` | 本スキルの53統制の母集団 | https://github.com/goonobu-dot/ai-audit-skill/ |
| `ISO-IEC-25010` / `2023` | 製品品質9特性の分類 | https://www.iso.org/standard/78176.html |
| `ISO-IEC-IEEE-29119-2` / `2021` | テスト工程 | https://www.iso.org/standard/79428.html |
| `ISO-IEC-IEEE-29119-3` / `2021` | テスト文書・証拠 | https://www.iso.org/standard/79429.html |
| `NIST-SP-800-218` / `1.1` | セキュア開発・供給網 | https://csrc.nist.gov/pubs/sp/800/218/final |

ISO/IEC 25010:2023の9特性は、機能適合性、性能効率性、互換性、相互作用能力、信頼性、セキュリティ、保守性、柔軟性、安全性。規格本文はライセンスに従って入手し、本リポジトリへ複製しない。

日本企業との要求調整にはIPA「非機能要求グレード2018」を補助的に使えるが、ISO/IEC 25010:2023との同一性は主張しない。

## 対象別追加基準

- `ios`: OWASP MASVSに加えて[iOS quality profile](ios-quality-profile.md)のApple固有項目を必須追加。
- `android`: OWASP MASVS v2.1.0の24統制を必須追加。Android固有の配布・署名・権限要件は案件側overlayで補う。
- `web` / `api`: `OWASP-ASVS` v5.0.0を要求ID単位で追加。簡易・標準・厳格をASVSの検証レベルと同一視しない。
- `ai-enabled`: NIST SP 800-218A（2024）を追加。ただしAIモデル・AIシステム固有のサイバーセキュリティ範囲であり、バイアス、知財、法令等の全リスクを代替しない。
- `safety-related` / `ot` / `regulated`: [安全関連境界](safety-critical-boundary.md)を適用し、分野固有規格と人間の専門家を必須にする。

## 機械可読成果物

### `quality-profile.json`

対象種別、採用基準の版・公式URL・参照日、主張レベル、専門家レビュー要否、機械算出した技術評価結論を保存する。テンプレートは `templates/quality-profile-template.json`。

`report_release_gate`は常に必須で、既定は`status=draft`、`semantic_review_required=true`とする。外部提出を承認する場合だけ`status=approved`へ変更し、`reviewer_identity`、`reviewer_name`、`reviewer_role`、`reviewer_organization`、`approved_at`、`report_sha256`、`approval_record`、`approval_record_sha256`、`approval_signature`を記録する。

`approval_record`はJSON objectとし、profileと同じ承認者情報に加え、`schema_version=1`、`decision=external-release-approved`、`system_name`、`quality_profile_version`、`technical_conclusion`、`profile_payload_sha256`、`requirements_matrix_sha256`、`report_sha256`、`audit_artifact_manifest_sha256`、`source_seal_sha256`を含める。`profile_payload_sha256`は`report_release_gate`を除いたprofileのcanonical JSON、manifestはprofile・承認記録・署名を除く監査bundle全ファイルの相対パスとSHA-256をcanonical JSON化したものに対するSHA-256である。

承認者はOpenSSHのnamespace`ai-audit-release`で承認記録へdetached signatureを作る。`validate-release`には顧客がbundle外で管理する`allowed_signers`を渡す。これにより供給者が報告書、マトリクス、未検証台帳、調書、証拠、封印を承認後に差し替える操作を拒否する。公開鍵の本人性・承認権限・失効管理は顧客組織の責任である。

承認記録の型は`templates/release-approval-record-template.json`を使う。署名例は`ssh-keygen -Y sign -f <reviewer-private-key> -n ai-audit-release release-approval.json`。秘密鍵を監査bundle、リポジトリ、プロンプトへ入れない。顧客の`allowed_signers`は`reviewer@example.com ssh-ed25519 AAAA...`形式で、監査bundle外に置く。

安全関連、OT、規制対象では`sector_gate`も必須にする。準備段階は`status=blocked`、理由を`blocking_reasons`へ列挙し、結論を`not-acceptable`とする。完了扱いにする場合は`status=complete`とし、ハザード追跡、構成ベースライン、検証計画、独立した人間のレビュー、段階承認の各証拠パスと責任承認者を記録する。ガードは証拠ファイルの存在と安全な相対パスを検査するが、証拠内容の妥当性や承認権限そのものは人間が確認する。

### `requirements-matrix.csv`

次の列を固定する。

| 列 | 内容 |
|---|---|
| `requirement_id` | この検証パッケージ内で一意のID |
| `source_id`, `source_version`, `source_requirement` | 出典・版・元要求ID |
| `applicability` | `applicable` / `not-applicable` / `undetermined` |
| `applicability_approver` | 非適用の承認者。必須又はCriticalはownerと別人・別役割 |
| `mandatory` | `true` / `false` |
| `severity` | `critical` / `important` / `minor` |
| `test_method` | レビュー、SAST、実機試験等 |
| `expected_result`, `actual_result` | 合否基準と実測結果 |
| `evidence_id`, `evidence`, `evidence_sha256` | 一意ID、相対パス、SHA-256。複数は同数の`;`区切り |
| `result` | `pass` / `conditional` / `fail` / `not-tested` / `not-applicable` |
| `limitation` | 条件、不適合、未試験、非適用の根拠 |
| `owner` | 対応・受容の責任者 |
| `hazard_id`〜`stage_approval_id` | 安全関連のハザード、設計、試験、逸脱、残余リスク、段階承認の連鎖 |

AI-AUDITの53統制、ISO/IEC 25010:2023の9特性、NIST SSDF v1.1の47 task ID、iOS時のMASVS v2.1.0全24統制とApple検査群は、ガード内の版付き母集団と照合する。欠落・未知IDは失敗する。ガードは既定の`mandatory`と`severity`も照合し、難しい行だけを任意・Minorへ格下げする操作を拒否する。

非適用は削除ではなく行として残し、理由と承認者を必須にする。必須又はCriticalの非適用はowner自身の承認を拒否する。pass/conditional/failは期待値・実測値・非空証拠・一致するSHA-256を必須にする。未実施を非適用へ置き換えない。CSVを表計算ソフトで開くことを考慮し、`=`, `+`, `-`, `@`から始まるセルを禁止する。

同一の出典・版・元要求IDを複数行へ重複させない。1つの要求行の中又は複数の要求行に、同じ証拠ID、証拠パス、証拠ハッシュを使い回さない。複数要求を1回の試験で確認した場合も、要求ごとの判定根拠を分けた証拠として出力する。

## 技術評価結論

結論はガードがマトリクスから算出し、報告書の見出しと一致させる。

- `acceptable-within-scope`: 適用要求が存在し、すべて`pass`。
- `conditional`: Critical以外の未試験、条件付き、不適合、適用未確定がある。
- `not-acceptable`: 適用要求がない、Criticalが`pass`以外、または必須要求が`fail`。

これは運転許可、App Store承認、契約検収、規制承認を意味しない。各段階の承認権者が別に判断する。

## 実行ゲート

```bash
python3 "$SKILL_DIR/scripts/audit_guard.py" validate-quality \
  "$OUTPUT_DIR/quality-profile.json" \
  "$OUTPUT_DIR/requirements-matrix.csv" \
  "$OUTPUT_DIR"
python3 "$SKILL_DIR/scripts/audit_guard.py" validate-report \
  "$OUTPUT_DIR/quality-profile.json" \
  "$OUTPUT_DIR/audit-report.md"
```

非ゼロなら報告書を提出しない。`validate-bundle`、`scan-artifacts`、`verify-seal`も別途すべて成功させる。
