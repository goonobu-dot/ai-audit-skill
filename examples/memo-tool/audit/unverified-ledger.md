# 未検証・適用未確定台帳:業務メモ整理ツール(memo-tool)

対応報告書:MEMO-20260807-003。未検証は安全とも危険とも確認していないことを示す。

| Requirement ID | 出典・版・要求ID | 必須 | 重大度 | 状態 | 理由 | 推奨 | owner | 結論影響 |
|---|---|---|---|---|---|---|---|---|
| MEMO-AA-001〜053 | AI-AUDIT 1.2.0 AA-1.1〜AA-9.9（正本はmatrix） | true | Critical/Important | not-tested | v1.1証拠をv1.2要求単位で再収集していない | 各行の期待値・実測値・Evidence ID/hashを収集 | quality-owner | not-acceptable |
| MEMO-Q-001〜008 | ISO-IEC-25010 2023（正本はmatrix） | true | Important | not-tested | 9特性のv1.2粒度で再試験前 | 特性別に試験・証拠化 | quality-owner | not-acceptable |
| MEMO-S-001〜047 | NIST-SP-800-218 1.1の47 task ID | true | Important | not-tested | SSDF実務の要求単位証拠を再収集していない | 開発・保護・実装・対応証拠を収集 | security-owner | not-acceptable |

## 非適用

| Requirement ID | 理由 | 判断者 | 承認者 | 再評価トリガー |
|---|---|---|---|---|
| MEMO-Q-009 | 安全機能・制御出力を持たないローカルCLI | product-owner | quality-owner | 用途を安全関連へ拡大した時点 |

人間の専門家レビュー、Windows、納品binaryは本検証範囲外。別系統AIレビューは第三者監査又は独立V&Vではない。
