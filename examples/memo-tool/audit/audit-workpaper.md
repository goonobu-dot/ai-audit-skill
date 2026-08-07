# 技術監査調書:業務メモ整理ツール(memo-tool)

対応報告書:MEMO-20260807-003 / Quality Profile:1.2.0。公開証拠は秘密値・ローカル絶対パスを除去済み。

## W1. 対象・環境・不変性

- 実施日:2026-08-07 / macOS / Python 3.14.6
- 対象:`seal.json`記載の全追跡ファイル。`audit/`、`atlas/`は生成物として除外
- 監査AI:Codex CLI 0.144.5 / gpt-5.6-sol / xhigh / session `019fda66-ba45-7990-881b-2d11821d77ef`
- 実装AI:Claude（Anthropic）。Codexとは提供元が異なるが、第三者監査又は独立V&Vとは扱わない
- Codexはread-only。試験は一時ディレクトリで実施

## W2. 適用性・要求基準

- target type:`cli` / 安全関連・OT・規制対象:該当なし
- リスク:影響度低、データ機密度中、自律性低 → 標準
- 要求母集団:`requirements-matrix.csv`（AI-AUDIT 53統制、ISO品質9特性、NIST SSDF v1.1の47 task ID）
- AI-AUDIT 1.2.0、ISO/IEC 25010:2023、NIST SP 800-218 v1.1はmapped、29119-2/-3:2021はreferenced
- v1.1証拠は保存しているがv1.2要求単位の期待値・実測値・Evidence ID/hashを再収集していないため、該当行はnot-tested

## W3. 要求別機械検査

- 外部依存・外部通信:なし
- 受入試験:`python3 -m unittest discover -s tests -v` → 9 tests / exit 0
- Evidence:`evidence/uat-log.txt`
- 逆向き検証:欠陥fixture exit 1 / failures=6 / errors=2、最終コード9 tests / exit 0
- Evidence:`evidence/reverse-test.log`
- 詳細なRequirement ID、適用性、判定、owner:`requirements-matrix.csv`

## W4. Codex別系統AIレビュー

- 初回prompt:`evidence/codex-initial-prompt.txt`
- 初回output:`evidence/codex-initial-output.txt` / 判定Reject / 8件
- 再検証prompt:`evidence/codex-revalidation-prompt.txt`
- 再検証output:`evidence/codex-revalidation-output.txt` / 静的レビュー上Must-fixなし
- 正確なsession IDを指定して再開
- 保存された初回promptには旧v1.1の「独立監査人」という語がある。v1.2では別系統AIレビューと再分類し、第三者性を主張しない

## W5. 修正・再試験

1. 削除、未知command、負数、リンク追跡、終了コードを修正
2. 予約fileと`os.replace`の競合をFDベースへ変更
3. 原子的な非上書きrenameへ変更
4. 対象範囲、空検索、余分な引数、行末空白を仕様・試験化

## W6. 能動的試験

- `evidence/vulnerable-memo.py`を`MEMO_TOOL_PATH`で隔離注入
- 本体コード・Git・本番・外部サービス・実データへの欠陥注入なし
- Evidence:`evidence/reverse-test.log`

## W7. 未検証・残余リスク

- 専用SAST/secret scanner、悪意ある同時競合、Windows、大量file性能、人間専門家レビュー
- ownerと結論影響:`requirements-matrix.csv`、`unverified-ledger.md`

## W8. 機械検証・公開ゲート

- `python3 scripts/audit_guard.py validate-quality examples/memo-tool/audit/quality-profile.json examples/memo-tool/audit/requirements-matrix.csv examples/memo-tool/audit` → exit 0
- `python3 scripts/audit_guard.py validate-report examples/memo-tool/audit/quality-profile.json examples/memo-tool/audit/audit-report.md` → exit 0
- `python3 scripts/audit_guard.py verify-seal examples/memo-tool examples/memo-tool/audit/seal.json` → exit 0
- `python3 scripts/audit_guard.py scan-artifacts examples/memo-tool/audit` → exit 0
- 非ゼロなら提出・公開しない
