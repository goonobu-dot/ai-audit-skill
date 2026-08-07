# 技術監査調書:{システム名}

対応報告書:{ID} / Quality Profile:1.2.0 / 目的:要求から証拠・判定まで第三者が再実行できる記録を残す

## W1. 対象・環境・不変性

- 日時、OS、ランタイム、ツール版:
- 対象commit、開始/終了のHEAD・worktree・index・未追跡一覧:
- source seal、納品artifact名・版・署名・SHA-256:
- 実装AI、レビューAI、セッションID、提供元関係:
- 人間の実施者、独立確認者、利益相反、力量・役割:

別提供元AIは別系統レビューであり、第三者監査人又は独立V&Vではない。

## W2. 適用性・要求基準

- `quality-profile.json`のtarget types、基準版、参照日、claim level:
- リスク格付け、適用法令・契約・社内基準:
- 安全関連/OT/規制ゲート、専門規格、専門家レビュー:
- 要求母集団:`requirements-matrix.csv`の行数とhash:

## W3. 要求別検証記録

検査ごとに記録する。

- Requirement ID / 出典・版・元要求ID:
- 適用性、必須性、重大度、非適用の場合の根拠・承認者:
- Test ID、試験手順版、前提、構成基準、期待値・許容差:
- 実行コマンド、ツール・測定器版、校正状態、終了コード:
- 実測値、マスキング済み証拠path、Evidence ID、SHA-256:
- 判定、Finding/Deviation ID、owner、期限、再試験:

## W4. 別系統AIレビュー

- 渡した入力:仕様書、要求マトリクス、コードだけ。先行結論・実装者説明は除外
- 権限境界を含む依頼文全文:
- モデル、推論設定、正確なsession ID:
- マスキング済み出力全文とEvidence ID/hash:
- 各指摘とRequirement IDの対応:

## W5. 承認済み修正

| 周回 | Finding ID | Requirement ID | 承認範囲 | 修正commit | 再試験Evidence ID | 状態 |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |

## W6. 能動的試験

- 承認者、隔離環境、外部副作用、ロールバック:
- UAT/逆向き検証/漏洩/不変条件/MASTG等のTest ID:
- 試験前後の対象hash不変証拠:
- 安全関連の場合:FAT/SAT/試運転/故障注入等は専門手順・専門家の別記録を参照。本調書で代替しない

## W7. 不適合・残余リスク

| Finding/Deviation ID | Requirement/Hazard ID | 原因 | 暫定措置 | 恒久対策 | 再試験 | 残余リスク | owner/期限 |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

## W8. 機械検証・公開ゲート

- `validate-quality`:{コマンド、日時、終了コード、算出結論}
- `create-seal` / `verify-seal`:{コマンド、除外、終了コード}
- `scan-artifacts`:{対象、日時、終了コード、バイナリ別経路}
- 例外・除外:{理由、承認者。非ゼロの共有bundleは例外承認不可}
