# 監査調書:業務メモ整理ツール(memo-tool)

対応報告書:MEMO-20260807-002。公開用証拠はすべて秘密値・ローカル絶対パスを除去済み。

## W1. 監査環境

- 実施日:2026-08-07
- 対象:このディレクトリの `seal.json` に列挙した全追跡ファイル（`audit/` と `atlas/` は生成物として除外）
- 実行環境:macOS / Python 3.14.6
- 監査AI:Codex CLI 0.144.5 / gpt-5.6-sol / xhigh
- CodexセッションID:`019fda66-ba45-7990-881b-2d11821d77ef`
- 権限:Codexはread-only。欠陥fixtureと最終コードの試験はいずれも一時ディレクトリ内で実行

## W2. リスク格付け

- 影響度:低（単独利用の補助ツール）
- データ機密度:中（社内メモ）
- 自律性:低（人が毎回CLIを実行）
- メニュー:標準
- 運用前提:macOS/Linux、単独利用、実行中に他プロセスが対象ディレクトリを変更しない

## W3. 機械検査

- 外部依存:なし（Python標準ライブラリのみ）
- 外部通信:対象コードにHTTP、socket、外部プロセス実行なし
- 秘密情報:公開証拠に実在の秘密値なし。検出時は秘密値そのものを保存せず、マスク表示とSHA-256短縮指紋のみを残す
- 受入試験:`python3 -m unittest discover -s tests -v` → 9 tests / exit 0
- 証拠:`evidence/uat-log.txt`

## W4. Codex独立監査

- 初回プロンプト:`evidence/codex-initial-prompt.txt`
- 初回出力（マスキング・相対パス化済み）:`evidence/codex-initial-output.txt`
- 初回判定:Reject。削除、入力検証、シンボリックリンク、異常終了など8件
- 再検証プロンプト:`evidence/codex-revalidation-prompt.txt`
- 最終出力（マスキング・相対パス化済み）:`evidence/codex-revalidation-output.txt`
- 最終判定:approve（静的監査上）。新規・残存Must-fixなし
- 再検証は `codex exec resume --json 019fda66-ba45-7990-881b-2d11821d77ef -` で正確なセッションを指定

## W5. 修正履歴

1. 破壊的削除、未知コマンド、負数、リンク追跡、誤った終了コードを修正
2. 予約ファイル+`os.replace` の競合を発見し、FDベース検査へ変更
3. ハードリンク+`unlink` の競合を発見し、macOS/Linuxの原子的な非上書きrenameへ変更
4. 対象ファイル範囲と単独利用前提を仕様化し、空検索、余分な引数、行末空白をテスト化

## W6. 能動的試験

- 逆向き検証:`evidence/vulnerable-memo.py` を `MEMO_TOOL_PATH` で隔離注入
- 欠陥fixture:exit 1 / failures=2 / errors=2
- 最終コード:9 tests / exit 0
- 証拠:`evidence/reverse-test.log`
- 本体コードやGitブランチへの欠陥注入:なし
- 本番・外部サービス・実データへの能動的試験:なし

## W7. 封印

- 生成:`python3 ../../../scripts/audit_guard.py create-seal . audit/seal.json`
- 照合:`python3 ../../../scripts/audit_guard.py verify-seal . audit/seal.json`
- `seal.json` は全対象ファイルのSHA-256とマニフェストSHA-256を記録する
- 静的JSONは自動更新されない。公開・納品・再利用前に照合し、非ゼロなら監査意見を失効扱いにする

## W8. 限界

- Codexの判定は静的監査であり、人間の専門監査を代替しない
- gitleaks/semgrep等の専用スキャナーは未使用
- Linux上の実行はGitHub Actionsで検証し、macOS上はローカル受入試験で検証する
