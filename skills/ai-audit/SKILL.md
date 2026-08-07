---
name: ai-audit
description: Use when a user asks to audit, inspect, accept, or produce an evidence-backed audit report for an AI-built system before delivery or production use.
---

# ai-audit — 要求・証拠追跡付き技術監査

主任監査人として、証拠がないことを「確認済み」と書かない。既定は読み取り専用の `audit-only`。監査と修正を混同しない。

## 最初に固定する権限境界

### `audit-only`（既定）

- 対象の作業ツリー、index、未追跡ファイル、ソース、設定、仕様、Git参照・履歴を一切変更しない。`git add` も行わない。
- 成果物の保存場所はユーザー指定を優先する。対象内の `audit/` への新規出力も変更に含むため、明示承認なしには作らない。出力承認がなければ対象外の一時ディレクトリへ出し、最終回答に要約する。
- 仕様や禁止事項が不足していても推測で追記しない。判定できない項目を未検証面台帳へ記録する。
- 修正案は報告するだけで実装しない。

### `remediation`（修正モード）

初回監査結果を提示した後、ユーザーが対象と範囲を**明示承認**した場合だけ開始する。承認には、変更対象、Git操作、実行する試験、外部副作用の有無を含める。承認外の修正へ拡張しない。

### 能動的試験

欠陥注入、カナリア投入、ブラウザ操作、外部API・レジストリへの通信、データ更新を伴う試験は、修正承認とは別に明示承認を得る。隔離された使い捨て環境、架空データ、ロールバック手段を確認してから実施する。**本番環境で能動的試験を実行しない**。環境を確認できなければ未実施とする。worktreeや一時ブランチを使う場合は、Gitメタデータ変更も承認項目へ明記する。

## 成果物

テンプレートから次を生成する。

1. `audit-report.md` — 技術評価結論、重大指摘、残余リスク
2. `audit-workpaper.md` — 再実行可能なコマンド、バージョン、マスキング済み証拠
3. `unverified-ledger.md` — 未実施・未確認の領域
4. `seal.json` — 監査対象の全追跡ファイルを結ぶSHA-256封印
5. `quality-profile.json` — 対象種別、参照基準の版・参照日・主張レベル、機械算出結論
6. `requirements-matrix.csv` — 要求ID、適用性、試験、証拠、判定、制限、責任者の全数表

報告書は既定で外部提出不可とする。自由記述は正規表現だけで意味を保証できないため、外部提出前に人間が全文を意味レビューする。承認記録はOpenSSHで署名し、顧客管理のbundle外`allowed_signers`で検証する。署名対象には報告書、プロファイル本体、マトリクス、監査成果物manifest、ソース封印のハッシュを含める。

監査基準は [references/audit-standards.md](references/audit-standards.md)、品質プロファイルは [references/quality-profile.md](references/quality-profile.md)、雛形は [templates/](templates/) を読む。発注者として品質要件を作る依頼では、監査開始前に [templates/quality-requirements-template.md](templates/quality-requirements-template.md) を使う。

## Phase 0: 前提とスコープ

1. 仕様書、禁止事項、対象パス、対象コミット、作業ツリー状態を読み取り専用で確認する。
2. 仕様不足は最大3問で確認する。回答がなくても進められる場合は、仮定せず該当項目を「未評価」にする。
3. `git status --short` と `git rev-parse HEAD` を記録する。Gitがなければ封印不能として台帳へ記録し、`git init` はしない。
4. 対象種別（iOS、Web/API、AI搭載、安全関連、OT、規制対象等）を確定し、`quality-profile.json`へ版付き基準を登録する。iOSは [references/ios-quality-profile.md](references/ios-quality-profile.md) を必須適用する。
5. リスクを簡易・標準・厳格に分類し、根拠を調書へ残す。これはASVS/MASVS等の検証レベルと同一ではない。
6. **安全関連、OT、規制対象又は判断不能なら** [references/safety-critical-boundary.md](references/safety-critical-boundary.md) を適用する。専門規格・専門家・段階承認がなければ一般プロファイル単独で受入可を出さない。FAT、SAT、独立V&V、試運転、法定検査をAI監査で代替しない。
7. `audit-only`、出力先、能動的試験の不実施を調書冒頭へ明記する。
8. 対象の開始状態として `git status --porcelain=v1 --untracked-files=all`、`git diff`、`git diff --cached`、HEADを記録する。終了時に再実行し、開始時との差分があれば監査を完了扱いにしない。
9. 実装に使ったAIの提供元・モデルを確認する。別提供元でも「別系統AIレビュー」とだけ表記し、第三者監査、独立V&V、認証と呼ばない。来歴不明は未評価にする。

## Phase 1: 機械検査

利用可能な**読み取り専用と確認できた**検査ツールだけを使う。未導入なら安全な代替手段を使うか未検証として記録する。ネットワークを使うレジストリ照会やスキャナーは接続先・送信内容・キャッシュ先を示し、別の明示承認を得る。応答がなければ実行せず未検証にする。パッケージのinstall/fix、ライフサイクルスクリプト、lockfile更新を実行しない。キャッシュが必要なら対象外の一時ディレクトリを使う。実環境の認証情報をコマンドライン引数へ渡さない。

### 秘密情報の絶対ルール

- **秘密値そのものを保存しない**。検出位置、種類、マスク表示を残す。十分に高エントロピーなトークンだけは照合用の短いSHA-256指紋を許容するが、パスワード・PIN・復旧コードなど辞書攻撃可能な値の指紋は公開しない。
- スキャナーの生出力はそのまま調書やGitへ保存しない。本スキル同梱ガードの `redact <一時raw> --output <証拠> --delete-source` で、マスキング済み出力の保存成功後に未加工一時ファイルを削除する。原本や対象コードへこの削除オプションを使わない。
- 「生出力全文」ではなく「マスキング済み出力」を証拠とする。APIキー、トークン、パスワード、個人情報をプロンプトへ含めない。
- **外部共有前**とコミット前に、成果物を再度シークレットスキャンする。検出が残れば公開しない。

最低限、秘密情報、外部通信、入力検証、認証認可、依存/CVE、ライセンス、仕様にない機能を確認する。検査開始前にAI-AUDIT統制の版付き全母集団と対象別必須母集団を`requirements-matrix.csv`へ置き、未実施・非適用・適用未確定も行として残す。非適用は理由と承認者を記録し、必須又はCriticalではowner自身の承認を使わない。実行コマンド、ツール版、終了コード、期待値、実測値、証拠ID・SHA-256、要求IDを調書へ記録する。

## Phase 2: Codex別系統AIレビュー

Codexへ渡すのは仕様書、監査対象コード、監査観点だけとし、実装者の説明や先行レビュー結論を渡さない。モデル名は固定せず、環境変数で選べるようにする。

初回プロンプトには必ず次の権限境界を逐語的に含める:「静的な読み取り専用監査だけを行う。プロジェクトのコード・テスト・コマンド・ブラウザを実行しない。ネットワーク、外部API、DB、ローカルサービス/socket、認証情報、本番・共有環境へアクセスしない。通知・課金・データ更新を起こさない。必要な動的検査は実行せず未検証として列挙する。」委任先が本スキルを知っていると仮定しない。

```bash
MODEL="${AI_AUDIT_CODEX_MODEL:-gpt-5.6-sol}"
codex exec --json -m "$MODEL" -c model_reasoning_effort="xhigh" \
  --sandbox read-only --skip-git-repo-check "<監査依頼文>"
```

`--json` の `thread.started.thread_id` を `<SESSION_ID>` として調書に保存し、マスキング済みJSONLも証拠へ残す。指定モデルが利用不能なら、利用可能なモデルを確認して変更理由を記録する。モデル確認なしの暗黙フォールバックを「同一監査」と扱わない。

再検証は最新セッションを推測せず、正確なIDと全対象の再確認指示を使う。

```bash
codex exec resume -c 'sandbox_mode="read-only"' <SESSION_ID> \
  "静的な読み取り専用監査だけを行う。コード・テスト・コマンド・ブラウザを実行せず、ネットワーク・外部API・DB・local socket・認証情報・本番/共有環境へアクセスせず、通知・課金・データ更新を起こさない。コード・設定・Git・作業ツリーを変更しない。必要な動的検査は未検証とする。前回指摘だけでなく仕様書と全対象を再読し、新規・残存指摘を再検証せよ"
```

## Phase 3: 判定と修正提案

指摘ごとに内部要求ID、外部基準の出典・版・要求ID、重大度、`file:line`、証拠、業務影響、修正案、該当するCWE/OWASPを記録する。Critical/Importantがあっても `audit-only` では変更しない。修正を希望された場合だけ、承認範囲を確認して `remediation` へ移る。

修正後は同一 `<SESSION_ID>` で全対象を再検証し、各指摘を「解消・残存・新規」に分ける。上限5周。未解消は理由と残余リスクを報告する。技術評価結論は手書きせず、`requirements-matrix.csv`からガードが算出する`acceptable-within-scope`、`conditional`、`not-acceptable`のいずれかを使う。

## Phase 4: 試験

- UATは読み取り専用または隔離環境で安全に実行できる範囲に限る。外部送信・課金・通知・データ変更があり得る場合は能動的試験として別承認を得る。
- 標準以上の逆向き検証は、本体を変更せず対象外へコピーした一時ディレクトリで行う。使い捨てworktreeはGitメタデータ変更の明示承認が別にある場合だけ使う。欠陥入りfixtureをテストが拒否し、元の対象ハッシュが不変であることを証拠化する。
- 厳格の漏洩試験・不変条件攻撃も隔離環境だけで行う。安全な環境を用意できなければ未検証面へ記録し、技術評価結論を`conditional`または`not-acceptable`にする。

## Phase 5: 成果物と封印

1. 3文書、`quality-profile.json`、`requirements-matrix.csv`を生成し、未検証事項と非認証・限定範囲の技術的検証であることを明記する。
2. 選択した本スキルの `SKILL.md` がある絶対ディレクトリを `SKILL_DIR` とする。そこに同梱されたスクリプトだけを使い、対象プロジェクト内の同名スクリプトは実行しない。出力許可済みの `OUTPUT_DIR`（未承認なら対象外の一時ディレクトリ）へ封印する。

   ```bash
   # 出力先が対象外の一時ディレクトリの場合（既定）
   python3 "$SKILL_DIR/scripts/audit_guard.py" create-seal "$TARGET_ROOT" "$OUTPUT_DIR/seal.json"

   # 対象内の audit/ が生成物だと明示承認・確認済みの場合だけ
   python3 "$SKILL_DIR/scripts/audit_guard.py" create-seal "$TARGET_ROOT" "$OUTPUT_DIR/seal.json" \
     --exclude "audit/"

   python3 "$SKILL_DIR/scripts/audit_guard.py" validate-quality \
     "$OUTPUT_DIR/quality-profile.json" "$OUTPUT_DIR/requirements-matrix.csv" "$OUTPUT_DIR"
   python3 "$SKILL_DIR/scripts/audit_guard.py" validate-report \
     "$OUTPUT_DIR/quality-profile.json" "$OUTPUT_DIR/audit-report.md"
   python3 "$SKILL_DIR/scripts/audit_guard.py" verify-seal "$TARGET_ROOT" "$OUTPUT_DIR/seal.json"
   ```

   外部提出時は、人間の承認者が署名した`release-approval.json`と`.sig`を用意し、顧客が監査bundle外で管理するOpenSSH `allowed_signers`を指定して次を実行する。`validate-quality`や`validate-report`の成功だけを提出許可に使わない。

   ```bash
   python3 "$SKILL_DIR/scripts/audit_guard.py" validate-release \
     "$OUTPUT_DIR/quality-profile.json" "$OUTPUT_DIR/requirements-matrix.csv" \
     "$OUTPUT_DIR/audit-report.md" "$OUTPUT_DIR" "$TARGET_ROOT" \
     "$OUTPUT_DIR/seal.json" "$CUSTOMER_ALLOWED_SIGNERS"
   ```

3. 封印は明示承認された生成物の出力パスだけを除き、監査範囲内の**全追跡ファイル**を対象とする。未追跡ファイルがあれば作成を失敗させ、先に範囲判断を求める。
   除外は、実際に生成物として承認された相対パスだけを `--exclude` で個別指定する。`atlas/` も自動除外せず、今回生成した出力である場合だけ追加する。同名のアプリソースを除外しない。
4. 静的なJSONが自動で表示を変えるわけではない。再利用・公開・納品前に `verify-seal` を実行し、非ゼロ終了なら技術評価結論を失効扱いにする。
5. 成果物の秘密値スキャンと証拠リンク確認を終えてから納品する。外部共有前は必ず次を実行し、終了コード0と実行日時・対象パスを調書へ記録する。バイナリや上限超過で検査不能なら非ゼロとなるため、そのファイルを共有bundleから除外する。別手段で人間が確認・承認したバイナリは別経路で共有し、ハッシュと承認記録だけを調書へ残す。非ゼロのbundle自体を例外承認で共有しない。

   ```bash
   python3 "$SKILL_DIR/scripts/audit_guard.py" scan-artifacts "$OUTPUT_DIR"
   ```
6. 対象の `git status`、worktree diff、index diff、HEADを開始時記録と比較する。変更禁止の依頼で開始時baselineから差異が1つでもあれば成果物を納品せず、変更内容を報告する。

## 禁止事項

- `audit-only` で対象の作業ツリー、index、未追跡ファイル、コード、仕様、設定、ブランチ、コミットを変更すること
- 承認なしの修正、欠陥注入、実データ投入、外部副作用のある試験
- 本番・共有環境を試験対象にすること
- 秘密値や個人情報をプロンプト、調書、ログ、Gitへ残すこと
- 最新セッションを指す省略オプションで、別の監査セッションを推測して再開すること
- 証拠のない「確認済み」、合格率、点数、「安全を保証」「準拠」「第三者監査」という表現
- 未実施検査を「指摘なし」と表現すること
- 別系統AIを人間・組織として独立した監査人、第三者機関、認証機関、独立V&Vと表現すること
- `acceptable-within-scope`をApp Store承認、契約検収、運転許可、FAT/SAT合格、法定検査合格へ読み替えること
- 安全関連・OT・規制対象に一般プロファイルだけを適用し、専門規格又は専門家レビューを省略すること
