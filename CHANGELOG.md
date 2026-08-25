# Changelog

## 1.8.0 - 2026-08-25

3社会議(Claude・Codex・Grok独立)による「仕組みそのもの」の再監査で、別系統AIが**実装AIの見落とした欠陥を再現手順つきで検出**。複数ラウンドで修正・再監査し、回帰テストと機械ゲートを追加した。**注:再監査はラウンドごとにまだ新たな残穴を指摘しており(これ自体が独立監査に実利がある証拠)、本版は「既知欠陥を塞いだPreview」であって「全欠陥をクローズした」ものではない。**

- **[重大・修正]** `build-prompt-bundle` が `--output` 先の既存ディレクトリを無条件 `rmtree` しうるデータ消失リスクを修正。**このツールは既存ファイルを一切削除しない**——出力先は新規/空のディレクトリのみ許可し、非空の既存ディレクトリ・home/root・(語彙/解決後の)シンボリックリンクを拒否。失敗時も自ラン生成分のみ後始末する
- **[重大・修正]** 封印(seal)の除外リストを自己申告で信用していたため、全ソースを除外+空 `artifacts` の「空の封印」が `valid` になるバイパスを修正。除外は生成物dirのみ許可し、0ファイル封印を拒否(`create-seal`/`verify-seal` 両方)
- **[重大・修正]** 依存脆弱性スキャン(`scan-deps`)の fail-open を修正。空結果・`results`キー欠落・scanner異常終了を NOT-TESTED(exit 3)に、CVSSベクトルを数値評価(9.8=Critical等)、重大度不明はブロッキング扱い。CIの `|| true` を廃止しscanner失敗を伝播
- **[修正]** 非エンジニア向けサンプル `atlas/index.html` が旧コード(memo.py 111行時代)を「機械確認済み」と表示していた陳腐化を、現行(189行)へ再生成。生成物の整合を機械検査する `verify-atlas` を追加しCIに接続。`critical-review` は原理的盲点が残る限り緑(ok)にせず conditional で止めるよう判定を修正
- **[修正]** 送信前DLPを `external=True`(外部bundleに秘密の指紋を残さない)へ、台帳から端末の絶対パスを除き、宛先(`--destination`)・モデル(`--model`)を記録。`gate-commit` は gitleaks 不在時に「clean」と言わず NOT-TESTED を返し、`--strict` で exit 3
- **[整合]** AA-8.9(外部LLM送信)を「redact既定・高機密はallowlist・送信前に人間確認・網羅ではない」に改訂し実装と一致。統制数・版の表記を統一(54統制、v1.8)。能力・営業セクションの誇張(「唯一の現実解」「お約束」「安心」)を、観測された再現事例と工程記述へ置換。3体AI自己評価に「利害一致・参考値」の但し書きを明記
- **[テスト]** 上記バイパスの回帰テスト(`tests/test_review_fixes.py`)16件を追加

## 1.7.0 - 2026-08-25

各指摘に「発見の来歴(なぜ発見できたか)」を記録する仕組みを追加。3社会議(Claude・Codex・Grok独立)で設計を確定し、コードレビューの実証研究(Bacchelli&Bird, Edmundson, Mäntylä&Lassenius, Cisco/Cohen, Rigby&Bird)とAI企業の一次研究(LLM自己選好バイアス, Anthropic Sabotage/harness-design, OpenAI CriticGPT)で各項を接地。

- **references/discovery-provenance.md を追加**:監査の5観点(lens: contract/execution/exposure/authority/independence)のゴール定義、人が構造的に見落とす4型(story-trust/sampling/single-tool-trust/negative-evidence)、認知的独立性が発見できる機序(assumption-free/uniform-sweep/full-context/evidence-conflict/execution-proof)、AIが弱い点、findingごとの来歴スキーマ
- **報告書テンプレの指摘欄に来歴フィールド**(lens/why_found/human_blindspot/finder_class/reproduction)+発見の来歴サマリー(ai_cross件数の別掲)
- **SKILL.md Phase 3 に来歴の記録を必須化**
- 中核思想:「AIにしか見つけられない」でなく「認知的独立性(別系統・別手順・実行証拠が実装者の思い込みを共有しない)が破った見落とし」と正確に記述。`reproduction`の無い指摘は幻覚の疑いとして重大度を上げない。来歴の充実を安全の保証に読み替えない

## 1.6.0 - 2026-08-24

依存の脆弱性(SCA)とSBOMを、文書でなく機械で取る(P1)。読み取り検査であり実装能力を一切制限しない。

- `security_gate.py scan-deps`:osv-scanner(Apache-2.0)でlockfileの既知脆弱性を検査。Critical/Highで非ゼロ。実測で古いlodashのCRITICAL/HIGHを検出しブロックを確認。CI用に既存osv JSONを採点する `--results` も提供
- `security_gate.py gen-sbom`:syft(Apache-2.0)でCycloneDX SBOMを生成(監査bundleへ同梱・seal対象)
- **ツール未導入時は exit 3 = NOT-TESTED**(cleanと扱わない=正直な安全側)
- CIに osv-scanner(pinned container)を追加し、自リポの依存脆弱性を機械検査
- 回帰テスト+6(計74)。osv結果のパース・重大度判定・未導入経路をツール有無に依存せず固定

## 1.5.0 - 2026-08-24

セキュリティ・監視・監査の強化。3社会議(Claude・Codex・Grok独立)+OSS徹底調査で「現状は事後の証跡が強く、防止・機械強制が弱い」と一致。CodexとGrokが独立に最優先で挙げた「入口の機械ゲート」を実装。文書だけだった防御を実際に動くコードにした。

- **security_gate.py を新設(機械の入口ゲート2種)**
  - `build-prompt-bundle`:外部LLM(Codex/Grok等)へコードを渡す前の送信前DLP。既定の redact モードは**全文脈を送りつつ秘密・PIIをマスク**(外部AIの能力を落とさず漏洩を防ぐ)。allowlist モードは許可パスのみ。秘密がredactを生き延びたら bundle を作らず fail-close。送信内容を transmission-ledger.json に台帳化。出力は0700/0600
  - `gate-commit`:コミット前ゲート。gitleaks(あれば)+パターンの**両方**を走らせ、どちらかが秘密を見つけたら非ゼロで停止(両者は取りこぼす対象が異なるため union が安全 — 実測でハイフン付きトークンをgitleaksが見逃しパターンが捕捉)。PIIは誤検知回避のため警告のみ
- **pre-commit 雛形を同梱**(templates/pre-commit-config-template.yaml):gitleaks + 同梱 gate-commit
- **CIで実際にスキャナを実行**:validate.yml に gitleaks(全履歴、.gitleaks.toml準拠)を追加。「文書だけ」を機械強制へ
- 回帰テスト+9(計68 guard/gateテスト)。PII赤字化はexample.com等を除外する保守的パターン
- OSS調査の成果を security-brushup-synthesis.md に記録:採用候補(osv-scanner/syft/trivy/guarddog、いずれもApache-2.0・オフライン可)と、避けるべきもの(CodeQL=非公開コード有料、npm audit/ggshield=外部送信、Falco/Wazuh=個人に過剰)を一次確認。SCA/SBOM機械接続はP1として次段へ

## 1.4.0 - 2026-08-10

非エンジニアが「全部を理解する」のでなく「事故のほぼ全てが通る急所だけを自分で検証する」ための code-atlas critical-review モードを追加。3社会議(Claude・Codex・Grok独立評価)で設計を確定。

- code-atlas に critical-review モードを追加:急所6カテゴリ(外部送信/高影響な外部作用/機密・個人データのライフサイクル/権限境界/異常時の安全動作/供給網)+禁止事項の横串を、非エンジニアが「許可/禁止/不明」を判断できる検証カードとして提示する静的HTMLを生成
- theater(見せかけ)回避の設計憲法を references/critical-review.md に明文化:found(発見)とcoverage(解析範囲)の分離、緑バッジ単独禁止、盲点(ネイティブ呼び出し・eval・動的import等)の赤での強制開示、根拠を開くまで許否選択不可、不明が残れば非緑、網羅を主張しない
- 実証サンプル examples/memo-tool/critical-review/index.html:実コード(ctypes ネイティブ呼び出しの盲点を含む)に対し、全根拠行の実在・通信API不在を機械確認済み。検証結論ゲート(未回答/不明/禁止が残れば緑にしない)の状態遷移を検証
- 位置づけ:前バージョンの「出荷ゲート(読まずに止める)」の対になる「急所だけ読む(能動確認)」。両者の二層で「証跡=麻酔」を破る

## 1.3.1 - 2026-08-10

3体のAI(Claude・Codex・Grok)の再レビューで、v1.3の改善が「基準・文書には書かれたが機械ゲートに接続されていない」という不一致が判明。CodexとGrokが独立に同じ3点を指摘し、それを修正。

- **外部提出ゲートの指紋除去を接続**:`validate_external_release`が`scan_artifacts`を`external=True`なしで呼んでおり、v1.3で追加した指紋除去が外部提出時に効いていなかった。最も指紋を出してはいけない経路での抜けを修正
- **v1.3統制を機械ゲートへ同期**:基準にAA-8.9を追加したが必須母集団(`AUDIT_CONTROL_IDS`)がAA-8.8止まりで、AA-8.9欠落のマトリクスが完全性検査を通っていた。母集団をAA-8.9まで拡張し、内部版・プロファイル版を1.3.0へ統一。`expected_inventories`のAI-AUDIT版番号を`CORE_STANDARDS`から導出し、版ドリフトを再発防止
- **実施者≠承認者を機械検証**:AA-8.8は別人を要求していたが宣言のみで、自己承認が通っていた。承認記録・ゲートに`audit_performer_identity`を追加し、`reviewer_identity`と同一なら拒否。署名対象へも束ねる
- 回帰テスト+1(自己承認拒否)、計59 guardテスト

## 1.3.0 - 2026-08-09

3体のAI(Claude・Codex・Grok)による独立レビューで見つかった弱点を反映。3者が独立に「外部審査到達度3/5」と評価し、その差分を埋める改修。

- 秘密検出を拡張:`refresh_token`・`db_password`・`connection_string`・`session_id`等、下線で連結された秘密キーワードの取りこぼしを修正(専用スキャナ未導入時は結論を`conditional`以下に固定する運用を明記)
- `redact --external` / `scan-artifacts --external` を追加:外部提出bundleではSHA-256指紋も出さず、位置・種別のみとする
- `redact --delete-source` にパスガード:システム一時ディレクトリ配下・非symlinkの原rawのみ削除可。誤指定による原本破壊を防止
- `redact` 出力を0600・原子的書き込みに変更(平文の world-readable 残存とクラッシュ時の部分ファイルを防止)
- `scan-artifacts` をsymlink非追従・読込前サイズ判定へ:リンク経由の対象外ファイル混入と巨大ファイル一括読込を防止
- 監査基準に追加:機械検査の隔離実行(通信遮断・RO・設定無効化)、外部LLM送信前DLP(分類済みallowlist・送信内容の台帳化)、プロンプトインジェクション対策(対象内文書を指示として扱わない)、外部提出での実施者≠承認者の署名分離
- 回帰テスト7件追加(計58 guardテスト)

## 1.2.0 - 2026-08-07

- 規格名・版・適用レベルを固定する `quality-profile.json` を追加
- 要求IDから検証方法・証拠・結果・未解決事項を追跡する `requirements-matrix.csv` を追加
- ISO/IEC 25010:2023、ISO/IEC/IEEE 29119-2/-3:2021、NIST SSDF v1.1を共通軸に整理
- iOS向けにOWASP MASVS v2.1.0、Apple Privacy Manifest、Entitlements、署名・配布成果物の検査を追加
- 必須未試験・重大不合格を見逃さない決定論的な技術評価結論ゲートを追加
- AI-AUDIT 53統制、ISO品質9特性、iOSのMASVS 24統制・Apple検査群の完全性照合を追加
- 非適用の別承認者、期待値・実測値、非空証拠、Evidence ID・SHA-256検証を追加
- 元要求IDの重複と証拠ID・パス・ハッシュの要求間使い回しを拒否
- Markdown報告書の結論・禁止保証表現を機械可読プロファイルと照合するゲートを追加
- 外部提出前の人間による意味レビューと、顧客管理OpenSSH公開鍵で承認記録・監査bundle・sealを結ぶ`validate-release`を追加
- 安全関連・OT・規制対象を一般IT監査だけで承認しない強制停止境界を追加
- 認証・第三者保証と誤認されうる表現を限定範囲の技術的検証へ変更

## 1.1.0 - 2026-08-07

- 既定の読み取り専用 `audit-only` と、明示承認が必要な修正・能動試験を分離
- 秘密値マスキングと公開前検査を追加
- 全監査対象ファイルを検証するseal v2とCLIを追加
- 正確なCodexセッションIDによる再検証へ変更
- 再現可能なサンプル証拠、受入テスト、逆向き検証を追加
- 最小権限・SHA固定のGitHub Actions検証を追加
