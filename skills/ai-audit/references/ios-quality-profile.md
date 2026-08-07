# iOS Quality Profile v1.2

`target_types`に`ios`がある場合に必須。ソースだけを見て「iOSセキュリティ適合」と結論しない。

## 必須の参照元

| source_id / 版 | 用途 | 公式情報 |
|---|---|---|
| `OWASP-MASVS` / `2.1.0` | モバイルアプリのセキュリティ要求 | https://mas.owasp.org/MASVS/ |
| `APPLE-APP-REVIEW` / `current` | 審査・安全・プライバシー要件 | https://developer.apple.com/app-store/review/guidelines/ |
| `APPLE-PRIVACY-MANIFEST` / `current` | PrivacyInfo.xcprivacyとRequired Reason API | https://developer.apple.com/documentation/bundleresources/privacy-manifest-files |
| `APPLE-PLATFORM-SECURITY` / `current` | ATS、Keychain、署名、サンドボックス等 | https://developer.apple.com/security/ |

Apple文書は固定版番号がないため、`retrieved_at`を必ず記録する。App Store Connectの申告内容は認証情報を公開証拠へ含めず、マスキング済みエクスポート又は人間による照合記録を残す。

## MASVSの対象群

`requirements-matrix.csv`では、使用したOWASP公式チェックリストの各要求IDをそのまま`source_requirement`へ記録する。少なくとも次の群について、適用・非適用・未確定を行単位で残す。

- `MASVS-STORAGE`: 端末内の機密データ
- `MASVS-CRYPTO`: 暗号と鍵管理
- `MASVS-AUTH`: 認証・認可
- `MASVS-NETWORK`: 通信路
- `MASVS-PLATFORM`: iOS機能・他アプリとの連携
- `MASVS-CODE`: コード品質、更新、入力処理
- `MASVS-RESILIENCE`: 解析・改ざん耐性。脅威モデルに基づき適用判断
- `MASVS-PRIVACY`: データ最小化、透明性、ユーザー制御

ガードはv2.1.0公式配布物にある全24 control IDを母集団として保持し、欠落IDと架空IDを拒否する。`verified`を使えるのは24行すべてが存在し、適用未確定・適用要求の未試験がない場合だけである。非適用行も削除せず、理由と承認者を記録する。

旧L1/L2/RやASVSのレベルを、本スキルの簡易・標準・厳格と読み替えない。

## 検証深度を4段階で明示

| 深度 | 必要証拠 | 言えること |
|---|---|---|
| source | Swift/設定/依存の静的確認 | ソース範囲の技術検証のみ |
| archive | `.xcarchive`又はIPA、署名・Entitlements・統合Manifest・ハッシュ | 納品候補artifactとの一致を追加確認 |
| device | 承認済み隔離端末でのMASTG相当試験 | 実行時挙動の範囲を追加確認 |
| store | App Store Connect申告と提出artifactの人間照合 | 提出情報との整合を追加確認。Appleの承認保証ではない |

`archive`未実施ならIPA・署名・統合Privacy Manifestを未検証とする。`device`未実施なら動的検査を未検証とする。

## 最低限の要求群

1. Xcode project/workspace、scheme、target、configuration、bundle ID、deployment targetを列挙する。
2. app、extension、embedded framework/SDKごとに`PrivacyInfo.xcprivacy`を検出し、許可キーだけで構成されることを確認する。
3. `NSPrivacyTracking`、tracking domains、収集データ、linked/tracking/purpose、Required Reason APIとreason codeをコード・依存・申告で突合する。
4. Entitlements、Info.plist、ATS例外、Keychain groups、Associated Domains、Background Modes、URL scheme/deep link、WebView、pasteboard、通知権限を必要最小限で確認する。
5. Keychain、Data Protection、LocalAuthentication、TLS/ATSの利用を確認する。独自暗号を安易に認めない。
6. `Package.resolved`、Podfile.lock等とXCFramework/SDKを含む依存・ライセンス・既知脆弱性を確認する。
7. archive/IPAのTeam ID、署名、provisioning、Entitlements、Privacy Manifest、SHA-256を記録し、ソース監査対象との対応を示す。
8. App Store privacy answers、プライバシーポリシー、アプリ実態、第三者SDKの挙動を照合する。

Apple資料は固定の要件番号を提供しないため、本プロファイルが版管理する内部ID（App Review 2件、Privacy Manifest 3件、Platform Security 4件）を全数行として要求する。各行にはsource/archive/device/storeのどこまで確認したかを`coverage_scope`、試験方法、期待値・実測値、証拠hashで示す。

Appleの技術要件との整合確認と、個人情報保護法等への法的適合判断は分離する。法的判断は有資格者・法務担当へ引き継ぐ。
