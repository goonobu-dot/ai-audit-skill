# Changelog

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
