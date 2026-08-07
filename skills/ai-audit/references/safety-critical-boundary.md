# Safety-Critical / OT Boundary

## 強制停止ゲート

人命、健康、環境、発電・製造設備、保護機能、制御出力、規制対象業務に影響する場合、一般プロファイル単独で`acceptable-within-scope`を出さない。`target_types`へ`safety-related`、`ot`又は`regulated`を設定し、次を必須にする。

1. 適用法令・安全分類・設備境界・制御出力・安全側状態を人間が確定する。
2. `sector_overlays`へ購入・確認済みの分野固有規格を版付きで登録する。
3. `specialist_review_required=true`とし、専門家の力量・組織的独立性・利益相反・役割を記録する。
4. 法定検査、規制承認、独立V&V、FAT、SAT、試運転、本運用移行をAIレビューで代替しない。

`quality-profile.json`には`sector_gate`を置く。未完了なら次のように停止理由を明示する。

```json
{
  "sector_gate": {
    "status": "blocked",
    "blocking_reasons": ["適用法令と安全分類が未確定"]
  },
  "technical_conclusion": "not-acceptable"
}
```

各`sector_overlays`には、専門家が確定した`requirement_catalog`、`catalog_approver`、`catalog_evidence`、`catalog_evidence_sha256`を置く。ガードはカタログとマトリクスの要求ID集合を完全一致させる。規格本文そのものを公開せず、許諾に従った要求ID索引と承認記録を証拠化する。

`status=complete`を使えるのは、`hazard_traceability_evidence`、`configuration_baseline_evidence`、`verification_plan_evidence`、`independent_review_evidence`、`stage_approval_evidence`を別ファイルで記録し、各ファイルのSHA-256を`evidence_sha256`へ置き、`supplier_organization`、`independent_reviewer`、`reviewer_organization`、`responsible_approver`を明記した場合だけとする。レビュー組織と供給者組織が同一ならガードは拒否する。これは証拠の存在・分離・同一性ゲートであり、法的・技術的妥当性は権限を持つ人間が判断する。

安全関連・OT・規制対象では、本ツールの最良結論を`conditional`に制限する。これは「技術検証上の未解決条件がある」という意味であり、運転・試運転・規制・契約上の承認は別の権限者が行う。

前提を確定できない場合は`not-acceptable`とし、要求定義前のギャップ分析だけを提出する。

## 必須の追跡連鎖

`Hazard ID → Safety Goal → Requirement ID → Design Item → Test ID → Evidence ID/hash → Result → Deviation → Residual Risk → Stage Approval`

最低限、次を品質要求仕様書とマトリクスに持たせる。

- 危害、原因、頻度・重大度、想定運転状態、設備境界
- 安全機能、安全側状態、決定論的応答時間、インターロック、バイパス・リセット条件
- 単一故障、共通要因故障、冗長性、多様性、分離、縮退・手動代替
- 試験前提、構成基準、手順版、期待値、実測値、測定器・校正、実施者・立会者
- 不適合、根本原因、是正、再試験、残余リスク、期限、所有者
- PLCロジック、FPGA、ファームウェア、設定値、I/O、配線、型式・製造番号、更新媒体、保守ツールを含む構成管理

## 分野固有規格の例

以下は適用候補であり、対象設備・法域・契約によって人間が選定する。

- 原子力I&C: IEC 61513:2026、IAEA SSG-39、国内規制要求
- プロセス産業SIS: IEC 61511-1:2016+AMD1:2017、基礎規格IEC 61508系列
- 産業用制御製品のセキュア開発: IEC 62443-4-1:2018。運用者・統合者には別パート・別要求が必要

規格名の記載だけで適合を主張しない。規格本文の利用許諾を守り、要求ID、適用判断、証拠、独立確認をマトリクスへ記録する。

## 段階別承認

- 設計レビュー受入
- FAT受入
- SAT・据付後試験受入
- 試運転移行承認
- 本運用移行承認
- 規制・法定検査

報告書の技術評価結論は、これらの承認を自動的に付与しない。供給者、設計責任者、独立V&V、設備所有者、運転責任者、規制担当を分けて記録する。
