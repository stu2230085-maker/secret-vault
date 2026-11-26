# AGENTS.md — AI Coding Agent Guidelines

このドキュメントは、本リポジトリ（**Secret Vault `.vlt`**）で開発・テスト・保守を行う AI エージェント向けの設計原則・制約・検証ルールを定義します。

---

## 1. 開発ワークフローと基本方針

- **環境前提**:
  - 開発: Antigravity Web / Linux サンドボックス
  - テスト・UI プレビュー: GitHub Codespaces（`cargo test` + Vite ブラウザプレビュー）
  - Windows `.exe` ビルド: GitHub Actions（`windows-latest`, `workflow_dispatch` 手動実行のみ）
- **コード品質**:
  - 重複ロジックを作らず、共通処理はヘルパーへ切り出す。
  - 既存のコメント・docstring は変更に関係ない限り保持する。
  - リポジトリ作業ディレクトリをテスト用の一時ファイルや `.vlt` 生成物で汚さない。
- **Git / コミット運用**:
  - `main` ブランチへ反映・マージする際は、1つの大きなコミットにまとめず、機能・レイヤー・変更目的ごとに**小分けのコミット**に分割すること。

---

## 2. アーキテクチャ境界（厳守）

### バックエンド (`src-tauri/`)
1. **純粋コアモジュールの分離**:
   - 暗号化・`.vlt` フォーマット解析・自爆ロジックは必ず `src-tauri/src/vault/` 配下（`crypto.rs`, `format.rs`, `shred.rs` 等）に実装する。
   - `vault/` モジュールは **Tauri (`tauri::Window`, `tauri::AppHandle`, `tauri::State` 等) に一切依存してはならない**。これにより Linux/Codespaces 上で GUI なしに `cargo test` を完結させる。
2. **コマンド層の薄さ**:
   - `src-tauri/src/commands.rs` はフロントエンドからの IPC 受け口とエラーシリアライズに徹し、ビジネスロジックを持たせない。

### フロントエンド (`src/`)
1. **IPC 窓口の一本化**:
   - `@tauri-apps/api` の呼び出しを各画面やコンポーネントに散らばらせず、**必ず `src/vaultClient.ts` に一本化**する。
2. **自動モックモード**:
   - `src/vaultClient.ts` は `window.__TAURI_INTERNALS__` の有無を判定し、不在時（Codespaces のブラウザ等）は自動でインメモリモックモードに切り替えること。
   - モックモードの仕様:
     - 通常パスワード `test`: ダミーの Markdown および HTML を含む金庫を開く。
     - 自爆パスワード `burn`: 自爆挙動（選択中の擬装モードに応じた応答・金庫破棄）を再現する。
3. **軽量フロントエンド & テーマ集約**:
   - 重い UI フレームワークは導入せず、素の HTML / CSS / TypeScript で構成する。
   - 色・余白・フォント・角丸などのデザイントークンはすべて `src/styles/theme.css` の `:root` CSS 変数に集約する（初期テーマは落ち着いたミニマルダーク）。

---

## 3. `.vlt` フォーマット & セキュリティ不変条件

実装・変更時は以下のセキュリティ要件を絶対に損なわないこと：

1. **4ブロック構造**:
   - ヘッダ (8B): Magic `"VLT1"` (4B) + Version (`u16`) + Flags (`u16`)
   - 鍵スロット領域: 固定 4 スロット（すべて同一バイト長）。未使用スロットも暗号学的に安全な乱数で埋め、自爆スロットの存在を推測させない。
   - データ本体領域: 追記型。ファイルごとに `[nonce (12B)][AES-256-GCM ciphertext]` で個別暗号化。
   - 末尾目次＋ポインタ: 暗号化された目次 JSON + 末尾 20B `[目次 offset (u64)][目次 len (u64)]["1TLV"]`。
2. **暗号アルゴリズムと鍵管理**:
   - 暗号化: **AES-256-GCM**、鍵導出: **Argon2id**。
   - マスター鍵・スロット鍵・平文バッファは `zeroize` クレートを用いてドロップ時に確実にゼロクリアする。
   - 復号は **オンメモリのみ** とし、平文の一時ファイルをディスクへ絶対に書き出さない。
3. **強制削除（自爆）とブルートフォース対策**:
   - 自爆パスワード入力時は、ヘッダ＋全鍵スロット領域を暗号学的に安全な乱数で上書き破壊し、`fsync`（`sync_all()`）を実行してからファイルを削除する。
   - 金庫作成時に「通常と同じ誤り表示でとぼけるモード」と「空のダミー金庫を開くモード」を選択可能にする。
   - 通常パスワードと同一・または酷似（大文字小文字違い、前後空白、編集距離が極端に小さい等）する自爆パスワードの登録は拒否する。
   - 認証失敗時はブルートフォース対策として **500ms** 待機する。
4. **Compact（領域最適化）**:
   - 削除済みエントリの空き領域を詰め、目次と末尾ポインタを整合性を保ったまま再構築できるようにする。
5. **UI プレビュー隔離**:
   - HTML / Markdown プレビューを描画する際は、必ず `sandbox=""` 属性を付与した `iframe`（`srcdoc` 等）内に隔離し、JavaScript 実行および外部ネットワーク通信を遮断する。

---

## 4. ビルド・CI 構成ルール

- **`.devcontainer/devcontainer.json`**:
  - `mcr.microsoft.com/devcontainers/rust:1` ベース、Node.js LTS 追加、ポート `1420` フォワード。
- **`.github/workflows/build-windows.yml`**:
  - トリガーは `workflow_dispatch` のみ（無料枠節約）。
  - `windows-latest` 上で `swatinem/rust-cache@v2` と `tauri-apps/tauri-action@v1` を使用。
  - `src-tauri/target/release/bundle/nsis/*.exe` および `src-tauri/target/release/*.exe` を Artifact（保持 7 日）としてアップロード。
- **Tauri v2 ビルドエラー防止**:
  - `src-tauri/capabilities/` の権限設定と `src-tauri/icons/` のアイコン一式（Windows `.ico` 含む）を必ず揃えてからビルド検証を行う。

---

## 5. 完了条件（検証ゲート）

コード変更を行った際は、報告前に必ず以下を自分で実行・確認すること：

1. `src-tauri` にて `cargo test` を実行し、全テストがパスすること（必ず `tempfile` 等の一時ディレクトリを使用し、リポジトリを汚さないこと）：
   - 金庫新規作成
   - ファイル追加
   - 末尾目次復号
   - 個別オンメモリ復号
   - 誤パスワード拒否（および 500ms 待機・自爆挙動）
   - 自爆パスによるヘッダ／鍵スロット破壊＆ファイル削除
   - Compact による空き領域最適化
2. ルートディレクトリにて `npm run build` がエラーゼロで完了すること。
