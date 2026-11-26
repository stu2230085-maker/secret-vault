# Secret Vault (`.vlt`)

Windows 向けの **秘密の金庫（暗号化コンテナ）アプリケーション** です。  
**Tauri v2 (Vite + TypeScript + Rust)** で構築し、**Antigravity Web** で開発、**GitHub Codespaces** で UI プレビューおよび Rust 単体テスト、**GitHub Actions** で Windows 用 `.exe` をビルドする構成を採用しています。

> [!NOTE]
> 現在このリポジトリは設計・ドキュメントフェーズです。実装は `AGENTS.md` のルールに従って段階的（Phase 1〜）に進めます。

---

## 主な特徴とセキュリティ設計

| 項目 | 仕様 |
| :--- | :--- |
| **暗号化方式** | **AES-256-GCM**（ファイル単位の個別暗号化・認証付き暗号） |
| **鍵導出関数** | **Argon2id** |
| **メモリ保護** | `zeroize` によるマスター鍵・復号バッファの確実なメモリ消去 |
| **オンメモリ復号** | ロック解除時は末尾の目次 JSON のみ復号し、ファイル閲覧時は一時ファイルをディスクに書き出さずオンメモリで復号 |
| **ブルートフォース対策** | 認証失敗時に **500ms** の強制待機 |
| **強制削除パスワード（自爆パス）** | 入力された瞬間にヘッダ＋全鍵スロット領域を暗号学的に安全なランダムデータで上書き破壊（クリプトシュレッディング）し、`fsync` 後にファイルを削除 |
| **自爆時の擬装モード** | 金庫作成時に「通常と同じパスワード誤り表示でとぼけるモード」または「空のダミー金庫を開くモード」を選択可能（通常パスと同一・酷似する自爆パスは登録拒否） |
| **領域最適化 (Compact)** | 削除済みファイルによって生じた空き領域を詰めてコンテナサイズを最適化 |
| **プレビュー隔離** | HTML / Markdown プレビューは必ず `sandbox=""` 属性付き `iframe` 内に隔離し、スクリプト実行と外部通信を完全遮断 |

---

## 独自暗号化ファイル仕様（`.vlt`）

`.vlt` ファイルは以下の **4ブロック構成** です。

```text
+-----------------------------------------------------------------------+
| 1. ヘッダ (8B)                                                        |
|    Magic "VLT1" (4B) | Version (u16) | Flags (u16)                    |
+-----------------------------------------------------------------------+
| 2. 鍵スロット領域 (固定4スロット・すべて同一サイズ)                   |
|    Slot 0..3: 通常パス用 / 自爆パス用 / 未使用ダミー (ランダム埋め)   |
+-----------------------------------------------------------------------+
| 3. データ本体領域 (追記型・ファイルごとに個別暗号化)                  |
|    [nonce (12B)][AES-256-GCM ciphertext] ...                         |
+-----------------------------------------------------------------------+
| 4. 末尾目次 ＋ ポインタ                                               |
|    暗号化済み目次 JSON (フォルダ階層・ファイル名・offset・len)        |
|    + 末尾 20B: [目次 offset (u64)][目次 len (u64)]["1TLV" (4B)]       |
+-----------------------------------------------------------------------+
```

- **スロット秘匿性**: 未使用スロットも暗号学的に安全なランダムバイトで埋め、バイナリ解析による「自爆パスの有無」の判別を困難にします。
- **高速なロック解除**: ファイル末尾 20B のポインタから目次領域のみを読み込んで復号するため、大容量コンテナでも高速に一覧表示できます。

---

## アーキテクチャ

```text
secret-vault/
├── .devcontainer/
│   └── devcontainer.json          # Codespaces (rust:1 + Node.js LTS, port 1420)
├── .github/
│   └── workflows/
│       └── build-windows.yml      # 手動実行 (workflow_dispatch) 専用 Windows .exe ビルド
├── src/                           # フロントエンド (Vanilla TypeScript + HTML/CSS)
│   ├── vaultClient.ts             # Tauri IPC 窓口の一本化 & ブラウザ用モックモード切替
│   ├── styles/
│   │   └── theme.css              # :root CSS変数集約 (初期テーマ: ミニマルダーク)
│   └── ...                        # ロック画面 / 2ペイン画面 (ツリー・検索・隔離プレビュー)
├── src-tauri/                     # バックエンド (Rust / Tauri v2)
│   ├── capabilities/              # Tauri v2 権限設定
│   ├── icons/                     # Windows ビルド用アイコン一式
│   └── src/
│       ├── commands.rs            # Tauri コマンド層（薄いラッパー）
│       └── vault/                 # Tauri 非依存の純粋暗号・コンテナコア
│           ├── mod.rs
│           ├── crypto.rs          # Argon2id / AES-256-GCM / zeroize
│           ├── format.rs          # .vlt 読み書き・目次管理・Compact
│           └── shred.rs           # 自爆パス検証・クリプトシュレッディング
├── AGENTS.md                      # AI エージェント開発ガイドライン
└── SPEC.md                        # (任意) 詳細仕様書
```

### ブラウザ単体プレビュー（モックモード）
`window.__TAURI_INTERNALS__` が存在しない環境（GitHub Codespaces のブラウザプレビュー等）では、`src/vaultClient.ts` が自動でモックモードに切り替わります。
- **通常パス**: `test` → ダミーの Markdown・HTML ファイルを含む金庫が開きます。
- **自爆パス**: `burn` → 自爆（クリプトシュレッディング）時の挙動を UI 上で確認できます。

---

## 開発・テスト・ビルド手順

### 1. GitHub Codespaces（開発・テスト・UI プレビュー）
1. Codespaces を起動すると `.devcontainer/devcontainer.json`（Rust + Node.js LTS）が自動構築され、ポート `1420` がフォワードされます。
2. コアエンジンの単体テストを実行：
   ```bash
   cd src-tauri && cargo test
   ```
3. フロントエンドのビルド確認・ブラウザ UI プレビュー：
   ```bash
   npm install
   npm run build
   npm run dev
   ```

### 2. GitHub Actions（Windows 用 `.exe` ビルド）
無料枠節約のため、自動トリガーは無効化し **`workflow_dispatch`（手動実行専用）** にしています。
1. GitHub リポジトリの **Actions** タブから **Build Windows** ワークフローを選択。
2. **Run workflow** をクリックして `windows-latest` 上で `tauri-apps/tauri-action@v1` を実行。
3. 完了後、Artifact（保持期間 7 日）から `src-tauri/target/release/bundle/nsis/*.exe` または `src-tauri/target/release/*.exe` をダウンロードして Windows 上で動作確認します。

---

## ロードマップ

- [x] **Phase 0**: リポジトリ初期化・`README.md` / `AGENTS.md` 整備
- [ ] **Phase 1**: 環境ファイル一式 + `.vlt` コアエンジン（暗号化・復号・自爆・Compact）+ 最小 2 ペイン UI + `cargo test` / `npm run build` 検証
- [ ] **Phase 2以降**: ファイルドラッグ＆ドロップ追加・フォルダ操作・パスワード変更・検索強化・テーマカスタマイズ拡張
