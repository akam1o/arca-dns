# arca-dns コントリビューションガイド

[English](contributing.md) | 日本語

このドキュメントは、arca-dns プロジェクトへの貢献方法を説明します。

## コントリビュートの方法

以下のような貢献を歓迎します。

- バグ報告
- 機能要望
- ドキュメント改善
- コード改善
- テスト追加

## 開発プロセス

### 1. Issue を作成する

バグ報告や機能要望は GitHub Issues に起票してください。

**バグ報告テンプレート**:

```markdown
## Bug Description
Describe the bug concisely.

## Steps to Reproduce
1. ...
2. ...
3. ...

## Expected Behavior
What should happen?

## Actual Behavior
What actually happened?

## Environment
- OS:
- Go version:
- arca-dns version:
```

### 2. ブランチを作成する

```bash
# Get the latest main
git checkout main
git pull origin main

# Create a feature branch
git checkout -b feature/my-feature
# or
git checkout -b fix/my-bugfix
```

### 3. 変更を加える

- 既存のコードスタイルに従ってください。
- テストを追加または更新してください。
- 挙動が変わる場合はドキュメントも更新してください。

### 4. コミット

```bash
git add .
git commit -m "feat: add new feature"
# or
git commit -m "fix: correct zone update behavior"
```

**コミットメッセージの prefix**:

- `feat:` - 新機能
- `fix:` - バグ修正
- `docs:` - ドキュメント
- `test:` - テスト
- `refactor:` - リファクタリング
- `chore:` - その他

## Developer Certificate of Origin（DCO）

個人・企業ともに参加しやすくするため、軽量な sign-off プロセスを採用しています。

コントリビュートすることで、あなたの作業はプロジェクトライセンスの下で提供され、提出する権利を持つことに同意したものとみなします。

コミットに sign-off を付与してください。

```bash
git commit -s
```

### 5. Push して Pull Request を作成する

```bash
git push origin feature/my-feature
```

その後 GitHub 上で Pull Request を作成してください。

## コードレビュー

### Pull Request チェックリスト

- [ ] 既存スタイルに沿っている
- [ ] テストが追加/更新されている
- [ ] （必要に応じて）ドキュメントが更新されている
- [ ] Lint エラーがない
- [ ] テストがすべて通る

### レビューの観点

- コード品質
- テストカバレッジ
- 性能への影響
- セキュリティへの影響
- ドキュメントの充実度

## コーディング規約

### Go ガイドライン

- [Effective Go](https://go.dev/doc/effective_go) に従ってください
- `gofmt`（または `make fmt`）で整形してください
- 品質チェックに `golangci-lint` を利用してください（`make lint`）

### 命名

- **packages**: 小文字、短く
- **types**: PascalCase
- **functions**: PascalCase（exported）、camelCase（unexported）

### エラーハンドリング

```go
if err != nil {
	return fmt.Errorf("context: %w", err)
}
```

### ロギング

構造化ログ（zap）を利用します。

```go
logger.Warn("Failed to create zone",
	zap.String("zone", zoneName),
	zap.Error(err))
```

## テスト

### テスト実行

```bash
make test
```

### 特定パッケージだけ実行

```bash
go test ./internal/controller/api/...
```

## Lint

```bash
make install-tools
make lint
```

## ドキュメント

- `README.md` - プロジェクト概要
- `docs/` - ユーザ/開発者向けドキュメント
- `api/openapi.yaml` - API 定義（source of truth）
- `docs/api.ja.md` - 人が読みやすい API ガイド（日本語）

## ライセンス

コントリビューションは Apache License 2.0 の下で提供されます（`LICENSE` を参照）。
