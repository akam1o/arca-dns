# arca-dns Contribution Guide

English | [日本語](contributing.ja.md)

This document explains how to contribute to the arca-dns project.

## Ways to Contribute

We welcome contributions such as:

- Bug reports
- Feature requests
- Documentation improvements
- Code improvements
- Additional tests

## Development Process

### 1. Create an issue

Open bug reports and feature requests in GitHub Issues.

**Bug report template**:

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

### 2. Create a branch

```bash
# Get the latest main
git checkout main
git pull origin main

# Create a feature branch
git checkout -b feature/my-feature
# or
git checkout -b fix/my-bugfix
```

### 3. Make changes

- Follow the existing code style.
- Add or update tests.
- Update documentation when behavior changes.

### 4. Commit

```bash
git add .
git commit -m "feat: add new feature"
# or
git commit -m "fix: correct zone update behavior"
```

**Commit message prefixes**:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Tests
- `refactor:` - Refactoring
- `chore:` - Other

## Developer Certificate of Origin (DCO)

To keep contributions easy for individuals and companies, we use a lightweight sign-off process.

By contributing, you agree that your work is submitted under the project license and that you have the right to submit it.

Please sign off your commits:

```bash
git commit -s
```

### 5. Push and open a Pull Request

```bash
git push origin feature/my-feature
```

Then open a Pull Request on GitHub.

## Code Review

### Pull Request checklist

- [ ] Code follows existing style
- [ ] Tests are added or updated
- [ ] Documentation is updated (as needed)
- [ ] No linter errors
- [ ] All tests pass

### Review focus

- Code quality
- Test coverage
- Performance impact
- Security impact
- Documentation completeness

## Coding Conventions

### Go guidelines

- Follow [Effective Go](https://go.dev/doc/effective_go)
- Format with `gofmt` (or `make fmt`)
- Use `golangci-lint` for quality checks (`make lint`)

### Naming

- **Packages**: lowercase, short
- **Types**: PascalCase
- **Functions**: PascalCase (exported), camelCase (unexported)

### Error handling

```go
if err != nil {
	return fmt.Errorf("context: %w", err)
}
```

### Logging

Use structured logging (zap):

```go
logger.Warn("Failed to create zone",
	zap.String("zone", zoneName),
	zap.Error(err))
```

## Testing

### Run tests

```bash
make test
```

### Run a specific package

```bash
go test ./internal/controller/api/...
```

## Linting

```bash
make install-tools
make lint
```

## Documentation

- `README.md` - project overview
- `docs/` - user/developer documentation
- `api/openapi.yaml` - API definition (source of truth)
- `docs/api.md` - human-friendly API guide

## License

Contributions are provided under the Apache License 2.0 (see `LICENSE`).
