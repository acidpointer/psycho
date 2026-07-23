# Git Commit Messages Guidelines

## Commit Message Structure

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Required Parts

**Type** - the type of change:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes that don't affect functionality (whitespace, semicolons, etc.)
- `refactor`: Code refactoring without changing functionality
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Changes to build process, dependencies, config, etc.
- `ci`: Changes to CI/CD configuration

**Scope** (optional) - the area of change:
- Name of the module, package, or component
- Examples: `auth`, `payment`, `database`, `api`, `iam-engine`

**Subject** - brief description:
- Use imperative mood: "add" instead of "added" or "adds"
- Don't capitalize the first letter
- No period at the end
- Maximum 50 characters
- Answers the question "what does this do?"

### Optional Parts

**Body** - detailed description (leave a blank line before the body):
- Explain WHAT you changed and WHY
- Don't describe HOW (that's visible in the code)
- Wrap lines at ~72 characters
- Separate logical blocks with blank lines

**Footer** - additional information:
- Issue references: `Closes #123`, `Fixes #456`, `Relates to #789`
- Breaking changes: `BREAKING CHANGE: description`

## Examples

### Simple change
```
feat(auth): add JWT token validation
```

### With detailed description
```
feat(payment): implement Stripe webhook handling

Add comprehensive webhook signature validation and idempotency handling
for Stripe payment events. Process payment_intent.succeeded events
through the payment service with proper error handling and retry logic.

- Validate webhook signatures using Stripe secret
- Store webhook event IDs to prevent duplicate processing
- Handle timeouts and network errors gracefully
- Log all webhook interactions for audit trail

Closes #234
```

### Bug fix
```
fix(blockchain): handle Ethereum client failover on connection timeout

When primary RPC endpoint becomes unresponsive, automatically switch
to backup endpoint. Restore primary endpoint after successful health check.

Previous behavior caused requests to hang indefinitely.

Fixes #567
```

### Refactoring
```
refactor(iam-engine): split policy evaluation into smaller functions

Extract permission checking and field access logic into separate functions
following single responsibility principle. Improves testability and
maintainability without changing external behavior.

No breaking changes.
```

### Documentation
```
docs: update setup instructions for PostgreSQL

Add environment variable examples and explain schema migration process.
Include troubleshooting section for common connection issues.
```

## Rules and Best Practices

### ✅ Do this:
- Use present tense: "add feature" not "added feature"
- Write about what the commit does, not how you wrote it
- Group logically related changes in one commit
- Make commits frequent enough but meaningful
- Review the diff before committing: `git diff` and `git diff --cached`

### ❌ Don't do this:
- Don't mix unrelated changes (refactoring + feature)
- Don't write generic messages: "update", "fix", "changes"
- Don't commit garbage: debug code, commented code, temporary files
- Don't forget about capitalization and punctuation in body text
- Don't make very large commits - break them into logical parts
