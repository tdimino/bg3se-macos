---
name: osgrep-reference
description: Comprehensive CLI reference and search strategies for osgrep semantic code search. Use for detailed CLI options, index management commands, search strategy guidance (architectural vs targeted queries), and troubleshooting. Complements the osgrep plugin which handles daemon lifecycle.
version: 0.5.16
last_updated: 2025-12-09
allowed-tools: "Bash(osgrep:*), Read"
---

# osgrep: Semantic Code Search

## Overview

osgrep is a natural-language semantic code search tool that finds code by concept rather than keyword matching. Unlike `grep` which matches literal strings, osgrep understands code semantics using local AI embeddings.

**Version 0.5.x highlights:**
- V2 architecture with improved performance (~20% token savings, ~30% speedup)
- Call graph tracing with `osgrep trace "function_name"`
- Role detection (ORCHESTRATION vs DEFINITION)
- Skeleton generation with `osgrep skeleton`
- Symbol listing with `osgrep symbols`
- Go, Rust, Java, C#, Ruby, PHP language support
- `--reset` flag for clean re-indexing
- ColBERT reranking for better result relevance
- Separate "Code" and "Docs" index channels
- Tree-sitter-based chunking by function/class boundaries
- Per-repository indexes stored in `.osgrep/` within each repo root

**When to use osgrep:**
- Exploring unfamiliar codebases ("where is the auth logic?")
- Finding conceptual patterns ("show me error handling")
- Locating cross-cutting concerns ("all database migrations")
- User explicitly asks to search code semantically

**When to use traditional tools:**
- Searching for exact strings or identifiers (use `Grep`)
- Finding files by name pattern (use `Glob`)
- Already know the exact location (use `Read`)

## Quick Start

### Basic Search

```bash
osgrep "your semantic query"
osgrep "your query" path/to/scope    # Scope to subdirectory
```

**Examples:**
```bash
osgrep "user registration flow"
osgrep "webhook signature validation"
osgrep "database transaction handling"
osgrep "how are plugins loaded" packages/src
```

### Output Format

Returns: `path/to/file:line [Tags] Code Snippet`

- `[Definition]`: Semantic search detected a class/function here. High relevance.
- `...`: **Truncation marker**. Snippet is incomplete (max 16 lines)—use `Read` for full context.

## Search Strategy

### For Architectural/System-Level Questions

Use for: auth, integrations, file watching, cross-cutting concerns

1. **Search broadly first** to map the landscape:
   ```bash
   osgrep "authentication authorization checks"
   ```

2. **Survey the results** - look for patterns across multiple files:
   - Are checks in middleware? Decorators? Multiple services?
   - Do file paths suggest different layers (gateway, handlers, utils)?

3. **Read strategically** - pick 2-4 files that represent different aspects:
   - Read the main entry point
   - Read representative middleware/util files
   - Follow imports if architecture is unclear

4. **Refine with specific searches** if one aspect is unclear:
   ```bash
   osgrep "session validation logic"
   osgrep "API authentication middleware"
   ```

### For Targeted Implementation Details

Use for: specific function, algorithm, single feature

1. **Search specifically** about the precise logic:
   ```bash
   osgrep "logic for merging user and default configuration"
   ```

2. **Evaluate the semantic match**:
   - Does the snippet look relevant?
   - If it ends in `...` or cuts off mid-logic, **read the file**

3. **One search, one read**: Use osgrep to pinpoint the best file, then read it fully.

## CLI Reference

### Search Options

**Control result count:**
```bash
osgrep "validation logic" -m 20           # Max 20 results total (default: 25)
osgrep "validation logic" --per-file 3    # Up to 3 matches per file (default: 1)
```

**Reset index during search:**
```bash
osgrep "validation logic" -r              # Reset index and re-index from scratch before searching
```

**Output formats:**
```bash
osgrep "API endpoints" --compact           # File paths only
osgrep "API endpoints" --content           # Full chunk content (not just snippets)
osgrep "API endpoints" --scores            # Show relevance scores
osgrep "API endpoints" --plain             # Disable ANSI colors
```

**Sync before search:**
```bash
osgrep "validation logic" -s               # Sync files to index before searching
osgrep "validation logic" -d               # Dry run (show what would sync)
```

### Index Management

```bash
osgrep index                    # Incremental update
osgrep index --reset            # Full re-index from scratch (v0.4.6+)
osgrep index -p /path/to/repo   # Index a specific directory
osgrep index --dry-run          # Preview what would be indexed
```

### Call Graph Tracing

```bash
osgrep trace "function_name"    # Show upstream/downstream dependencies
osgrep symbols                  # List all symbols in the codebase
```

### Skeleton Generation

```bash
osgrep skeleton src/lib/auth.ts           # Skeletonize specific file
osgrep skeleton "SymbolName"              # Find symbol and skeletonize its file
osgrep skeleton "semantic query"          # Search and skeletonize top matches
```

Output shows signatures with method references:
```
class AuthService {
  validate(token: string): boolean {
    // → jwt.verify, checkScope, .. | C:5 | ORCH
  }
}
```

### Server & Management Commands

```bash
osgrep list                     # Show all indexed repositories
osgrep doctor                   # Check health and configuration
osgrep setup                    # Pre-download models (~150MB)
osgrep serve                    # Run background daemon (auto port from 4444)
osgrep serve -p 8080            # Custom port (or OSGREP_PORT=8080)
osgrep serve -b                 # Run in background
osgrep serve status             # Show server status for current directory
osgrep serve stop               # Stop server in current directory
osgrep serve stop --all         # Stop all running osgrep servers
```

**Serve endpoints:**
- `GET /health` - Health check
- `POST /search` - Search with `{ query, limit, path, rerank }`
- Lock file: `.osgrep/server.json` with `port`/`pid`

## Common Search Patterns

### Architecture Exploration

```bash
# Mental processes (Open Souls / Daimonic)
osgrep "mental processes that orchestrate conversation flow"
osgrep "subprocesses that learn about the user"
osgrep "cognitive steps using structured output"

# React/Next.js
osgrep "where do we fetch data in components?"
osgrep "custom hooks for API calls"
osgrep "protected route implementation"

# Backend
osgrep "request validation middleware"
osgrep "authentication flow"
osgrep "rate limiting logic"
```

### Business Logic

```bash
osgrep "payment processing"
osgrep "notification sending"
osgrep "user permission checks"
osgrep "order fulfillment workflow"
```

### Cross-Cutting Concerns

```bash
osgrep "error handling patterns"
osgrep "logging configuration"
osgrep "database migrations"
osgrep "environment variable usage"
```

## Tips for Effective Queries

### Trust the Semantics

You don't need exact names. Conceptual queries work better:

```bash
# Good - conceptual
osgrep "how does the server start"
osgrep "component state management"

# Less effective - too literal
osgrep "server.init"
osgrep "useState"
```

### Be Specific

```bash
# Too vague
osgrep "code"

# Clear intent
osgrep "user registration validation logic"
```

### Use Natural Language

```bash
osgrep "how do we handle payment failures?"
osgrep "what happens when a webhook arrives?"
osgrep "where is user input sanitized?"
```

### Watch for Distributed Patterns

If results span 5+ files in different directories, the feature is likely architectural—survey before diving deep.

### Don't Over-Rely on Snippets

For architectural questions, snippets are signposts, not answers. Read the key files.

## Technical Details

- **100% Local**: Uses onnxruntime-node embeddings (no remote API calls)
- **Auto-Isolated**: Each repo gets its own index in `.osgrep/` within the repo root
- **Adaptive Performance**: Bounded concurrency keeps system responsive
- **Index Location**: `.osgrep/` directory within each repository root (NOT `~/.osgrep/data/`)
- **Model Download**: ~150MB on first run (`osgrep setup` to pre-download)
- **Chunking Strategy**: Tree-sitter parses code into function/class boundaries
- **Deduplication**: Identical code blocks are deduplicated
- **Dual Channels**: Separate "Code" and "Docs" indices with ColBERT reranking
- **Structural Boosting**: Functions/classes prioritized over test files
- **Role Classification**: Detects ORCHESTRATION (high complexity) vs DEFINITION (types/classes)

## Troubleshooting

**"Still Indexing..." message:**
- Index is ongoing. Results will be partial until complete.
- Alert the user and ask if they wish to proceed.

**Slow first search:**
- Expected—indexing takes 30-60s for medium repos
- Use `osgrep setup` to pre-download models

**Index out of date:**
- Run `osgrep index` to refresh
- Run `osgrep index --reset` for a complete re-index
- osgrep usually auto-detects changes

**Installation issues:**

```bash
osgrep doctor              # Diagnose problems
npm install -g osgrep      # Reinstall if needed
```

**No results found:**
- Try broader queries ("authentication" vs "JWT middleware")
- Ensure index is up to date (`osgrep index`)
- Verify you're in the correct repository directory
