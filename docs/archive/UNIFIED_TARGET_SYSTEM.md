# Unified Target System - Single & Batch Workflows

**Design Philosophy:** One registry system serves both single-target assessments and batch operations seamlessly.

---

## Core Principle

```
targets/profiles/*.yaml = Source of truth for ALL MCP configurations
     ↓
  Used by both:
     • mcpsf assess --target <id>    (single)
     • mcpsf batch --targets <sel>   (multiple)
```

**No more separate scope.yaml files!** Everything goes through the target registry.

---

## User Experience Goals

### Goal 1: Make Single-MCP Setup Fast & Easy
```bash
# Option A: Interactive wizard (easiest)
mcpsf targets init
  → What's your target ID? my-server
  → Transport type? (sse/stdio): sse
  → URL: http://localhost:9001/sse
  → Authentication? (none/api_key/oauth): none
  → Tags? (comma-separated): production,api
  ✓ Created targets/profiles/my-server.yaml
  ✓ Added to targets/registry.yaml

# Option B: One-liner
mcpsf targets init --id my-server --type sse --url http://localhost:9001/sse --tags production,api

# Option C: From existing server (auto-detect)
mcpsf targets init --id my-server --probe http://localhost:9001/sse
  → Detected: SSE transport, no auth required, 5 tools, 3 resources
  → Tags? production,api
  ✓ Created profile with detected settings
```

### Goal 2: Seamless Single-Target Assessment
```bash
# New way: Use target ID (reads from registry)
mcpsf assess --target my-server --profile balanced
mcpsf assess --target my-server --profile aggressive

# Legacy way: Direct connection (still works, no config needed)
mcpsf assess --transport sse --url http://localhost:9001/sse
mcpsf assess --transport stdio --command npx --args -y,@modelcontextprotocol/server-time

# Save legacy command as reusable target
mcpsf assess --transport sse --url http://localhost:9001/sse --save-target my-server
  ✓ Assessment complete
  ✓ Saved as targets/profiles/my-server.yaml
  → Tip: Next time use: mcpsf assess --target my-server
```

### Goal 3: Scale to Batch Seamlessly
```bash
# You've been running single assessments for a week...
mcpsf assess --target server1 --profile balanced
mcpsf assess --target server2 --profile balanced
mcpsf assess --target server3 --profile balanced

# Now scale to batch mode (same configs, just parallel)
mcpsf batch --targets id=server1,server2,server3 --profile balanced --concurrency 3

# Or add them to a group
echo "server1\nserver2\nserver3" > targets/groups/my-group.txt
mcpsf batch --targets group=my-group --profile balanced
```

---

## CLI Design (Updated)

### Single-Target Commands

```bash
# === ASSESS (Single Target) ===

# Method 1: Use registered target (RECOMMENDED)
mcpsf assess --target <target-id> [--profile <safe|balanced|aggressive>] [--output <dir>]

# Method 2: Direct connection (no config needed)
mcpsf assess --transport <sse|stdio> --url <url> [--command <cmd>] [--args <args>]

# Method 3: Direct + save for reuse
mcpsf assess --transport sse --url http://... --save-target <id> [--tags <tags>]

# Examples:
mcpsf assess --target dv-mcp-ch1                          # Use registered target
mcpsf assess --target dv-mcp-ch1 --profile aggressive     # Override profile
mcpsf assess --transport sse --url http://localhost:9001/sse  # Direct connection
mcpsf assess --transport sse --url http://localhost:9001/sse --save-target my-server --tags test,api


# === TARGET MANAGEMENT ===

# Initialize new target (interactive)
mcpsf targets init

# Initialize new target (one-liner)
mcpsf targets init --id <id> --type <sse|stdio> --url <url> [--tags <tags>]

# Initialize from probe (auto-detect)
mcpsf targets init --id <id> --probe <url>

# List targets
mcpsf targets list [--tag <tag>] [--status <active|disabled>]

# Show target details
mcpsf targets show <target-id>

# Edit target (opens in $EDITOR)
mcpsf targets edit <target-id>

# Validate target config
mcpsf targets validate <profile.yaml>

# Enable/disable targets
mcpsf targets enable <target-id>
mcpsf targets disable <target-id>

# Delete target
mcpsf targets delete <target-id> [--force]

# Export target as standalone scope.yaml (for v0.3 compatibility)
mcpsf targets export <target-id> --output scope.yaml
```

### Batch Commands

```bash
# === BATCH (Multiple Targets) ===

mcpsf batch --targets <selector> [--profile <mode>] [--concurrency N] [--resume] [--output <dir>]

# Target selectors:
--targets all                           # All active targets
--targets tag=public                    # Single tag
--targets tag=public,production         # Multiple tags (AND)
--targets id=server1,server2,server3    # Specific IDs
--targets group=my-group                # Predefined group
--targets status=active                 # By status

# Examples:
mcpsf batch --targets all --profile balanced --concurrency 3
mcpsf batch --targets tag=production --profile safe --concurrency 1
mcpsf batch --targets id=server1,server2 --resume
mcpsf batch --targets group=critical --output ./reports/critical-scan


# === REGISTRY MANAGEMENT ===

# Initialize registry (first-time setup)
mcpsf registry init

# Validate entire registry
mcpsf registry validate

# Show registry stats
mcpsf registry stats

# Import v0.3 scope.yaml as target
mcpsf registry import scope.yaml --id <target-id> --tags <tags>

# Export registry to different format
mcpsf registry export --format json --output registry.json


# === EXISTING COMMANDS (unchanged) ===

mcpsf list-detectors
mcpsf version
```

---

## Implementation: CLI Routing Logic

### New mcpsf.py Structure

```python
#!/usr/bin/env python3
"""
MCP Security Framework CLI (v0.4)
Unified target system for single and batch operations.
"""

import sys
import asyncio
from pathlib import Path

# Main command routing
def main():
    parser = argparse.ArgumentParser(...)
    subparsers = parser.add_subparsers(dest="command")

    # ======================================================================
    # ASSESS (Single Target) - ENHANCED
    # ======================================================================
    assess_parser = subparsers.add_parser("assess")

    # Method 1: Use registered target (NEW)
    assess_parser.add_argument("--target", help="Target ID from registry")
    assess_parser.add_argument("--profile", choices=["safe", "balanced", "aggressive"])

    # Method 2: Direct connection (EXISTING, unchanged)
    assess_parser.add_argument("--transport", choices=["sse", "stdio"])
    assess_parser.add_argument("--url", help="SSE endpoint URL")
    assess_parser.add_argument("--command", help="stdio command")
    assess_parser.add_argument("--args", help="stdio args (comma-separated)")

    # Method 3: Save as target (NEW)
    assess_parser.add_argument("--save-target", help="Save config as reusable target")
    assess_parser.add_argument("--tags", help="Tags for saved target (comma-separated)")

    # Common options
    assess_parser.add_argument("-o", "--output", help="Output directory")
    assess_parser.add_argument("-v", "--verbose", action="store_true")
    assess_parser.add_argument("-d", "--detectors", help="Detector IDs (comma-separated)")

    # ======================================================================
    # TARGETS (Management) - NEW
    # ======================================================================
    targets_parser = subparsers.add_parser("targets")
    targets_sub = targets_parser.add_subparsers(dest="targets_command")

    # targets init
    init_parser = targets_sub.add_parser("init")
    init_parser.add_argument("--id", help="Target ID")
    init_parser.add_argument("--type", choices=["sse", "stdio"])
    init_parser.add_argument("--url", help="SSE URL or stdio command")
    init_parser.add_argument("--command", help="stdio command")
    init_parser.add_argument("--args", help="stdio args (comma-separated)")
    init_parser.add_argument("--tags", help="Tags (comma-separated)")
    init_parser.add_argument("--probe", help="Probe URL to auto-detect config")

    # targets list/show/edit/validate/enable/disable/delete
    targets_sub.add_parser("list").add_argument("--tag")
    targets_sub.add_parser("show").add_argument("target_id")
    targets_sub.add_parser("edit").add_argument("target_id")
    targets_sub.add_parser("validate").add_argument("profile")
    targets_sub.add_parser("enable").add_argument("target_id")
    targets_sub.add_parser("disable").add_argument("target_id")
    targets_sub.add_parser("delete").add_argument("target_id")
    targets_sub.add_parser("export").add_argument("target_id").add_argument("--output")

    # ======================================================================
    # BATCH (Multiple Targets) - NEW
    # ======================================================================
    batch_parser = subparsers.add_parser("batch")
    batch_parser.add_argument("--targets", required=True, help="Target selector")
    batch_parser.add_argument("--profile", default="balanced")
    batch_parser.add_argument("--concurrency", type=int, default=3)
    batch_parser.add_argument("--resume", action="store_true")
    batch_parser.add_argument("--fail-fast", action="store_true")
    batch_parser.add_argument("-o", "--output", default="./reports")

    # ======================================================================
    # REGISTRY (Management) - NEW
    # ======================================================================
    registry_parser = subparsers.add_parser("registry")
    registry_sub = registry_parser.add_subparsers(dest="registry_command")
    registry_sub.add_parser("init")
    registry_sub.add_parser("validate")
    registry_sub.add_parser("stats")
    registry_sub.add_parser("import").add_argument("scope_file").add_argument("--id").add_argument("--tags")
    registry_sub.add_parser("export").add_argument("--format").add_argument("--output")

    # ======================================================================
    # EXISTING COMMANDS (unchanged)
    # ======================================================================
    subparsers.add_parser("list-detectors")
    subparsers.add_parser("version")

    # Parse and route
    args = parser.parse_args()

    if args.command == "assess":
        exit_code = asyncio.run(assess_command(args))
        sys.exit(exit_code)

    elif args.command == "targets":
        exit_code = targets_command(args)
        sys.exit(exit_code)

    elif args.command == "batch":
        exit_code = asyncio.run(batch_command(args))
        sys.exit(exit_code)

    # ... other commands ...


# ======================================================================
# ASSESS COMMAND LOGIC
# ======================================================================

async def assess_command(args):
    """
    Handle single-target assessment with three modes:
    1. --target <id>: Load from registry
    2. --transport + --url/--command: Direct connection
    3. --save-target: Direct connection + save config
    """

    # Mode 1: Use registered target
    if args.target:
        print(f"[*] Loading target: {args.target}")
        target_profile = load_target_from_registry(args.target)

        # Override profile if specified
        if args.profile:
            target_profile.set_profile(args.profile)

        # Build scope from target profile
        scope = target_profile.to_scope_config()

        # Run assessment
        runner = TestRunner(scope)
        result = await runner.assess()

        # Generate reports
        generate_reports(result, args.output)
        return 0 if result.summary["present"] == 0 else 1

    # Mode 2 & 3: Direct connection
    elif args.transport:
        print(f"[*] Direct connection: {args.transport}")

        # Build scope from CLI args
        scope = build_scope_from_args(args)

        # Run assessment
        runner = TestRunner(scope)
        result = await runner.assess()

        # Generate reports
        generate_reports(result, args.output)

        # Mode 3: Save as reusable target
        if args.save_target:
            save_as_target(args, result)
            print(f"\n[+] Saved as reusable target: {args.save_target}")
            print(f"    Next time use: mcpsf assess --target {args.save_target}")

        return 0 if result.summary["present"] == 0 else 1

    else:
        print("[!] Error: Must specify --target <id> OR --transport <type>")
        return 1


def load_target_from_registry(target_id: str) -> TargetProfile:
    """Load target profile from registry."""
    registry = TargetRegistry.load("targets/registry.yaml")
    profile_path = registry.get_profile_path(target_id)
    return TargetProfile.from_yaml(profile_path)


def build_scope_from_args(args) -> ScopeConfig:
    """Build ScopeConfig from CLI arguments (legacy mode)."""
    if args.transport == "sse":
        target = args.url
    elif args.transport == "stdio":
        args_list = args.args.split(",") if args.args else []
        target = f"stdio://{args.command}/{'/'.join(args_list)}"

    return ScopeConfig(
        target=target,
        mode=args.profile or "balanced",
        # ... default scope settings ...
    )


def save_as_target(args, assessment_result: AssessmentResult):
    """Save direct connection as reusable target profile."""
    target_id = args.save_target
    tags = args.tags.split(",") if args.tags else ["imported"]

    # Build profile from CLI args + assessment results
    profile = TargetProfile(
        id=target_id,
        name=assessment_result.profile.server_name,
        tags=tags,
        priority="medium",
        status="active",
        transport=build_transport_config(args),
        # ... infer settings from assessment ...
    )

    # Save to files
    profile_path = Path(f"targets/profiles/{target_id}.yaml")
    profile.save(profile_path)

    # Add to registry
    registry = TargetRegistry.load("targets/registry.yaml")
    registry.add_target(target_id, f"profiles/{target_id}.yaml", enabled=True)
    registry.save()


# ======================================================================
# TARGETS COMMAND LOGIC
# ======================================================================

def targets_command(args):
    """Handle target management commands."""

    if args.targets_command == "init":
        return targets_init(args)

    elif args.targets_command == "list":
        return targets_list(args)

    # ... other subcommands ...


def targets_init(args):
    """
    Initialize new target (interactive or one-liner).
    """
    # Interactive mode
    if not args.id:
        print("=== New Target Setup ===\n")
        target_id = input("Target ID (lowercase-with-hyphens): ").strip()
        transport = input("Transport (sse/stdio): ").strip()

        if transport == "sse":
            url = input("URL: ").strip()
            # ... more prompts ...
        elif transport == "stdio":
            command = input("Command: ").strip()
            # ... more prompts ...

        tags = input("Tags (comma-separated): ").strip().split(",")

    # One-liner mode
    else:
        target_id = args.id
        transport = args.type
        # ... extract from args ...

    # Create profile from template
    profile = create_profile_from_template(
        target_id=target_id,
        transport=transport,
        tags=tags,
        # ... other params ...
    )

    # Save profile
    profile_path = Path(f"targets/profiles/{target_id}.yaml")
    profile.save(profile_path)

    # Add to registry
    registry = TargetRegistry.load("targets/registry.yaml")
    registry.add_target(target_id, f"profiles/{target_id}.yaml", enabled=True)
    registry.save()

    print(f"\n✓ Created targets/profiles/{target_id}.yaml")
    print(f"✓ Added to targets/registry.yaml")
    print(f"\nNext steps:")
    print(f"  • Review config: mcpsf targets show {target_id}")
    print(f"  • Run assessment: mcpsf assess --target {target_id}")

    return 0


def targets_list(args):
    """List all targets."""
    registry = TargetRegistry.load("targets/registry.yaml")
    targets = registry.get_all_targets()

    if args.tag:
        targets = [t for t in targets if args.tag in t.tags]

    print(f"\n{'ID':<25} {'Name':<40} {'Tags':<30} {'Status':<10}")
    print("-" * 110)

    for target in targets:
        tags_str = ",".join(target.tags[:3])
        print(f"{target.id:<25} {target.name:<40} {tags_str:<30} {target.status:<10}")

    print(f"\nTotal: {len(targets)} targets")
    return 0
```

---

## Key Classes (New in v0.4)

### TargetProfile (src/core/models.py)

```python
class TargetProfile(BaseModel):
    """
    Complete target configuration.
    Can be used for single assessment or batch operation.
    """
    id: str
    name: str
    tags: List[str]
    priority: str
    status: str
    transport: TransportConfig
    healthcheck: Optional[HealthcheckConfig]
    auth: Optional[AuthConfig]
    profiles: Optional[Dict[str, ProfileOverride]]  # safe/balanced/aggressive
    scope: Optional[ScopeOverride]
    reporting: Optional[ReportingConfig]
    metadata: Optional[Dict[str, Any]]

    def to_scope_config(self, profile: str = "balanced") -> ScopeConfig:
        """
        Convert TargetProfile to ScopeConfig for TestRunner.
        This bridges the new registry system with existing TestRunner.
        """
        # Get profile overrides
        profile_override = self.profiles.get(profile) if self.profiles else None

        # Build target string
        if self.transport.type == "sse":
            target = self.transport.url
        elif self.transport.type == "stdio":
            args_str = "/".join(self.transport.args)
            target = f"stdio://{self.transport.command}/{args_str}"

        # Build ScopeConfig
        return ScopeConfig(
            target=target,
            mode=profile_override.mode if profile_override else profile,
            allowed_prefixes=self.scope.allowed_prefixes if self.scope else DEFAULT_PREFIXES,
            blocked_paths=self.scope.blocked_paths if self.scope else [],
            rate_limit=profile_override.rate_limit if profile_override else DEFAULT_RATE_LIMIT,
            policy=profile_override.policy if profile_override else DEFAULT_POLICY,
            auth=self.auth or DEFAULT_AUTH,
            reporting=self.reporting or DEFAULT_REPORTING,
            detectors=profile_override.detectors if profile_override else None,
            metadata=self.metadata or {},
        )

    @classmethod
    def from_yaml(cls, path: Path) -> "TargetProfile":
        """Load from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    def save(self, path: Path):
        """Save to YAML file."""
        with open(path, "w") as f:
            yaml.dump(self.model_dump(), f, sort_keys=False)
```

### TargetRegistry (src/core/target_registry.py)

```python
class TargetRegistry:
    """
    Master registry of all targets.
    Used by both single-target (assess) and batch operations.
    """

    def __init__(self, registry_path: Path = Path("targets/registry.yaml")):
        self.registry_path = registry_path
        self.data: Dict[str, Any] = {}
        self.targets: Dict[str, TargetRef] = {}

    @classmethod
    def load(cls, path: Path = Path("targets/registry.yaml")) -> "TargetRegistry":
        """Load registry from YAML."""
        registry = cls(path)
        with open(path) as f:
            registry.data = yaml.safe_load(f)

        # Parse targets
        for target_entry in registry.data.get("targets", []):
            registry.targets[target_entry["id"]] = TargetRef(**target_entry)

        return registry

    def get_target(self, target_id: str) -> TargetProfile:
        """Load full target profile by ID."""
        if target_id not in self.targets:
            raise ValueError(f"Target not found: {target_id}")

        profile_path = Path("targets") / self.targets[target_id].profile
        return TargetProfile.from_yaml(profile_path)

    def select_targets(self, selector: str) -> List[TargetProfile]:
        """
        Select targets by DSL selector.

        Examples:
            "all" -> all active targets
            "tag=public" -> targets with tag "public"
            "id=t1,t2,t3" -> specific IDs
        """
        # Parse selector
        if selector == "all":
            target_ids = [t for t in self.targets.keys() if self.targets[t].enabled]

        elif selector.startswith("tag="):
            tag = selector[4:]
            target_ids = [
                tid for tid, tref in self.targets.items()
                if tref.enabled and self._has_tag(tid, tag)
            ]

        elif selector.startswith("id="):
            target_ids = selector[3:].split(",")

        # Load profiles
        return [self.get_target(tid) for tid in target_ids]

    def add_target(self, target_id: str, profile_path: str, enabled: bool = True):
        """Add new target to registry."""
        self.data["targets"].append({
            "id": target_id,
            "profile": profile_path,
            "enabled": enabled,
        })

    def save(self):
        """Save registry back to YAML."""
        with open(self.registry_path, "w") as f:
            yaml.dump(self.data, f, sort_keys=False)
```

---

## Migration Strategy

### Phase 1: Add TargetRegistry Support (Week 1)
- Implement `TargetProfile` and `TargetRegistry` classes
- Add `targets init/list/show` commands
- Keep existing `mcpsf assess <url>` working unchanged

### Phase 2: Bridge Single & Batch (Week 2)
- Add `mcpsf assess --target <id>` support
- Implement `TargetProfile.to_scope_config()` bridge
- Test single-target workflow with registry

### Phase 3: Add Batch Mode (Week 3-4)
- Implement `BatchRunner` using same `TargetRegistry`
- Add `mcpsf batch` command
- Test with 3-5 targets

### Phase 4: Polish UX (Week 5)
- Add interactive `targets init` wizard
- Add `--save-target` flag to `assess` command
- Add `registry import` for v0.3 scope files

---

## Benefits of This Design

✅ **Single source of truth** - All configs in `targets/`
✅ **Smooth onboarding** - `targets init` wizard for first-time users
✅ **Backward compatible** - Legacy `mcpsf assess <url>` still works
✅ **Progressive enhancement** - Start with one target, scale to 100+
✅ **No duplication** - Same config for single and batch
✅ **Easy migration** - `--save-target` converts ad-hoc runs to reusable configs
✅ **Version control friendly** - All targets in git, reviewable diffs

---

## Example Workflows

### Workflow 1: Brand New User (First Assessment)

```bash
# Quick start: Direct connection (no config needed)
mcpsf assess --transport sse --url http://localhost:9001/sse

# That worked! Save it for reuse:
mcpsf assess --transport sse --url http://localhost:9001/sse --save-target my-first-mcp --tags test
# ✓ Assessment complete
# ✓ Saved as targets/profiles/my-first-mcp.yaml
# → Next time use: mcpsf assess --target my-first-mcp

# Now use the saved config:
mcpsf assess --target my-first-mcp --profile aggressive
```

### Workflow 2: Power User (Many Targets)

```bash
# Set up multiple targets at once
mcpsf targets init --id prod-api --type sse --url https://api.example.com/mcp --tags production,api
mcpsf targets init --id staging-api --type sse --url https://staging.example.com/mcp --tags staging,api
mcpsf targets init --id dev-api --type sse --url http://localhost:9001/sse --tags dev,api

# Test them individually first
mcpsf assess --target dev-api --profile safe
mcpsf assess --target staging-api --profile balanced

# Now run all at once
mcpsf batch --targets tag=api --profile balanced --concurrency 3
```

### Workflow 3: Security Team (100+ Targets)

```bash
# Initialize registry
mcpsf registry init

# Bulk import from CSV/JSON
python scripts/import_targets.py --input servers.csv

# Validate all configs
mcpsf registry validate

# Run batch scan
mcpsf batch --targets tag=production --profile safe --concurrency 5 --output ./scans/production-$(date +%Y%m%d)

# Check summary
mcpsf reports summary --batch latest

# Deep dive on high-risk findings
mcpsf batch --targets tag=high-risk --profile aggressive --concurrency 1
```

---

## Summary

This unified design makes MCPSF equally smooth for:
- **First-time users** - Direct connection, no config needed
- **Frequent users** - Saved targets, quick `--target <id>` syntax
- **Enterprise users** - Batch mode, 100+ targets, CI/CD integration

The key insight: **TargetProfile serves both single and batch**, eliminating duplication and providing consistent behavior across all workflows.

**Next Steps:**
1. Implement `TargetProfile` and `TargetRegistry` classes
2. Add `targets init/list/show` commands
3. Wire up `assess --target <id>` routing
4. Test with 3-5 targets before scaling to 60+
