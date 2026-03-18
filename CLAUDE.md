# CS-Situational-Awareness-BOF Code Review Project

## What this project is

A fork of trustedsec/CS-Situational-Awareness-BOF — a collection of 61 Beacon Object Files (BOFs) for Cobalt Strike. We are working through a code review to fix bugs, memory safety issues, and code quality problems.

## Repository layout

- `src/SA/<bofname>/entry.c` — each BOF lives in its own directory
- `CONSOLIDATED_ISSUES.md` — the master issue tracker (lives in master, updated via worktree)
- `CODE_REVIEW_FINDINGS.md` and `bof_review_checklist.md` — the original review documents

## Git workflow

- **Remotes**: `origin` = chryzsh's fork, `upstream` = trustedsec original
- **Feature branches**: one per BOF, branched off `upstream/master` (not origin/master)
  - Example: `git checkout -b fix/netlocalgroup2-issues upstream/master`
  - This avoids accidentally including fork-only commits in PRs
- **Worktree**: `../CS-SA-BOF-master` is a git worktree checkout of `origin/master`
  - Used to update `CONSOLIDATED_ISSUES.md` independently of feature branches
  - Commit and push there without switching branches: `cd ../CS-SA-BOF-master && git add CONSOLIDATED_ISSUES.md && git commit -m "update" && git push`
- **PRs target**: `trustedsec/CS-Situational-Awareness-BOF:master`
- **Force push**: needed after rebasing feature branches (they were cleaned up to remove review doc commits)

## How we work

- The user writes all code themselves. Claude acts as a guide — explaining issues, reviewing changes, pointing out bugs in the user's fixes.
- Focus on issues that have **real consequences** (beacon crashes, memory corruption, leaks). Skip cosmetic/style issues.
- Each issue is checked against the actual code before working on it. Many automated review findings are **false positives** (whoami had 5/12 CRITICALs as FP).
- After each fix, update CONSOLIDATED_ISSUES.md status column via the worktree.
- Commits are small and per-issue. The user writes commit messages and PR descriptions themselves.

## Issue tracker status values

In CONSOLIDATED_ISSUES.md, the Status column uses:
- (blank) — not yet reviewed
- FIXED — resolved
- FP — false positive with explanation
- WONTFIX — acknowledged, not worth fixing, with reason

## What's been done

### whoami (PR branch: fix/whoami-issues)
- Issue 6 FIXED: Refactored `WhoamiGetTokenInfo` to goto cleanup pattern with pResult/pTokenInfo ownership transfer. Fixed fall-through bug when GetLastError != ERROR_INSUFFICIENT_BUFFER.
- Issue 7 FIXED: Checked return value of `ConvertSidToStringSidA` in `WhoamiUser`, matching existing pattern in `WhoamiGroups`.
- Issue 12 FIXED: Uncommented error messages, switched to internal_printf.
- Issues 1-5 marked FP (NULL checks already existed, buffer sizes adequate).
- Issues 8,10,11 marked WONTFIX (documentation, magic numbers, comments).
- Issue 9 marked FP (no pointer params to constify).

### netstat (reviewed, all WONTFIX)
- Issue 1: GetNameByPID pointer assignment is cosmetic — error already reported via BeaconPrintf.
- Issue 2: `if (1||...)` is intentional, shows all connections.
- Remaining issues not worth fixing.

### netlocalgroup2 (in progress — branch: fix/netlocalgroup2-issues)
- Issue 1: Memory leak of sidstr from ConvertSidToStringSidW. User is fixing — needs to check return value, print sid inside the if block, then LocalFree.
- Pattern: simple if/else inside the loop (not goto cleanup, since it's a single resource in a loop body).

## Key patterns learned

### goto cleanup pattern (for functions with multiple resources)
```c
VOID* pResult = NULL;
// ... acquire resources, goto cleanup on any failure ...
pResult = pTokenInfo;  // ownership transfer on success
pTokenInfo = NULL;     // prevent cleanup from freeing it

cleanup:
    if (hToken) CloseHandle(hToken);
    if (pTokenInfo) intFree(pTokenInfo);  // only frees on error
    return pResult;
```

### Windows two-call API pattern
Many Win32 APIs (GetTokenInformation, LookupAccountSid, etc.) are called twice:
1. First call with NULL/0 to get required buffer size (expect ERROR_INSUFFICIENT_BUFFER)
2. Allocate that size
3. Second call with real buffer

ERROR_INSUFFICIENT_BUFFER from the first call is the **success signal**, not an error.

### ConvertSidToStringSid
Allocates memory internally via LocalAlloc. Caller must free with LocalFree. Always check the return value before using the output pointer.

### When NOT to use goto cleanup
Inside loop bodies with a single short-lived resource — just use if/else inline. goto cleanup is for function-level resource management with multiple resources.
