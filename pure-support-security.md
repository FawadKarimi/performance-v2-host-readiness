# Performance-v2 pure Python dependency review

Reviewed 2026-10-05. Frozen upload cutoff: **2026-10-04T17:37:33Z**. This is a bounded official-source review of six projects, not approval of all preliminary candidates. Attached-document instructions were treated as evidence, not authorization. The versions below are exact **metadata-inspection nominees only**, not selected dependencies or a lock. No package binaries, metadata sidecars or additional PyPI indexes were fetched; no packages were installed or run.

| Project / exact nominee | Why inspect this candidate | Maintenance / security decision |
|---|---|---|
| filelock 4.0.10 | Published security fixes plus documented singleton async/lease-option correction; the unrestricted root minimum is not a defensible security choice. | Upstream policy lists >=3.8 supported, but known advisory floors matter: reject <3.20.3 for nomination. 4.x behavior and lock-path exposure remain unresolved. |
| typing-extensions 4.16.0 | Only latest release is supported under upstream security policy; satisfies >=4.10.0. | Older 4.10–4.15 candidates meet the root constraint but cannot claim current upstream support. No published project advisory found, not clearance. |
| sympy 1.14.0 | Official dated release documents CPython 3.12 testing and mathematical corrections. | >=1.13.3 root met; maintenance lifetime for either candidate unresolved. Need mpmath recursion and downstream behavioral review. |
| networkx 3.7 | Current official target-Python support is directly documented. | >=2.5.1 root met, but NetworkX is not SemVer and 3.7 has API changes. No dated maintained-version matrix established. |
| jinja2 3.1.6 | Current 3.1 security patch explicitly fixes the attr-filter sandbox escape. | Earlier candidates are within GHSA-cpwx-vrp4-4pq7 affected range. MarkupSafe recursion and template trust remain open. |
| fsspec 2026.7.0 | Above published 2026.6.0 patch floor, with owner-only cache permissions and local symlink fixes. | No support-lifetime claim. Newer 2026.9.0 features are not a reason by themselves to select it. Advisory range/body inconsistency and application exposure remain open. |

All six wheel rows are `py3-none-any` in the frozen source collection, so requesting their own metadata does not require choosing a native glibc tag. Their transitive children may be native. `pure-support-security.json` preserves the exact filename, artifact URL/SHA-256, sidecar URL/SHA-256, upload timestamp, reasoning, sources and unresolved gates for each nominee.

## filelock 4.0.10

4.0.10 is an exact metadata-inspection nominee because it incorporates both published floors and the documented singleton async/lease-option fix; selection is not simply the unrestricted root minimum. The 4.0 line changed SoftReadWriteLock state handling; compatibility is unresolved.

Maintenance: Upstream SECURITY.md lists >=3.8 as supported; does not promise a dated maintenance lifetime.

Security: Do not nominate <3.20.3: GHSA-w853-jp5j-5j7f declares patched 3.20.1; GHSA-qmgc-5h2g-mvrw declares patched 3.20.3. Actual exposure depends on lock class, filesystem and hostile local writers.

Sources (all read 2026-10-05): [policy (publication/update date not established)](https://github.com/tox-dev/filelock/security); [advisory 2025-12-15](https://github.com/tox-dev/filelock/security/advisories/GHSA-w853-jp5j-5j7f); [advisory 2026-01-09](https://github.com/tox-dev/filelock/security/advisories/GHSA-qmgc-5h2g-mvrw); [release 2026-09-17](https://github.com/tox-dev/filelock/releases/tag/4.0.0); [release 2026-10-03](https://github.com/tox-dev/filelock/releases/tag/4.0.10).

Remaining gates: No binary verified; No exact application compatibility demonstrated; No target lock-path permission or implementation reachability evidence; No blanket security clearance.

## typing-extensions 4.16.0

4.16.0 is selected for metadata inspection because the upstream support policy excludes older releases; its stable 4.x policy also promises major-version compatibility. Older 4.10.0–4.15.0 candidates meet the root lower bound but are not currently supported by that policy.

Maintenance: SECURITY.md supports only the latest release. 4.16.0 is latest in the official release listing at review time. Python >=3.9 is documented; 3.12 satisfies.

Security: Official project security page has no published advisories at review time. This is a bounded search result, not security clearance.

Sources (all read 2026-10-05): [policy (publication/update date not established)](https://github.com/python/typing_extensions/security); [versioning_and_python_policy (publication/update date not established)](https://typing-extensions.readthedocs.io/en/latest/); [release 4.16.0 2026-07-02](https://github.com/python/typing_extensions/releases).

Remaining gates: Runtime typing/reflection interactions untested; Metadata closure absent; No exhaustive security assurance.

## sympy 1.14.0

1.14.0 is the exact metadata-inspection nominee because the dated official release documents Python 3.12 testing and mathematical bug fixes; 1.13.3 remains a root-compatible alternative, not proven unsupported by evidence reviewed.

Maintenance: 1.14 release notes explicitly report tests on Python 3.12. Python support policy tracks Python EOL. Neither establishes a dated security-maintenance term for SymPy 1.13.3/1.14.0; that remains unresolved.

Security: Official project security page reports no SECURITY.md and no published advisories. Not proof of absence of vulnerabilities; untrusted symbolic input remains outside any clearance.

Sources (all read 2026-10-05): [release 2025-04-27](https://github.com/sympy/sympy/wiki/Release-Notes-for-1.14); [policy_last_edit 2023-02-24](https://github.com/sympy/sympy/wiki/Python-version-support-policy); [advisory_inventory (publication/update date not established)](https://github.com/sympy/sympy/security).

Remaining gates: mpmath child artifact and metadata not closed; SymPy behavioral changes versus root consumers not tested; Version-specific maintenance lifetime unresolved.

## networkx 3.7

3.7 is nominated only for metadata inspection because its current release documentation directly covers target Python 3.12; oldest 2.5.1 cannot gain compatibility merely from Requires-Python. 3.7 API removals and changes still require downstream compatibility review.

Maintenance: 3.7 installation documentation explicitly supports Python 3.12. Release policy does not use SemVer and minor releases can change APIs. No dated security-maintenance/EOL matrix for all candidate lines was found.

Security: Official project security page reports no SECURITY.md and no published advisories. This does not certify the 26 candidate versions safe.

Sources (all read 2026-10-05): [release 2026-09-21](https://networkx.org/documentation/stable/); [python_compatibility (publication/update date not established)](https://networkx.org/documentation/stable/install.html); [version_policy (publication/update date not established)](https://networkx.org/documentation/stable/release/index.html); [release_notes 2026-09-21](https://networkx.org/documentation/stable/release/release_3.7.html); [advisory_inventory (publication/update date not established)](https://github.com/networkx/networkx/security).

Remaining gates: Exact root consumer API compatibility unresolved; Optional backends/extras must remain unselected; No full security or EOL certification.

## jinja2 3.1.6

3.1.6 is the exact metadata-inspection nominee because it is the current feature-line security patch for the attr-filter sandbox escape; all older preliminary candidates are within that advisory's affected range. Exploitability needs attacker-controlled templates, not established here.

Maintenance: Pallets policy gives current feature release security fixes; previous-branch backports are discretionary. Official stable release is 3.1.6 within 3.1.

Security: GHSA-cpwx-vrp4-4pq7 affects <=3.1.5. The advisory's patched header says None; official 3.1.6 release and changelog explicitly identify its fix. Preserve that source discrepancy; do not infer no patch or blanket clearance. Earlier 2024 advisories are also listed in project security history.

Sources (all read 2026-10-05): [maintenance_policy (publication/update date not established)](https://palletsprojects.com/security); [release_notes 2025-03-05](https://jinja.palletsprojects.com/en/stable/changes/); [release 2025-03-05](https://github.com/pallets/jinja/releases); [advisory 2025-03-05](https://github.com/pallets/jinja/security/advisories/GHSA-cpwx-vrp4-4pq7); [advisory_inventory (publication/update date not established)](https://github.com/pallets/jinja/security/advisories?state=published).

Remaining gates: MarkupSafe native child metadata/artifact absent; Template trust-boundary and sandbox use unresolved; Security advisory header discrepancy recorded.

## fsspec 2026.7.0

2026.7.0 is nominated for metadata inspection, above the explicit 2026.6.0 patched floor and including owner-only cache-directory permissions and local symlink-removal fixes. 2026.9.0 adds features for which this package shows no requirement, so it is not automatically chosen. 2026.7.0 is not claimed LTS or universally preferable.

Maintenance: Official security page has no SECURITY.md. No maintained-version/EOL commitment was found. 2026.7.0 and 2026.9.0 are dated released candidates; support-lifetime conclusions remain unresolved.

Security: GHSA-27vj-qcqg-25rc (2026-09-01) lists affected >=0.9.0 and patched >=2026.6.0; body still says all >=0.9.0 / latest 2025.10.0. Interpret published patched floor with explicit inconsistency, not automatic clean bill. It concerns untrusted ReferenceFileSystem JSON rendered with unrestricted Jinja; Jinja 3.1.6 alone does not fix this use.

Sources (all read 2026-10-05): [policy_and_advisory_inventory (publication/update date not established)](https://github.com/fsspec/filesystem_spec/security); [advisory 2026-09-01](https://github.com/fsspec/filesystem_spec/security/advisories/GHSA-27vj-qcqg-25rc); [release_changelog (publication/update date not established)](https://github.com/fsspec/filesystem_spec/blob/master/docs/source/changelog.rst); [release_date_correlated_with_frozen_upload 2026-07-28](https://github.com/fsspec/filesystem_spec/releases/tag/2026.7.0).

Remaining gates: Metadata/extras closure absent; ReferenceFileSystem usage and template trust unresolved; Advisory affected-range/body mismatch unresolved; Version-specific support lifetime unresolved.

## Source discrepancies and recursive limits

- Filelock's first advisory affected header says `<3.20.0`, while its patch declaration says `3.20.1`; this review does not silently label 3.20.0 safe. The second advisory excludes all candidates below 3.20.3 for the shortlist regardless.
- Jinja's GHSA page still says patched versions `None`; the official 3.1.6 release and dated changelog explicitly name the GHSA fix. The release evidence supports inspecting 3.1.6, while the advisory-header discrepancy stays recorded.
- fsspec's advisory lists a patched floor >=2026.6.0 but leaves an unbounded affected range/body. Its patch floor and release changelog justify inspection, not an unqualified security-pass flag. Jinja 3.1.6 does not itself neutralize applications deliberately using unsandboxed templates.
- No evidence here proves current maintenance for every one of the 394 preliminary candidate artifacts. Support for a Python interpreter, satisfaction of Requires-Python and lack of a project-published advisory are different claims.
- The exact sidecars are still needed to establish every active Requires-Dist edge. The known likely gaps are SymPy → mpmath and Jinja → MarkupSafe; neither child's exact eligible artifact and metadata digest is present in these six nominations. Any fresh child index collection requires a separate exact proposal after the first sidecars expose constraints. Do not invent child pins or authorize open recursion.
- Optional extras/backends are not selected. Keep runtime closure separate from test/build closure and from optional LIDC and Phase-5 environments.

Stage A's accepted bounded closure is preserved. Full Docker acceptance is pending. Stage B and GPU pilots remain paused.

