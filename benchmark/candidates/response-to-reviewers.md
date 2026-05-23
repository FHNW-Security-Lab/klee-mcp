# Response to Reviewers — KES 2026, Paper 952

**Paper:** *Closing the Triage Loop: MCP-mediated KLEE Validation of LLM-Reported C/C++ Vulnerabilities*
**Authors:** Christopher Scherb, Alexander Trapp, Ruben Hutter, Nico Bachmann, Luc Bryan Heitz (University of Applied Sciences and Arts Northwestern Switzerland)

We thank both reviewers for their constructive feedback. This letter
lists every concrete remark and the corresponding revision.

---

## Review 1

The reviewer raised no required revision. We have tightened the
framing of §1 so the methodological contribution stands out earlier
in the paper.

---

## Review 2

### *"No strong baselines or comparative evaluation against existing tools"*

We added an explicit **Baseline contrast** paragraph in §5 that
quantifies the gap between raw KLEE (no LLM bounds) and klee-mcp on
the same target. On `libpng_check_fp_number`, raw KLEE times out at
60 s with 1700 partial paths and no verdict, while the LLM-bounded
run exhausts 1438 complete paths in 30.9 s and returns a definitive
`infeasible` proof. The sensitivity pair already in Table 2
(`libpng_fp_number` bounded vs unbounded) is the within-tool baseline
against KLEE itself.

A fair cross-tool comparison against static analysers (cppcheck,
clang-analyzer), fuzzer-harness generators (PromptFuzz, OSS-Fuzz-Gen),
or coverage-guided fuzzers (libFuzzer) requires a different
experimental design — the units those tools consume (rule sets, fuzz
drivers, corpora) are not commensurate with our structured candidate
schema. We acknowledge this explicitly in §5 and identify the
cross-tool study as the obvious follow-on.

### *"Exploitability classification and CVSS scoring are heuristic and not rigorously validated"*

We added a paragraph at the end of §4 that:

1. Labels the classifier explicitly as a **triage signal** rather
   than ground truth.
2. Reports a manual cross-check of the classifier's primitive label
   against a human-assigned label for every confirmed verdict in our
   benchmark (10/10 agreed).
3. Flags this as evidence of internal consistency only — not a
   precision figure.
4. Recommends that the CVSS strings be reviewed by a human triager
   before any external use; the role of the heuristic is to prefill
   the disclosure template with a starting vector that the analyst
   then refines.

We further marked the concrete CVSS vector printed for the
`libpng_format_number` row in §5 as a machine-generated placeholder
rather than a severity claim, given that the underlying finding is
explicitly not internally reachable.

### *"Real-world impact is modest (only one weak non-synthetic finding, not a CVE)"*

The previous version reproduced CVE-2015-8540 in `png_check_keyword`
(libpng 1.6.19) and verified the same OOB persists in libpng 1.6.47.
The revised version adds a **third reproduction** of the same CVE
pattern in the structurally different libpng 1.2.56 code path (which
uses `png_strlen` plus a `for(*kp)` loop instead of the inline
`while`), demonstrating that the caller-contract assumption persists
across two major code generations. Table 3 summarises the four runs
(three confirmations, one counterfactual that flips the verdict to
`infeasible`).

The classification of `png_format_number` remains framed exactly as
before — a defense-in-depth contract violation, explicitly **not** a
remotely-reachable CVE — because the call-site survey we report
still shows all internal callers respecting the contract; we
deliberately do not strengthen this claim because the call-site
survey we report does not support it.

### *"Main contribution is system integration rather than new symbolic execution or LLM methods"*

The Contributions paragraph in §1 has been rewritten so that the
methodological choices — the **candidate schema as a pre-commit
specification**, the **retractable-bounds protocol that surfaces
mis-modelled preconditions**, and the **symex-witness-to-disclosure
pipeline** — appear as the contribution, with the system realisation
labelled separately. The intent is to make explicit that the work is
not "LLM-plus-KLEE wiring" but a discipline imposed on how an LLM
speaks to a symbolic engine.

### *"Insufficient empirical evidence for strong acceptance"*

The additions above (third CVE reproduction in libpng 1.2.56,
baseline contrast paragraph, classifier consistency cross-check,
three new analysis paragraphs) extend the empirical evidence within
the original paper's scope. We acknowledge that a fuller evaluation
— larger CVE corpus, second-library reproductions, head-to-head
against external tools — is the right direction for a follow-on
study and now say so in §7. The paper as it stands positions itself
as a proof-of-concept triage workflow rather than a broad
vulnerability-discovery evaluation.

---

## Additional self-review changes (not driven by reviewer comments, but applied for consistency)

1. Fixed forward-reference resolution: all `\ref{}` and `\cite{}`
   placeholders that previously rendered as `??` or `[?]` are now
   resolved.
2. Removed a redundant period after `\cite{}` inside `\paragraph{}`
   headings (the Procedia `elsarticle.cls` adds its own period).
3. Replaced one self-referencing footnote in Table 2 that pointed at
   the section it lived in.
4. Made tool naming consistent across abstract, pipeline figure, and
   §2.2 (`check_reachability_tool`, `generate_harness_tool` match the
   names in the released code).
5. Aligned the "four phases" wording with the four phase-groups
   shown in Table 2 (the reachability micro-benchmark is shipped
   with the repository but omitted from the main table for space).
6. Softened the limitations paragraph so it correctly reflects both
   the historical CVE reproductions and the defense-in-depth
   finding.

---

*Submitted to KES 2026 / IS48 Revision upload.*
