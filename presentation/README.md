# KES 2026 presentation

An English, 16:9 Beamer presentation of **Closing the Triage Loop:
MCP-mediated KLEE Validation of LLM-Reported C/C++ Vulnerabilities**.
The talk is planned for **20 minutes**, with 14 main slides and 4 backup
slides. Extended questions are additional to the 20 minutes.

- [Presentation PDF](klee-mcp-kes-presentation.pdf)
- [LaTeX source with timed speaker notes](klee-mcp-kes-presentation.tex)
- [Source paper](../paper/klee-mcp-kes.pdf)
- `figures/`: editable TikZ diagrams and charts
- `theme/`: self-contained FHNW styling and original logo assets

## Build

Requires a normal TeX Live or MacTeX installation with `pdflatex`,
`latexmk`, Beamer, PGF/TikZ, Latin Modern, `booktabs`, and `dashrule`.
No shell escape, external image generation, Python, or sibling repository
is required to build the slides.

```sh
cd presentation
make
```

The final PDF is copied from the ignored `build/` directory to this folder
and is committed alongside its sources. After changing the source, run
`make` and commit both the source and refreshed PDF.

For a presenter copy with notes on the right:

```sh
make notes
```

This creates `klee-mcp-kes-presentation-notes.pdf` locally (ignored by Git).
The default audience PDF hides all notes. `make clean` removes only the
intermediate `build/` directory, retaining the presentation PDFs.

Without `latexmk`, compile the main source twice with `pdflatex` from this
directory. The Makefile is preferred because it resolves references
automatically and keeps intermediate files separate.

## Delivery plan

| Slide | Topic | Time | Cumulative |
|---|---|---:|---:|
| 1 | Title and research question | 0:30 | 0:30 |
| 2 | curl: verification costs maintainers time | 1:30 | 2:00 |
| 3 | Clear problem and audience hook | 1:00 | 3:00 |
| 4 | What the LLM does | 1:00 | 4:00 |
| 5 | Symbolic execution primer | 1:45 | 5:45 |
| 6 | Integrated candidate-to-harness-to-verdict workflow | 2:00 | 7:45 |
| 7 | Verdict meanings | 1:15 | 9:00 |
| 8 | Entry-point versus function-level analysis | 1:30 | 10:30 |
| 9 | Caller contract, search reduction, and libpng examples | 3:00 | 13:30 |
| 10 | Retry for different usage | 1:45 | 15:15 |
| 11 | Evaluation setup | 0:45 | 16:00 |
| 12 | Benchmark results | 1:15 | 17:15 |
| 13 | Within-KLEE baseline | 1:15 | 18:30 |
| 14 | Conclusion with system figure and opening question | 1:30 | 20:00 |

The opening uses curl as an external motivation, followed by a short show
of hands about reporting an AI-generated finding. The closing includes a pause
and invitation to questions. Backup slides contain the detailed benchmark,
cross-library results, limitations and next steps, and external references.
No live demo is required.

Before defining caller contracts, the deck contrasts analysis from an
application/API entry point with a direct function-level harness. The former
executes caller checks and carries their path constraints into the target;
the latter bypasses that code and needs an explicit model of its guarantees.
LLM-supplied bounds capture selected preconditions, not the entire caller
context. A relaxed retry remains a function-level analysis.

A schematic running example connects the explanations: a function processes
records and current callers use at most four. The LLM proposes the bound
`0 <= n <= 4`; the caller-contract slide explains how that excludes paths and
limits loop iterations. The notes specify 16 record slots in the harness.
The next slide explains the retry
without the LLM bounds when considering a different caller (for example,
`n = 8`). This example is explanatory, not a new experimental result.
The retry removes the declared LLM bounds; harness and engine limits remain.
A relaxed run can reveal a hardening opportunity without establishing a
reachable vulnerability in current usage.

The caller-contract slide also contains the historical libpng CVE example and
the separate `png_format_number` caller review. These illustrate the same
principle in one place; their detailed findings are in that slide's notes.
The toy bound is not presented as either libpng function's actual contract.
The harness explanation includes the full request/response flow, and one
conclusion returns to the opening question. The closing system diagram is
the only deliberate overview recap. Evaluation setup, verdict agreement,
and the bounded/unbounded comparison answer distinct experimental questions.

## Style and figures

The compact local theme adapts the FHNW yellow (`253,231,14`), charcoal
(`45,55,60`), teal (`0,110,110`), red (`210,5,55`), yellow title band,
dashed title separator, and footer treatment from
`../../sysad/template/fhnwbeam.sty`, the reference supplied for this task.
That file credits Ivan Giangreco's February 2015 Basel adaptation of the
Torino Beamer theme. The deck uses Latin Modern sans serif with pdfLaTeX.
It preserves the reference's 16:9 proportions but simplifies the theme's
course and bibliography machinery for a standalone conference talk.

`theme/fhnw-logo.png` and `theme/swissuniversities.png` are unchanged copies
of the reference repository's `header.png` and `swissuniversity.png`.
Institutional marks retain their original ownership. All new figures are
native TikZ, including the numerical charts; logo artwork is reused intact.

## Sources and interpretation

Experimental results for klee-mcp come from `../paper/klee-mcp-kes.pdf`, checked
against its LaTeX source. Source provenance is recorded here, without
self-citations or third-person descriptions of our work on the slides. The final backup slide lists foundational
work by other authors. The diagrams are
conceptual explanations, not measured coverage or deployment diagrams.
The benchmark chart aggregates the 14 rows of **Table 2** into four groups.
These are reported paper results, not a new benchmark execution.

The supplied paper contains numerical inconsistencies. To avoid repeating
them, the presentation uses the table rows for numerical summaries:

- Table 2 has **9 confirmed and 5 infeasible** rows; the surrounding prose
  says 7 and 7.
- The median of Table 2's displayed times is **3.25 seconds**, whereas the
  prose says 2.4 seconds. The main slides show only the table's
  **0.9–42.9 second range**.
- Table 2 has 9 confirmed rows and Table 3 has 3 confirmed runs, while the
  classifier discussion claims 10 total across both tables. The deck
  does not repeat a classifier agreement count.
- The baseline paragraph's 60-second unbounded timeout is a distinct
  reported experiment from the 9.4-second unbounded sensitivity row.
  The deck does not merge these or infer a general speedup.

The presentation preserves the paper's scope: agreement on hand-constructed
cases is not external precision or recall; local errors require caller
context; automatic impact labels need review; and whole-library linking
does not imply comprehensive coverage. It distinguishes the historical
CVE case from the separate defense-in-depth internal-helper finding.
The manuscript and analysis implementation are unchanged.

## External opening example: curl

The opening cites Daniel Stenberg's primary accounts:

- [The end of the curl bug-bounty (26 January 2026)](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/).
- [High-Quality Chaos (22 April 2026)](https://daniel.haxx.se/blog/2026/04/22/high-quality-chaos/).

The sub-5% figure describes all security submissions in the stated period,
not a measured false-positive rate for AI alone. April's update prevents
presenting the earlier slop episode as the current situation. curl is a
motivation example, not a target evaluated in this work. Checked 10 September
2026. The conclusion about independent verification is our interpretation.
