# KES 2026 presentation

An English, 16:9 Beamer presentation of **Closing the Triage Loop:
MCP-mediated KLEE Validation of LLM-Reported C/C++ Vulnerabilities**.
The talk is planned for **20 minutes**, with 17 main slides and 3 backup
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
| 1 | Title and context | 0:30 | 0:30 |
| 2 | Audience hook: would you report it? | 1:00 | 1:30 |
| 3 | The triage gap | 1:00 | 2:30 |
| 4 | Symbolic execution primer | 1:00 | 3:30 |
| 5 | Architecture | 1:00 | 4:30 |
| 6 | Candidate specification | 1:30 | 6:00 |
| 7 | Verdict semantics | 1:00 | 7:00 |
| 8 | Bounds as caller contracts | 1:30 | 8:30 |
| 9 | Retracting assumptions | 1:30 | 10:00 |
| 10 | Evaluation setup | 1:00 | 11:00 |
| 11 | Benchmark results | 1:30 | 12:30 |
| 12 | Within-KLEE baseline | 1:00 | 13:30 |
| 13 | Historical CVE and contracts | 1:30 | 15:00 |
| 14 | Caller reachability | 1:00 | 16:00 |
| 15 | Limitations | 1:30 | 17:30 |
| 16 | Contributions | 1:00 | 18:30 |
| 17 | Return to the opening question | 1:30 | 20:00 |

The opening invites a short show of hands. The closing includes a pause
and invitation to questions. Backup slides contain the detailed benchmark,
cross-library results, and source references. No live demo is required.

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

All empirical statements come from `../paper/klee-mcp-kes.pdf`, checked
against its LaTeX source. Slides cite the relevant paper sections/tables;
the final backup slide gives bibliographic details. The diagrams are
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
