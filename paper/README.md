# Paper sources — KES 2026 / IS48

Submission to KES 2026 Invited Session 48
(*Artificial Intelligence in Cybersecurity: Emerging Trends in Defensive
and Offensive Operations*), Royal Marine Hotel, Dublin, 9–11 September 2026.

## Files

| File | Purpose |
|---|---|
| `klee-mcp-kes.tex` / `.pdf` | **Submission paper.** Christopher Scherb, Alexander Trapp, Ruben Hutter, Nico Bachmann, Luc Bryan Heitz (all FHNW University of Applied Sciences and Arts Northwestern Switzerland). 8 pages in the Elsevier Procedia Computer Science layout — within the KES 8–10 page cap. |
| `ecrc.sty`, `elsarticle.cls`, `elsarticle-harv.bst`, `framed.sty` | Procedia Computer Science template files (bundled here so the paper compiles standalone). |
| `Procs.{eps,pdf}`, `SDlogo-3p.{eps,pdf}`, `elsevier-logo-3p.{eps,pdf}` | Procedia journal logos referenced by `ecrc.sty`. |

## Build

```
pdflatex klee-mcp-kes.tex
pdflatex klee-mcp-kes.tex   # second pass for cross-references
pdflatex klee-mcp-kes.tex   # third pass for final layout
```

## Format

Procedia Computer Science (Elsevier CRC), `procedia` option of
`elsarticle.cls`. KES paper-length cap: **8–10 pages including
references and appendices**.

## Review model

KES 2026's official submission page does not specify whether reviews are
double-blind or single-blind. Authors and affiliation are visible in
this submission file; if the venue clarifies a double-blind requirement
prior to the deadline, prepare an anonymised variant.
