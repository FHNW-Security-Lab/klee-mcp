# Paper sources — KES 2026 / IS48

Submission to KES 2026 Invited Session 48
(*Artificial Intelligence in Cybersecurity: Emerging Trends in Defensive
and Offensive Operations*), Royal Marine Hotel, Dublin, 9–11 September 2026.

## Files

| File | Purpose |
|---|---|
| `klee-mcp-kes-blinded.tex` / `.pdf` | **Submission version**. Authors, affiliation, emails, and the GitHub URL anonymised; self-citations rephrased in third person. 8 pages. |
| `klee-mcp-kes.tex` / `.pdf` | **Camera-ready / archival version** with full author list and code URL. 8 pages. |
| `ecrc.sty`, `elsarticle.cls`, `elsarticle-harv.bst`, `framed.sty` | Elsevier Procedia Computer Science template files (bundled here so the paper compiles standalone). |
| `Procs.{eps,pdf}`, `SDlogo-3p.{eps,pdf}`, `elsevier-logo-3p.{eps,pdf}` | Procedia journal logos referenced by `ecrc.sty`. |

## Build

```
pdflatex klee-mcp-kes.tex          # camera-ready
pdflatex klee-mcp-kes-blinded.tex  # double-blind submission
```

(Run twice each for cross-references.)

## Format

Procedia Computer Science (Elsevier CRC), `procedia` option of
`elsarticle.cls`. KES paper-length cap: 8–10 pages including
references and appendices.

## Review model

KES uses double-blind peer review. The `*-blinded.pdf` is what gets
uploaded to the submission system; the unblinded version is for
post-acceptance camera-ready / repository archival.
