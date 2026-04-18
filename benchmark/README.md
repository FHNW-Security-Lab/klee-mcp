# Benchmark

Two tiers:

1. **Hand-authored sanity set** (`benchmark/candidates/*.json`) — one
   candidate per file under `examples/`. This is what `run_bench.py`
   drives by default and what the paper uses as a baseline reproduction.
2. **Juliet Test Suite** (not vendored here). Download the C/C++ drop
   from NIST SARD and convert each test into a candidate JSON. A
   converter skeleton will live at `benchmark/juliet_to_candidates.py`.

## Running

```
source .venv/bin/activate
python benchmark/run_bench.py
```

Produces `benchmark/results.csv` with columns:

- `name`: test case
- `expected`: ground-truth verdict (derived from `safe_` prefix → infeasible, else confirmed)
- `verdict`: what KLEE actually returned
- `cwe`
- `wall_seconds`
- `notes`

## Paper metrics to compute from this CSV

- **Validation rate** (confirmed ∪ infeasible) / total — how often KLEE
  reaches a verdict at all.
- **Accuracy on ground truth** — rows where `verdict == expected`.
- **Time per validated candidate** — mean, p95.
- **False-positive rescue rate** — among `safe_*` candidates the LLM
  flagged, how many does KLEE correctly mark infeasible? This is the
  headline number for the paper.
