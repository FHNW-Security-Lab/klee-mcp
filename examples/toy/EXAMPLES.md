# Ground-truth examples

Minimal programs used to sanity-check the pipeline. Each declares exactly
one function the harness drives symbolically.

| File                  | Target function      | CWE     | Expected verdict | Notes |
|-----------------------|----------------------|---------|------------------|-------|
| `bof_01.c`            | `vulnerable_copy`    | CWE-121 | confirmed        | buf[len] write with len up to 256 into 16-byte stack buffer |
| `null_01.c`           | `read_magic`         | CWE-476 | confirmed        | cfg pointer never checked for NULL |
| `intoverflow_01.c`    | `compute_capacity`   | CWE-190 | confirmed        | count*per_entry wraps |
| `uaf_01.c`            | `process_record`     | CWE-416 | confirmed        | buf freed on mode==0 path, read when tag==0x42 |
| `safe_01.c`           | `safe_copy`          | CWE-121 | infeasible       | negative control — bound is correct |

Suggested taint specs for each (the harness auto-infers, but if you want
explicit sizes):

- `vulnerable_copy`: `buf` pointer size 256 (not null-terminated), `len` scalar.
- `read_magic`: `cfg` pointer size `sizeof(cfg_t)=40`, `fallback` scalar.
  Note: to reach the NULL-deref branch, declare `cfg` as scalar `size_bytes=8`
  (pointer value itself symbolic) OR omit it from taints so it defaults to 0.
- `compute_capacity`: `count` and `per_entry` both scalar (4 bytes each).
- `process_record`: `mode` and `tag` scalar (1 byte each).
- `safe_copy`: same as vulnerable_copy — KLEE should prove infeasibility.
