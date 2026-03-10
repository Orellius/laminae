# Benchmarks

See the full [BENCHMARKS.md](https://github.com/orellius/laminae/blob/main/BENCHMARKS.md) in the repository root for detailed numbers.

## Summary

| Layer | Operation | Typical Time |
|-------|-----------|-------------|
| Glassbox | Input/output validation | ~250 ns – 4 µs |
| Ironclad | Binary validation | ~1.1 µs |
| Persona | Voice filter (1000 chars) | ~12 µs |
| Shadow | Static analysis (50 lines) | ~31 ms |
| Shadow | Secrets analysis (100 lines) | ~430 µs |
| Cortex | Track edit | ~85 ns |
| Cortex | Detect patterns (100 edits) | ~426 µs |

## Running Benchmarks

```bash
# All crates
cargo bench --workspace

# Specific crate
cargo bench -p laminae-glassbox

# Specific benchmark
cargo bench -p laminae-shadow -- static_analyzer

# HTML reports
cargo bench --workspace
open target/criterion/report/index.html
```
