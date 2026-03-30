# Empusa Modules

Compilable multi-language plugins managed by the **Module Workshop** (menu option 9).

## Structure

Each module lives in its own subdirectory with a `module.json` manifest:

```txt
modules/
├-- my_module/
│   ├-- module.json    # Manifest: language, compiler, compile command
│   ├-- main.c         # Source file
│   └-- build/         # Compiled output (auto-created)
```

## module.json

```json
{
    "name": "my_module",
    "language": "c",
    "description": "What this module does",
    "compiler": "gcc",
    "source": "main.c",
    "compile_cmd": "gcc {source} -o {output}",
    "target_os": "linux",
    "output": "my_module"
}
```

### Placeholders

| Placeholder | Resolves To |
|-------------|-------------|
| `{source}` | Full path to the source file |
| `{output}` | Full path to the output binary |
| `{build_dir}` | The `build/` directory inside the module |
| `{source_dir}` | The module's root directory |

## Supported Languages

| Language | Key | Extensions | Default Compiler |
|----------|-----|-----------|-----------------|
| C | `c` | `.c` | gcc |
| C++ | `cpp` | `.cpp` | g++ |
| C# | `csharp` | `.cs` | dotnet |
| Rust | `rust` | `.rs` | cargo |
| Go | `go` | `.go` | go |
| Perl | `perl` | `.pl` | perl |
| Make | `make` | Makefile | make |

## Cross-Compilation

Use the `compiler` field to target different platforms:

```json
{
    "compiler": "x86_64-w64-mingw32-gcc",
    "compile_cmd": "x86_64-w64-mingw32-gcc {source} -o {output}",
    "target_os": "windows"
}
```

## Hook Integration

The `post_compile` hook fires after every successful build with context:

```python
{
    "module_name": "my_module",
    "language": "c",
    "output_path": "/path/to/build/my_module",
    "build_dir": "/path/to/build/",
    "source": "/path/to/main.c"
}
```

## Important

- Empusa **compiles only** - it never auto-launches built binaries.
- Use responsibly and only where you have explicit authorization.
