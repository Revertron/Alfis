# Apple Silicon (M processors) Patch

This patch automatically configures the Alfis project build for Apple Silicon (M1, M2, M3, M4) processors.

## What the patch includes:

### 1. Automatic C compiler configuration
- Sets `CC_aarch64-apple-darwin="clang -Wno-int-conversion"`
- Suppresses type incompatibility warnings in C code
- Works for both architectures: Apple Silicon and Intel Mac

### 2. Apple Silicon optimizations
- Enables LTO (Link Time Optimization)
- Sets `codegen-units = 1` for better optimization
- Enables `strip = true` to reduce binary size
- Configures `panic = "abort"` for better performance

### 3. GUI settings
- Automatically links Cocoa and WebKit frameworks
- Configures proper linker flags for macOS

## Optimization results:

| Version | Size | Optimization |
|---------|------|-------------|
| Debug   | 7.6 MB | Basic debugging |
| Release | 3.8 MB | Full optimization (-50%) |

## Usage:

### Regular build with GUI:
```bash
cargo build --features webgui
```

### Optimized build:
```bash
cargo build --release --features webgui
```

### Build without GUI:
```bash
cargo build --features "" --no-default-features
```

## Patch files:

- `.cargo/config.toml` - main Cargo configuration
- Automatically applied on every build
- Requires no additional user actions

## Compatibility:

- ✅ Apple Silicon (M1, M2, M3, M4)
- ✅ Intel Mac (for cross-compilation)
- ✅ macOS 10.15+ (Catalina and newer)
- ✅ Rust 1.70+

## Troubleshooting:

If you encounter C code compilation issues, make sure:
1. Xcode Command Line Tools are installed: `xcode-select --install`
2. Using the latest Rust version: `rustup update`
3. Clear build cache: `cargo clean`

## Technical details:

The patch solves the compilation issue with the `webview-sys` library, which contains C code with type incompatibility warnings. The `-Wno-int-conversion` flag suppresses these warnings, allowing the build to complete successfully on modern Clang versions.
