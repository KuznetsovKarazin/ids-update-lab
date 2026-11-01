# miniz inflater provenance

Vendored upstream miniz tag **3.0.2**, fetched from
https://github.com/richgel999/miniz/tree/3.0.2 . Upstream copyright and MIT license
are retained in `miniz_tinfl.c` and `LICENSE`; upstream authorship is not reassigned.

Files: `miniz_tinfl.c`, `miniz_tinfl.h`, `miniz_common.h`, `LICENSE`.
Integration authored by Oleksandr Kuznetsov:

- `miniz_tinfl.c` includes its standalone `miniz_tinfl.h` rather than aggregate
  `miniz.h`. No decompression algorithm changes.
- `miniz_export.h` supplies an empty visibility macro for the embedded/static build.
- `miniz_tinfl.h` prefixes all six exported inflater functions with `ids039_`.
  ESP32-S3's ROM linker script assigns the original `tinfl_*` names to an older
  decoder with an incompatible context layout. The namespace prevents those
  absolute ROM symbols from replacing the vendored implementation. The build
  checks the updater object's references and the final ELF definition.
- CMake compiles only the inflater. No runtime download or component registry is required.

The headers and the patched source are pinned by the source SHA256 map
in each revision039 build's metadata. The artifact uses the zlib wrapper and Adler32
check in addition to the signed target-image SHA256 check performed by the updater.
