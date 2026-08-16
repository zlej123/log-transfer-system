# Vendored dependencies

Only files needed to build this project are retained: product sources, their
headers, licenses, and the upstream build machinery those sources depend on.
Upstream test corpora, examples, unused platform backends, changelogs, and
contributor documentation are omitted.

- **Dear ImGui**: core sources plus the Win32 and DirectX 11 backends used by
  `log_client_gui`. License: `imgui/LICENSE.txt`.
- **Mbed TLS 3.6.4**: headers, libraries, required third-party crypto code, and
  the CMake/Python build support it invokes. Note that
  `mbedtls/CMakeLists.txt` runs `mbedtls/scripts/config.py` during configure,
  and that script imports `mbedtls_framework` from `mbedtls/framework/scripts`,
  so both directories are build inputs even though they look like tooling.
  Upstream test certificates and framework data are not build inputs and are
  omitted. License: `mbedtls/LICENSE`, framework under `mbedtls/framework/LICENSE`.

Dependency completeness is validated by clean Linux and Windows builds in
GitHub Actions; a missing build input shows up as a configure-time traceback.
