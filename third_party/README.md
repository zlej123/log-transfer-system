# Vendored dependencies

Only files required to build this project are retained. Upstream test corpora,
examples, unused platform backends, changelogs, and contributor documentation
are intentionally omitted.

- **Dear ImGui**: core sources plus the Win32 and DirectX 11 backends used by
  `log_client_gui`. License: `imgui/LICENSE.txt`.
- **Mbed TLS 3.6.4**: headers, libraries, required third-party crypto code, and
  CMake/Python build support. Its upstream test certificates and framework data
  are not product inputs. License: `mbedtls/LICENSE`.

Dependency versions and integrity are validated by clean Linux and Windows
builds in GitHub Actions.
