# Upstream review snapshot

These two patches reproduce the prepared upstream candidate. They are **not** the final PR split. The [roadmap](../docs/UPSTREAM_PLAN.md) explains how to turn the reference into small independently reviewable changes.

The snapshot includes untested Ethernet gateway support. No configuration checks, builds, tests or patch-application checks were run after that change. The commands below are instructions for a future review run, not results for this source revision.

The external components on the main branch target Stock ESPHome 2026.9.1. The upstream snapshot starts from ESPHome dev commit `c56bb140379962d69d6f02e8a683a64bdfef40a5` and applies the generic provider foundation followed by the mesh review patch. Integration glue differs between these artifacts; do not compare their full-tree hashes as if they were interchangeable.

```sh
git clone https://github.com/esphome/esphome.git esphome-review
cd esphome-review
git checkout c56bb140379962d69d6f02e8a683a64bdfef40a5
git apply /path/to/esphome-mesh/upstream/patches/0001-network-providers.patch
git apply /path/to/esphome-mesh/upstream/patches/0002-mesh-review.patch
script/setup
source venv/bin/activate
GTEST_FILTER='Mesh*:NativeWifi*' python script/cpp_unit_test.py mesh
python -m pytest -q --no-cov tests/unit_tests/components/mesh \
  tests/unit_tests/components/test_espnow.py::test_esp32_auto_loads_the_common_sdk_owner \
  tests/unit_tests/components/test_espnow.py::test_esp8266_does_not_load_the_esp32_sdk_owner
python script/test_build_components.py -e config -c mesh --isolate mesh
```

For explicit native compilation or upstream CI:

```sh
python script/test_build_components.py -e compile -c mesh --isolate mesh
```

The focused counts are 219 C++ cases and 23 Python cases plus six subtests. The C++ runner enables ASan/UBSan. Foundation tests remain in their own upstream suites; the filter only selects the Mesh regression scope for this command. Four native profiles and two config-only chip variants are retained. Tests are supplementary to the still-incomplete manual handover acceptance case.

Do not submit the combined mesh patch as one PR: it exceeds the normal upstream size cap. Individual PRs need real dependency links, tests and self-contained descriptions. No upstream PR from this series has been published yet.
