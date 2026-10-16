# Contributing

Please use issues in this repository for experimental mesh feedback. Include the repo tag or commit, ESPHome/IDF versions, chip/board, IPv4/IPv6 use, topology and a reproducible sequence. A useful report distinguishes native WiFi, mesh route selection, address acquisition and application reachability. Redact credentials and private identifiers.

Architecture and upstream splitting feedback belongs with a stable [roadmap step](docs/UPSTREAM_PLAN.md). A future ESPHome PR should link to an immutable commit here while remaining self-contained. The roadmap is a proposal, not upstream approval.

Keep protocol/security regressions in the official ESPHome test framework. Avoid broad repeated chip matrices when the compiled code is identical. Four representative native profiles are retained; config-only variants are used where compilation adds no new behavior.

The repo's quick check is:

```sh
python tools/check_examples.py
```

It validates and generates examples using local components and synthetic fixture credentials in a temporary directory. It does not access boards. Upstream C++/Python commands are documented separately in [upstream/README.md](upstream/README.md).

All code comments, public documentation and contribution descriptions should be English. Retain the source licenses and attribution.
