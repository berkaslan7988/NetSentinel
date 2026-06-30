# NetSentinel - Design Notes

Persistent decisions and preferences. Appended as the project evolves.

## UI / Dashboard direction (Phase 7)
- **NOT NetScope-style.** User preference: a **terminal / "hacker" aesthetic.**
- Target feel: dark background, monospace font (e.g. JetBrains Mono / Cascadia Code),
  green/amber "phosphor terminal" accents, ASCII/box-drawing touches, a log-stream
  look, optional subtle retro CRT scanline/glow.
- pyqtgraph charts follow the same palette (dark background, neon lines).
- Still professional and readable; the "theme" must not overpower the data.

## Feature Engineering (Phase 2)
- Goal: **exact CIC-IDS2017 column names and order** (78 features + Label).
- **Units:** Flow Duration and all IAT values in **microseconds** (CIC standard).
  Flow Bytes/s = total payload bytes / second.
- **"Packet length" = L4 payload length** (not the full frame).
- Reproduced with full fidelity: counts, payload length stats, IAT (flow/fwd/bwd),
  rates, flag counters, down/up ratio, segment sizes, subflow, init window,
  act_data_pkt_fwd, min_seg_size_forward.
- Approximate / documented (known CICFlowMeter quirks): header length (principled
  IP+L4), bulk features (0 - also ~always 0 in the dataset), active/idle (5s
  threshold).

## Alerting (Phase 5)
- The Autoencoder over-flags normal traffic live because its features come from
  CICFlowMeter, not from our live extractor. Fixed with an **RF-weighted risk
  score** + unsupervised **agreement**: a single AE flag no longer makes a THREAT.
  A deeper fix (live-benign calibration of the AE threshold) remains an option.
