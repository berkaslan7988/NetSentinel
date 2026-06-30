# NetSentinel — Tasarım Notları

Kalıcı kararlar ve tercihler. Faz ilerledikçe buraya eklenir.

## UI / Dashboard yönü (Faz 7)
- **NetScope tarzı OLMAYACAK.** Kullanıcı tercihi: **terminal / "hacker" estetiği.**
- Hedeflenen his: koyu zemin, monospace font (örn. JetBrains Mono / Cascadia Code),
  yeşil/amber "fosfor terminal" vurguları, ASCII/box-drawing aksanlar, log-akışı
  görünümü, retro CRT dokunuşları (hafif scanline/glow opsiyonel).
- pyqtgraph grafikleri de bu palete uyacak (koyu zemin, neon çizgiler).
- Yine de profesyonel ve okunur kalmalı; "tema" abartıya kaçıp veriyi gölgelememeli.

## Feature Engineering (Faz 2)
- Hedef: CIC-IDS2017 ile **birebir kolon isimleri ve sırası** (78 özellik + Label).
- **Birim:** Flow Duration ve tüm IAT değerleri **mikrosaniye** (CIC standardı).
  Flow Bytes/s = toplam payload baytı / saniye.
- **"Packet length" = L4 payload uzunluğu** (full frame değil).
- Tam sadakatle üretilenler: sayımlar, payload uzunluk istatistikleri, IAT
  (flow/fwd/bwd), hızlar, flag sayaçları, down/up oranı, segment boyutları,
  subflow, init window, act_data_pkt_fwd, min_seg_size_forward.
- Yaklaşık/dokümante edilen (CICFlowMeter'ın bilinen tuhaflıkları): header length
  (prensipli IP+L4), bulk özellikleri (0 — veri setinde de ~hep 0), active/idle
  (CIC tarzı 5sn eşikli segmentasyon).
