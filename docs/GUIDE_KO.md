# 🔎 Provenance Mirror — 신호 완전 가이드

> **대상 독자**: 파일의 출처를 신뢰할 수 있는지 판단하거나, 어떤 문서 사본이
> 유출됐는지 추적하려는 누구나. 각 신호가 무엇을·언제 발화하고 판정을 어떻게
> 읽는지 설명합니다.
>
> **관련**: [README_KO](../README_KO.md) · [CHANGELOG](../CHANGELOG.md)
> **English**: [GUIDE.md](GUIDE.md)

---

## 철학: 검증기, 탐지기 아님

**탐지기**는 픽셀로 "가짜"를 추측합니다 — 군비경쟁에 갇힌 학습 분류기. **검증기**는
결정론적 출처·무결성 신호를 검사합니다 — 서명, 선언된 출처, 컨테이너 구조. 출처거울은
검증기이고, 가장 가치 있는 출력은 탐지기가 거부하는 정직한 것 —
**`UNVERIFIED` — "모르겠다"**.

| 방향 | 예시 | 판정 효과 |
|---|---|---|
| 거짓양성 | 서명 없는 진짜 사진을 "AI 가짜"로 낙인 | `UNVERIFIED` 반환, 절대 고발 안 함 |
| 놓친 신호 | 출처 없는 유출 | `tamper_anchor` / `trace`가 여전히 귀속 |

서명 없는 진짜 사진은 `UNVERIFIED`이지 "가짜"가 아닙니다. 무고한 자에게 낙인 안
찍는 것이 전부입니다.

---

## 두 가지 능력

```
verify(파일)                          trace(유출본)
  ├─ ① c2pa_manifest                   ├─ 박힌 지문 디코드
  ├─ ② generator_meta                  ├─ 배포 원장 대조
  ├─ ③ ai_watermark        ┌──────────┤   → CONFIRMED / FINGERPRINT-ONLY /
  ├─ ④ tamper_anchor ──────┘ 공유         DOC-KNOWN / HASH-MATCH / UNTRACEABLE
  └─ ⑤ format_integrity      원장
        │                              distribute(텍스트, 수령자)
        ▼                                └─ 보이지 않는 마크 + 기록 봉인
   판정 (정직성 우선 종합)
```

둘 다 같은 체인해시 원장에 기록하므로, `④ tamper_anchor`와 `trace`가 재귀속
메커니즘을 공유합니다.

---

## 신호 레퍼런스

각 프로브는 `Signal(probe, direction, detail)`을 반환하며 `direction`은
`AUTHENTIC` / `SYNTHETIC` / `TAMPERED` / `NONE` 중 하나. 침묵(`NONE`)은 아무것도
증명하지 않습니다 — 신호 부재는 절대 위조의 증거가 아닙니다.

### ① `c2pa_manifest_check(data) → Signal`

**읽는 것**: 박힌 C2PA / Content Credentials 매니페스트.

```python
from provmirror import pm
pm.c2pa_manifest_check(img_bytes)
# AUTHENTIC  — 매니페스트 존재 (서명체인 암호검증은 아직 안 함)
# SYNTHETIC  — 매니페스트 존재 + AI origin 선언 (trainedAlgorithmicMedia)
# NONE       — 매니페스트 없음
```

AI origin을 *선언*하는 매니페스트(생성기가 "ML로 만들었다"고 서명)는 신호를
`SYNTHETIC`으로 뒤집습니다. **PoC 한계**: 매니페스트 존재를 바이트스캔으로 탐지;
암호 서명체인은 아직 검증 안 함 (`c2pa` 라이브러리 필요 — 문서화된 TODO).

### ② `generator_meta_check(data) → Signal`

**읽는 것**: EXIF/XMP/PNG-text에 남은 알려진 AI-생성기 시그니처.

```python
pm.generator_meta_check(b"...Software: Stable Diffusion XL...")
# SYNTHETIC — "AI-generator signature in metadata: Stable Diffusion"
```

마커: Stable Diffusion, Midjourney, DALL·E, Adobe Firefly, ComfyUI, NovelAI 등.
결정론적 스캔 — 존재는 신호, 부재는 무증명(`NONE`).

### ③ `ai_watermark_check(data) → Signal`

**읽는 것**: 선언된 AI 워터마크 / 훈련-미디어 마커.

**PoC 한계**: *선언된* 마커만 탐지. 실제 스테가노그래피 워터마크(SynthID 등)는
벤더 비공개라 NOT-IMPLEMENTED stub. 부재 = "확인 불가"이지 "워터마크 없음"이 아님.

### ④ `tamper_anchor_check(ledger_path, file_hash, origin) → Signal`

**읽는 것**: 원장 — 이 정확한 콘텐츠가 *다른* 선언 출처로 이전에 봉인됐나?

```python
# reuters.com이 사진 봉인; 나중에 troll-farm.ru가 같은 바이트 주장
pm.verify("photo.jpg", origin="reuters.com")     # ⚪ UNVERIFIED, 봉인됨
pm.verify("photo.jpg", origin="troll-farm.ru")   # 🔴 TAMPERED (④ 발화)
```

측정거울 `anchor` 직이식: 바이트의 SHA-256이 신원. 같은 바이트 + 다른 출처 =
재귀속/세탁 → `TAMPERED`. `origin`을 줄 때만 발화.

### ⑤ `format_integrity_check(data) → Signal`

**읽는 것**: 컨테이너 구조 (JPEG/PNG 매직 & 종료 마커, 다중 SOI).

```python
pm.format_integrity_check(truncated_jpeg)   # TAMPERED — EOI 마커 없음
pm.format_integrity_check(spliced_jpeg)     # TAMPERED — 다중 SOI 마커
pm.format_integrity_check(clean_png)        # NONE — 구조 무결
```

무결한 구조는 `NONE`(그 자체로 출처 신호 아님). 명백한 구조 파손만 `TAMPERED`.

---

## 판정 종합

`verify()`는 다섯 신호를 하나의 판정으로 종합합니다. 우선순위가 정직성 정책을
인코딩합니다:

| 우선 | 판정 | 조건 |
|---|---|---|
| 1 | `TAMPERED` | 어느 신호든 TAMPERED |
| 2 | `CONFLICTING` | AUTHENTIC과 SYNTHETIC 둘 다 |
| 3 | `SYNTHETIC` | AI-origin 신호 존재 |
| 4 | `AUTHENTIC-SIGNED` | 출처 서명 존재, 모순 없음 |
| 5 | `UNVERIFIED` | 아무것도 없음 — 정직한 기본값 |

```python
res = pm.verify("photo.jpg", ledger_path="pm_ledger.jsonl", origin="reuters.com")
pm.report(res)
#   Verdict: ⚪ UNVERIFIED
#   No usable signal. UNKNOWN — this is NOT evidence of fakery.
```

`verify()`는 `seal=False`가 아니면 판정(파일해시·출처·신호별 방향)을 원장에
봉인합니다. 원장은 체인해시·추가전용.

---

## 유출 추적

### `distribute(text, *, recipient, doc_id, ledger_path) → dict`

한 수령자용 사본에 지문을 박고 배포 기록을 봉인.

```python
from provmirror import tracing as tr
out = tr.distribute(DOC, recipient="jebi", doc_id="q3-report")
send_to_jebi(out["marked_text"])   # DOC와 육안 동일
```

마크는 수령자 id의 제로폭 문자 비트열, 단어 사이에 삽입. `clean_hash`는 문서를
식별(마크 무관), `marked_hash`는 이 정확한 사본을 식별.

### `trace(leaked_text, *, ledger_path) → dict`

등장한 사본을 귀속. 전략(신뢰도 높은 순):

| 판정 | 조건 |
|---|---|
| `CONFIRMED` | 지문이 수령자를 가리킴 + 정확한 바이트가 봉인 기록과 일치 |
| `FINGERPRINT-ONLY` | 지문이 수령자 지목하나 사본이 이후 수정됨 |
| `HASH-MATCH` | 읽을 지문 없으나 정확한 배포 바이트가 봉인 사본과 일치 |
| `DOC-KNOWN` | 문서 식별, 수령자 미상 (지문 제거됨/재타이핑됨) |
| `UNTRACEABLE` | 지문도 일치 기록도 없음 |

### `fingerprint_text` / `read_fingerprint`

봉인 없이 마크/디코드만 하는 저수준 코덱:

```python
marked = tr.fingerprint_text(DOC, "jebi")   # 보이지 않는 마크
tr.read_fingerprint(marked)                  # → "jebi"
tr._strip_marks(marked) == DOC               # True — 육안 동일
```

**정직한 한계**: 복붙은 버팀; 재타이핑·OCR·스크린샷·의도적 제로폭 제거엔 못 버팀.
귀속은 *사본*을 지목하지 사람을 지목 안 함. 암호화 아닌 난독화.

---

## 워크플로우

### 워크플로우 1: 인바운드 파일 검증

```python
from provmirror import pm
res = pm.verify("/inbox/screenshot.png", ledger_path="pm_ledger.jsonl",
                origin="slack:#general")
pm.report(res)
# UNVERIFIED → 미상 (증거로 신뢰 말고, 가짜로 낙인도 말 것)
# SYNTHETIC  → AI-origin 메타데이터 발견
# TAMPERED   → 재귀속 또는 구조 파손
```

### 워크플로우 2: 기밀문서 배포 + 유출 추적

```python
from provmirror import tracing as tr
LEDGER = "~/mirror_ledgers/provenance.jsonl"
for who in ["jebi", "sonnet", "ext-partner-07"]:
    out = tr.distribute(report_text, recipient=who, doc_id="q3", ledger_path=LEDGER)
    deliver(who, out["marked_text"])
# 나중에: tr.trace(leaked, ledger_path=LEDGER) → 누구
```

### 워크플로우 3: 콘텐츠 재귀속 탐지

```python
# 발행 자산마다 진짜 출처로 봉인
pm.verify("press_photo.jpg", origin="our-newsroom", ledger_path=LEDGER)
# 같은 바이트가 다른 주장 출처로 재등장 → TAMPERED
```

---

## 퀵 레퍼런스

| # | 신호 | 방향 | 발화 경로 |
|---|---|---|---|
| ① | `c2pa_manifest_check` | AUTHENTIC / SYNTHETIC | `verify` |
| ② | `generator_meta_check` | SYNTHETIC | `verify` |
| ③ | `ai_watermark_check` | SYNTHETIC | `verify` |
| ④ | `tamper_anchor_check` | TAMPERED | `verify(origin=...)` |
| ⑤ | `format_integrity_check` | TAMPERED | `verify` |
| — | `distribute` / `trace` | — | 유출 추적 |
| — | `badge` | — | 판정 배지 (markdown/svg) |

**판정 심각도**: `TAMPERED` > `SYNTHETIC` > `CONFLICTING` > `AUTHENTIC-SIGNED` >
`UNVERIFIED`.

---

*측정거울의 자매로, 하나의 규율 아래 제작:*
*증명 가능한 것만, 나머진 "모른다"고.*
