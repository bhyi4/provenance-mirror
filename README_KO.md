# 🔎 Provenance Mirror (출처거울)

<img src="docs/provenance_mirror_og.png" alt="Provenance Mirror" width="500">

**콘텐츠 진위 *검증기* — 딥페이크 *탐지기*가 아닙니다.**
거울 패밀리의 한 거울 — 같은 DNA, 다른 도메인:

| 도구 | 감사 대상 | 질문 |
|---|---|---|
| 🪞 [measure-mirror](https://github.com/bhyi4/measure-mirror) | AI 평가 주장 | **주장**이 정직한가? |
| 🪪 [action-mirror](https://github.com/bhyi4/action-mirror) | 에이전트 행동 | 누가 뭘 했나, **증명 가능하게**? |
| 🔎 **provenance-mirror** (현재 위치) | 콘텐츠 진위 | **출처가 증명되나?** |
| 👁 [mirror-witness](https://github.com/bhyi4/mirror-witness) | 운영자 간 증인 게시판 | 또 **누가 증인** 섰나? |

넷을 합치면 = 🪞🔎🪪 [미러스택](https://github.com/bhyi4/measure-mirror/tree/main/stack).

> 훈련 불요 · 결정론적 · 외부 의존성 없음 (Python 3.10+ stdlib만).

**[📖 프로브 완전 가이드 →](docs/GUIDE_KO.md)** · [English README](README.md)

---

## 핵심 구분

**탐지기**는 픽셀을 보고 "가짜다"를 추측합니다. 이건 학습된 분류기이고 군비경쟁에
갇혀 있어요 — 모든 탐지기가 다음 생성기에게 회피법을 가르칩니다.

**검증기**는 결정론적인 **출처·무결성 신호**를 검사합니다 — 서명, 선언된 출처,
컨테이너 무결성. 추측이 아니라 암호학과 구조죠. 서명은 더 좋은 GAN으로 지워지지 않습니다.

출처거울은 검증기입니다. 가장 중요한 출력은 탐지기가 거부하는 그것 — **"모르겠다"**.

| 판정 | 의미 |
|---|---|
| 🟢 `AUTHENTIC-SIGNED` | 출처 매니페스트 존재 (C2PA / Content Credentials) |
| 🟠 `SYNTHETIC` | AI-origin 신호 존재 (생성기 메타데이터 또는 선언된 assertion) |
| 🔴 `TAMPERED` | 무결성 파손, 또는 같은 바이트가 다른 출처로 재봉인됨 |
| 🟡 `CONFLICTING` | 진위·합성 신호가 충돌 — 조사 필요 |
| ⚪ `UNVERIFIED` | **사용 가능한 신호 없음. 모름 — 이것은 위조의 증거가 아님.** |

마지막 행이 전부입니다: 서명 없는 진짜 사진은 `UNVERIFIED`이지 절대 "가짜"가
아닙니다. 무고한 자에게 낙인 안 찍는 것이 탐지기가 못 주는 가치예요.

---

## 5대 설계 원칙 (측정거울에서 이식)

1. **검증기, 탐지기 아님** — 픽셀로 "가짜" 단정 안 함; 신호만 검사
2. **양방향** — "신호 없음" = UNVERIFIED이지 위조 고발이 아님
3. **불확실성에 정직** — 기본 판정은 `UNVERIFIED`
4. **봉인 원장** — 모든 판정이 SHA-256 체인해시 (변조 감지)
5. **입력 주도** — 파일에 실제 있는 신호만 읽음

---

## 신호

| # | 신호 | 가리키는 곳 | 무엇을 읽나 |
|---|---|---|---|
| ① | `c2pa_manifest` | AUTHENTIC / SYNTHETIC | C2PA / Content Credentials 매니페스트 (AI-assertion이면 SYNTHETIC) |
| ② | `generator_meta` | SYNTHETIC | 메타데이터의 알려진 AI-생성기 시그니처 (Midjourney, SD, DALL·E…) |
| ③ | `ai_watermark` | SYNTHETIC | 선언된 AI 워터마크 / 훈련-미디어 assertion |
| ④ | `tamper_anchor` | TAMPERED | 같은 바이트가 *다른* 출처로 이전 봉인됨 (재귀속) |
| ⑤ | `format_integrity` | TAMPERED | 컨테이너 구조 무결? 이중압축/스플라이스 힌트 |

---

## 사용법

```bash
pip install -e ~/provenance_mirror_poc --user   # 어디서든 `pm`
export PM_LEDGER=~/mirror_ledgers/provenance.jsonl

pm verify photo.jpg                       # 출처/무결성 검증
pm verify photo.jpg --origin reuters.com  # ④ 재귀속 탐지 활성화
pm verify photo.jpg --badge markdown      # 임베드용 배지
```

```python
from provmirror import pm

res = pm.verify("photo.jpg", ledger_path="pm_ledger.jsonl", origin="reuters.com")
print(res["verdict"])          # 예: "UNVERIFIED"
pm.report(res)                 # 전체 신호 분석
print(pm.badge(res))           # shields.io 배지 markdown
```

---

## 유출 추적 (`provmirror.tracing`)

유출을 *막을* 순 없습니다 (읽기 차단 = DRM = 지는 게임). 하지만 유출이 일어났음과
*누구 사본이* 샜는지는 **증명**할 수 있습니다 — 검증기 철학을 배포에 적용한 것.

```bash
# 한 문서를 세 명에게 배포 — 각 사본에 보이지 않는 수령자별 지문
pm distribute secret.txt --to jebi   --doc-id q3 --out copy_jebi.txt
pm distribute secret.txt --to sonnet --doc-id q3 --out copy_sonnet.txt

# 몇 달 뒤 사본이 포럼에 등장 → 누가 흘렸나?
pm trace leaked.txt
# → 🎯 CONFIRMED → recipient='jebi'  (지문 디코드 + 봉인 바이트 일치)
```

| 판정 | 의미 |
|---|---|
| `CONFIRMED` | 지문이 수령자를 가리키고 + 정확한 바이트가 봉인 기록과 일치 |
| `FINGERPRINT-ONLY` | 지문은 수령자를 지목하나, 사본이 이후 수정됨 |
| `HASH-MATCH` | 읽을 수 있는 지문은 없으나, 정확한 배포 바이트가 봉인 사본과 일치 |
| `DOC-KNOWN` | 문서는 식별, 수령자는 미상 (지문 제거됨/재타이핑됨) |
| `UNTRACEABLE` | 지문도 없고 일치 기록도 없음 |

**원리**: 수령자 id를 제로폭 문자(U+200B/U+200C, U+200D 경계) 비트열로 인코딩해
단어 사이에 숨깁니다. 모든 렌더러에서 보이지 않고, 복붙을 버티며, 수령자 id로 디코드됩니다.

**정직한 한계 (클린 유출의 비용을 올리는 것이지 깰 수 없는 것이 아님):**
- 복붙은 버팀; 재타이핑·OCR·스크린샷·의도적 제로폭 제거엔 **못 버팀**. 능숙한
  유출자는 세탁 가능 → `DOC-KNOWN` (어떤 *문서*인지는 증명, 누구인지는 미상).
- 귀속은 *사본*을 지목하지 사람을 지목하지 않음 — 도난당한 사본은 주인을 누명
  씌울 수 있음. 증거이지 판결이 아님.
- 암호화 아닌 난독화 — 제로폭 바이트를 찾는 누구에게나 마크가 보임.

---

## 정직한 한계 (제품 아닌 PoC 뼈대)

**뼈대**는 실재하고 테스트됨; **무거운 암호/ML 신호는 stub**으로 명시:

- **C2PA 서명 체인은 암호학적으로 검증 안 됨** — ① 은 매니페스트 *존재*를 바이트
  스캔으로 탐지; 서명 체인 검증은 `c2pa` 라이브러리 필요 (문서화된 TODO).
- **스테가노그래피 워터마크(SynthID 등)는 못 읽음** — 벤더 비공개; ③ 은 *선언된*
  마커만 봄.
- **픽셀/주파수 분석 없음** — 의도적. 그게 우리가 피하는 탐지기 군비경쟁. 학습
  분류기를 추가하더라도 검증기 *안의* 감사받는 1개 신호로, verdict 전체로는 안 씀.

오늘 견고한 것: verdict 로직, 정직성 보장(`UNVERIFIED` ≠ 가짜), 재귀속 tamper-anchor,
봉인 체인해시 원장 — 모두 zero-dep·결정론. 33 테스트 통과.

---

## 로드맵 (값을 증명하면)

1. 실제 C2PA 서명 체인 검증 (`c2pa` 옵션 의존성)
2. EXIF/XMP 파싱으로 메타데이터 모순 검출
3. MCP 서버 (`pm_verify`, `pm_trace`) — 측정거울 패턴
4. 이미지 지문 (LSB/지각해시, Pillow 옵션)

거울 규율 아래 제작:
**증명 가능한 것만 측정하고, 나머지는 "모른다"고 말한다.**

---

## 라이선스

[Apache 2.0](LICENSE)
