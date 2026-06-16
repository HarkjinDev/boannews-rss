# summarizer.py — 3줄 요약 모듈
# 우선순위: Gemini 2.5 Flash-Lite → Groq (llama-3.3-70b) → sumy → 앞 3문장

import re
import time
import nltk
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lsa import LsaSummarizer

MAX_LINE_CHARS   = 50  # 각 줄 최대 글자 수
GEMINI_FAIL_LIMIT = 2  # Gemini 연속 실패 N회 → Groq 전환
GROQ_FAIL_LIMIT   = 2  # Groq   연속 실패 N회 → sumy 전환

# 실행 세션 내 상태
_gemini_fail_count = 0
_gemini_disabled   = False
_groq_fail_count   = 0
_groq_disabled     = False


# ================================================================
# NLTK 초기화
# ================================================================

def setup_nltk():
    for resource in ['punkt', 'punkt_tab', 'stopwords']:
        try:
            nltk.download(resource, quiet=True)
        except Exception:
            pass


# ================================================================
# 공통 유틸
# ================================================================

def _trim(text: str) -> str:
    t = re.sub(r'\s+', ' ', str(text)).strip()
    return t[:MAX_LINE_CHARS] if len(t) > MAX_LINE_CHARS else t


def _format_numbered(sentences: list) -> str:
    result = []
    for i, s in enumerate(sentences[:3], start=1):
        line = _trim(s)
        if len(line) > 3:
            result.append(f"{i}. {line}")
    return '\n'.join(result)


def _count_sentences(text: str) -> int:
    parts = re.split(r'(?<=[.!?。])\s+', text.strip())
    return len([p for p in parts if len(p.strip()) > 10])


def _build_prompt(text: str) -> str:
    return f"""다음 보안 뉴스를 한국어로 핵심만 3줄로 요약해줘.

규칙:
- 반드시 아래 형식으로만 답변 (다른 말 없이)
- 각 줄은 {MAX_LINE_CHARS}자 이내
- 번호로 시작
- 기사에 등장하는 고유명사(기관명·기업명·인물명·악성코드명), 수치(용량·건수·금액), CVE 번호를 반드시 포함할 것
- "우려", "중요", "경각심", "필요" 같은 일반적 표현 사용 금지
- 이 기사에만 해당하는 구체적 사실을 담을 것

1. (주요 사건/공격 대상 + 구체적 수치나 고유명사)
2. (공격 방식/유출 내용 + 구체적 사실)
3. (영향 범위/조치 사항 + 구체적 사실)

뉴스 내용:
{text[:3000]}"""


def _parse_response(text: str) -> str:
    """모델 응답에서 번호 형식 추출 + 각 줄 trim"""
    lines    = [l.strip() for l in text.splitlines() if l.strip()]
    numbered = [l for l in lines if re.match(r'^[1-3]\.', l)]
    if len(numbered) < 2:
        return ''
    trimmed = []
    for l in numbered[:3]:
        prefix = l[:3]
        body   = l[3:]
        trimmed.append(f"{prefix}{_trim(body)}")
    return '\n'.join(trimmed)


# ================================================================
# Gemini 요약
# ================================================================

def _summarize_with_gemini(text: str, api_key: str) -> str:
    global _gemini_fail_count, _gemini_disabled

    if _gemini_disabled:
        return ''

    from google import genai as google_genai
    client = google_genai.Client(api_key=api_key)
    prompt = _build_prompt(text)

    def _call(retry: bool = False) -> str:
        global _gemini_fail_count, _gemini_disabled
        try:
            resp   = client.models.generate_content(
                model='gemini-2.5-flash-lite', contents=prompt)
            result = _parse_response(resp.text.strip())
            if result:
                _gemini_fail_count = 0  # 성공 시 카운터 리셋
            return result
        except Exception as e:
            err = str(e)
            if '429' in err or 'RESOURCE_EXHAUSTED' in err:
                _gemini_fail_count += 1
                print(f"  [Gemini 429] 누적 {_gemini_fail_count}/{GEMINI_FAIL_LIMIT}회")
                if _gemini_fail_count >= GEMINI_FAIL_LIMIT:
                    _gemini_disabled = True
                    print(f"  [Gemini 비활성화] → Groq 전환")
                    return ''
                if not retry:
                    # retry_delay 파싱 후 대기
                    m    = re.search(r'retry_delay.*?seconds:\s*(\d+)',
                                     err, re.DOTALL)
                    wait = int(m.group(1)) + 5 if m else 60
                    print(f"  [Gemini 429] {wait}초 대기 후 재시도...")
                    time.sleep(wait)
                    return _call(retry=True)
            else:
                print(f"  [Gemini 오류] {err[:100]}")
            return ''

    return _call()


# ================================================================
# Groq 요약
# ================================================================

def _summarize_with_groq(text: str, api_key: str) -> str:
    global _groq_fail_count, _groq_disabled

    if _groq_disabled:
        return ''

    try:
        from openai import OpenAI
        client = OpenAI(
            api_key=api_key,
            base_url='https://api.groq.com/openai/v1',
        )
        prompt = _build_prompt(text)

        resp   = client.chat.completions.create(
            model='qwen/qwen3-32b',  # 한국어 강화 모델 (Alibaba 다국어)
            messages=[{'role': 'user', 'content': prompt}],
            max_tokens=200,
            temperature=0.3,
        )
        result = _parse_response(resp.choices[0].message.content.strip())
        if result:
            _groq_fail_count = 0  # 성공 시 카운터 리셋
        return result

    except Exception as e:
        err = str(e)
        _groq_fail_count += 1
        print(f"  [Groq 오류] 누적 {_groq_fail_count}/{GROQ_FAIL_LIMIT}회 — {err[:100]}")
        if _groq_fail_count >= GROQ_FAIL_LIMIT:
            _groq_disabled = True
            print(f"  [Groq 비활성화] → sumy 전환")
        return ''


# ================================================================
# sumy fallback
# ================================================================

def _summarize_with_sumy(text: str, translator_fn=None, lang: str = 'en') -> str:
    cleaned = text.strip()

    # 짧은 헤더 줄 제거 (CISA 등 구조화 콘텐츠 대응)
    lines   = [l.strip() for l in cleaned.splitlines()
               if len(l.strip().split()) >= 5]
    cleaned = re.sub(r'\s{2,}', ' ',
                     ' '.join(lines) if lines else cleaned).strip()

    # 3문장 이하 → sumy 생략
    if _count_sentences(cleaned) <= 3:
        parts = re.split(r'(?<=[.!?。])\s+', cleaned)
        parts = [p.strip() for p in parts if len(p.strip()) > 10] or [cleaned]
        if lang != 'ko' and translator_fn:
            translated = []
            for p in parts[:3]:
                tr, _ = translator_fn(p)
                translated.append(tr or p)
            return _format_numbered(translated)
        return _format_numbered(parts)

    try:
        parser     = PlaintextParser.from_string(cleaned, Tokenizer('english'))
        summarizer = LsaSummarizer()
        sentences  = [str(s) for s in summarizer(parser.document, 3)]
        if not any(sentences):
            raise ValueError("빈 요약 결과")
    except Exception as e:
        print(f"  [sumy 오류] {e} — 앞 3문장 사용")
        parts     = re.split(r'(?<=[.!?。])\s+', cleaned)
        sentences = [p.strip() for p in parts if len(p.strip()) > 10][:3]

    if lang != 'ko' and translator_fn:
        translated = []
        for s in sentences:
            tr, _ = translator_fn(s)
            translated.append(tr or s)
        return _format_numbered(translated)

    return _format_numbered(sentences)


# ================================================================
# 메인 함수
# ================================================================

def summarize_3lines(
    text: str,
    lang: str = 'en',
    translator_fn=None,
    gemini_api_key: str = '',
    groq_api_key:   str = '',
) -> str:
    """
    3줄 요약 (우선순위: Gemini → Groq → sumy)

    Gemini 2회 연속 실패 → 세션 내 Groq 전환
    Groq   2회 연속 실패 → 세션 내 sumy  전환
    """
    if not text or not text.strip():
        return ''

    # ── 1순위: Gemini ──────────────────────────────────────────
    if gemini_api_key and not _gemini_disabled:
        result = _summarize_with_gemini(text, gemini_api_key)
        if result:
            return result

    # ── 2순위: Groq ────────────────────────────────────────────
    if groq_api_key and not _groq_disabled:
        result = _summarize_with_groq(text, groq_api_key)
        if result:
            return result

    # ── 3순위: sumy ────────────────────────────────────────────
    return _summarize_with_sumy(text, translator_fn=translator_fn, lang=lang)
