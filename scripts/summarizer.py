# summarizer.py — 3줄 요약 모듈
# 우선순위: Gemini 2.5 Flash-Lite → sumy → 앞 3문장 fallback

import re
import time
import nltk
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lsa import LsaSummarizer

MAX_LINE_CHARS = 50  # 각 줄 최대 글자 수


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
    """공백 정리 + MAX_LINE_CHARS 이내로 자르기"""
    t = re.sub(r'\s+', ' ', str(text)).strip()
    return t[:MAX_LINE_CHARS] if len(t) > MAX_LINE_CHARS else t


def _format_numbered(sentences: list) -> str:
    """
    문장 리스트 → 번호 형식 (1.\n2.\n3.)
    각 항목 MAX_LINE_CHARS 이내, 빈 줄 제거
    """
    result = []
    for i, s in enumerate(sentences[:3], start=1):
        line = _trim(s)
        if len(line) > 3:
            result.append(f"{i}. {line}")
    return '\n'.join(result)


def _count_sentences(text: str) -> int:
    parts = re.split(r'(?<=[.!?。])\s+', text.strip())
    return len([p for p in parts if len(p.strip()) > 10])


# ================================================================
# Gemini 요약
# ================================================================

def _summarize_with_gemini(text: str, api_key: str) -> str:
    """
    Gemini 2.5 Flash-Lite로 3줄 요약 생성
    Returns: "1. ...\n2. ...\n3. ..." 형식 or '' (실패 시)
    """
    try:
        import google.generativeai as genai

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.5-flash-lite')

        prompt = f"""다음 보안 뉴스를 한국어로 핵심만 3줄로 요약해줘.

규칙:
- 반드시 아래 형식으로만 답변 (다른 말 없이)
- 각 줄은 {MAX_LINE_CHARS}자 이내
- 번호로 시작

1. (첫 번째 핵심)
2. (두 번째 핵심)
3. (세 번째 핵심)

뉴스 내용:
{text[:3000]}"""

        response = model.generate_content(prompt)
        result = response.text.strip()

        # 형식 검증: 1. 로 시작하는 줄이 있는지 확인
        lines = [l.strip() for l in result.splitlines() if l.strip()]
        numbered = [l for l in lines if re.match(r'^[1-3]\.', l)]

        if len(numbered) >= 2:
            # 각 줄 MAX_LINE_CHARS 적용
            trimmed = []
            for l in numbered[:3]:
                prefix = l[:3]   # "1. "
                body   = l[3:]
                trimmed.append(f"{prefix}{_trim(body)}")
            return '\n'.join(trimmed)

        return ''

    except Exception as e:
        print(f"  [Gemini 오류] {e}")
        return ''


# ================================================================
# sumy fallback 요약
# ================================================================

def _summarize_with_sumy(text: str, translator_fn=None, lang: str = 'en') -> str:
    """sumy LsaSummarizer fallback"""
    cleaned = text.strip()

    # 짧은 헤더 줄 제거 (CISA 등 구조화 콘텐츠 대응)
    lines = [l.strip() for l in cleaned.splitlines() if len(l.strip().split()) >= 5]
    cleaned = re.sub(r'\s{2,}', ' ', ' '.join(lines) if lines else cleaned).strip()

    # 3문장 이하면 sumy 생략
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
        parser    = PlaintextParser.from_string(cleaned, Tokenizer('english'))
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
# 메인 함수 (외부에서 호출)
# ================================================================

def summarize_3lines(
    text: str,
    lang: str = 'en',
    translator_fn=None,
    gemini_api_key: str = '',
) -> str:
    """
    3줄 요약 생성 (우선순위: Gemini → sumy → 앞 3문장)

    Args:
        text            : 요약할 원문
        lang            : 원문 언어 ('ko' / 'en' 등)
        translator_fn   : translate_to_korean 함수 (sumy fallback용)
        gemini_api_key  : Gemini API 키 (있으면 Gemini 우선 사용)

    Returns:
        "1. ...\n2. ...\n3. ..." 형식 문자열
    """
    if not text or not text.strip():
        return ''

    # ── 1순위: Gemini ─────────────────────────────────────────
    if gemini_api_key:
        result = _summarize_with_gemini(text, gemini_api_key)
        if result:
            return result
        print("  [Gemini 실패] sumy로 대체")
        time.sleep(1)  # 실패 후 잠시 대기

    # ── 2순위: sumy ───────────────────────────────────────────
    return _summarize_with_sumy(text, translator_fn=translator_fn, lang=lang)
