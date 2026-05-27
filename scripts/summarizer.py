# summarizer.py — 3줄 요약 모듈 (sumy 기반)
# 출력 형식: "1. 첫 번째 문장.\n2. 두 번째 문장.\n3. 세 번째 문장."

import re
import nltk
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lsa import LsaSummarizer


def setup_nltk():
    """Actions 환경에서 NLTK 필수 데이터 다운로드"""
    for resource in ['punkt', 'punkt_tab', 'stopwords']:
        try:
            nltk.download(resource, quiet=True)
        except Exception:
            pass


def _count_sentences(text: str) -> int:
    """대략적인 문장 수 계산 (10자 이상 문장만 카운트)"""
    parts = re.split(r'(?<=[.!?。])\s+', text.strip())
    return len([p for p in parts if len(p.strip()) > 10])


MAX_LINE_CHARS = 50  # 번호 뒤 내용 최대 글자 수

def _trim(text: str) -> str:
    """공백 정리 후 MAX_LINE_CHARS 이내로 자르기"""
    t = re.sub(r'\s+', ' ', str(text)).strip()
    return t[:MAX_LINE_CHARS] if len(t) > MAX_LINE_CHARS else t


def _format_numbered(sentences: list) -> str:
    """
    문장 리스트를 번호 형식으로 반환
    - 각 항목 내용은 MAX_LINE_CHARS(15자) 이내
    - 빈 항목·헤더성 텍스트 제외
    """
    result = []
    for i, s in enumerate(sentences[:3], start=1):
        line = _trim(s)
        if len(line) > 3:   # 너무 짧은 헤더성 텍스트 제외
            result.append(f"{i}. {line}")
    return '\n'.join(result)


def summarize_3lines(text: str, lang: str = 'en', translator_fn=None) -> str:
    """
    텍스트에서 3문장 요약 추출 후 번호 형식(1./2./3.) 한국어로 반환

    Args:
        text         : 요약할 원문
        lang         : 원문 언어 코드 ('ko' / 'en' 등)
        translator_fn: translate_to_korean 함수 참조

    Returns:
        "1. ...\n2. ...\n3. ..." 형식 문자열 (한국어)
    """
    if not text or not text.strip():
        return ''

    cleaned = text.strip()

    # ── 문장이 3개 이하면 sumy 생략, 그대로 번호 붙이기 ──────
    if _count_sentences(cleaned) <= 3:
        parts = re.split(r'(?<=[.!?。])\s+', cleaned)
        parts = [p.strip() for p in parts if len(p.strip()) > 10]
        if not parts:
            parts = [cleaned]

        if lang != 'ko' and translator_fn:
            translated_parts = []
            for p in parts[:3]:
                tr, _ = translator_fn(p)
                translated_parts.append(tr or p)
            return _format_numbered(translated_parts)

        return _format_numbered(parts)

    # ── sumy 전처리: 짧은 헤더성 줄 제거 (CISA 등 구조화 콘텐츠 대응) ──
    lines = [l.strip() for l in cleaned.splitlines() if len(l.strip().split()) >= 5]
    cleaned = ' '.join(lines) if lines else cleaned
    # 연속 공백 정리
    cleaned = re.sub(r'\s{2,}', ' ', cleaned).strip()

    # ── sumy LsaSummarizer로 3문장 추출 ──────────────────────
    # konlpy(Java 필요)는 GitHub Actions 환경에서 불가 → 항상 'english' tokenizer 사용
    try:
        parser = PlaintextParser.from_string(cleaned, Tokenizer('english'))
        summarizer = LsaSummarizer()
        sentences = [str(s) for s in summarizer(parser.document, 3)]

        if not any(sentences):
            raise ValueError("빈 요약 결과")

    except Exception as e:
        print(f"  [요약 오류] {e} — 앞 3문장으로 대체")
        parts = re.split(r'(?<=[.!?。])\s+', cleaned)
        sentences = [p.strip() for p in parts if len(p.strip()) > 10][:3]

    # ── 영문이면 번역 ─────────────────────────────────────────
    if lang != 'ko' and translator_fn:
        translated = []
        for s in sentences:
            tr, _ = translator_fn(s)
            translated.append(tr or s)
        return _format_numbered(translated)

    return _format_numbered(sentences)
