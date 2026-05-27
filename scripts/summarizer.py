# summarizer.py — 3줄 요약 모듈 (sumy 기반)

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


def summarize_3lines(text: str, lang: str = 'en', translator_fn=None) -> str:
    """
    텍스트에서 3문장 요약 추출 후 한국어로 반환

    Args:
        text         : 요약할 원문
        lang         : 원문 언어 코드 ('ko' / 'en' 등)
        translator_fn: translate_to_korean 함수 참조
                       (영문 요약 → 한국어 변환에 사용)

    Returns:
        3줄 요약 문자열 (한국어)
        텍스트가 짧거나 요약 실패 시 원문(또는 번역문) 반환
    """
    if not text or not text.strip():
        return ''

    cleaned = text.strip()

    # ── 문장이 3개 이하면 sumy 생략 ──────────────────────────
    if _count_sentences(cleaned) <= 3:
        if lang != 'ko' and translator_fn:
            translated, _ = translator_fn(cleaned)
            return translated or cleaned
        return cleaned

    # ── sumy LsaSummarizer로 3문장 추출 ──────────────────────
    try:
        tokenizer_lang = 'korean' if lang == 'ko' else 'english'
        parser = PlaintextParser.from_string(cleaned, Tokenizer(tokenizer_lang))
        summarizer = LsaSummarizer()
        sentences = summarizer(parser.document, 3)
        summary = ' '.join(str(s) for s in sentences)

        if not summary.strip():
            raise ValueError("빈 요약 결과")

    except Exception as e:
        print(f"  [요약 오류] {e} — 앞 3문장으로 대체")
        parts = re.split(r'(?<=[.!?。])\s+', cleaned)
        parts = [p for p in parts if len(p.strip()) > 10]
        summary = ' '.join(parts[:3])

    # ── 영문 요약이면 한국어로 번역 ──────────────────────────
    if lang != 'ko' and translator_fn:
        translated, _ = translator_fn(summary)
        return translated or summary

    return summary
