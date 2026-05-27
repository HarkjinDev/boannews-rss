# translator.py — 번역 모듈 (deep-translator 기반)

from deep_translator import GoogleTranslator
from langdetect import detect, LangDetectException


def detect_language(text: str) -> str:
    """
    텍스트 언어 감지
    Returns: 언어 코드 (e.g. 'ko', 'en') 또는 'unknown'
    """
    try:
        cleaned = text.strip()
        if not cleaned or len(cleaned) < 10:
            return 'unknown'
        return detect(cleaned)
    except LangDetectException:
        return 'unknown'


def translate_to_korean(text: str, max_chars: int = 4000) -> tuple:
    """
    텍스트를 한국어로 번역

    Returns:
        (translated_text, detected_lang)
        - 이미 한국어인 경우 : (None, 'ko')
        - 번역 성공          : (번역문, 언어코드)
        - 번역 실패          : (None,  언어코드)
    """
    if not text or not text.strip():
        return None, 'unknown'

    lang = detect_language(text)

    # 이미 한국어면 번역 불필요
    if lang == 'ko':
        return None, 'ko'

    # GoogleTranslator 무료 버전 글자 수 제한 대응
    truncated = text[:max_chars] if len(text) > max_chars else text

    try:
        translated = GoogleTranslator(source='auto', target='ko').translate(truncated)
        return translated, lang
    except Exception as e:
        print(f"  [번역 오류] {e}")
        return None, lang
