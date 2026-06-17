# fetch_rss.py — 보안뉴스 RSS 수집 메인 스크립트
#
# 카테고리: security_news / vulnerability / reputation
# 실행 방법: python scripts/fetch_rss.py
# 환경변수 : NAVER_CLIENT_ID, NAVER_CLIENT_SECRET (GitHub Secrets)

import os
import json
import re
import ssl
import time
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from difflib import SequenceMatcher

import pytz
import feedparser
import requests
import urllib3
from bs4 import BeautifulSoup
import html as html_lib
from dateutil.parser import parse as parse_date

from translator import translate_to_korean
from summarizer import summarize_3lines, setup_nltk

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================================================================
# 전역 설정
# ================================================================

KST              = pytz.timezone('Asia/Seoul')
RETENTION_DAYS   = 3                        # feeds.json 보존 기간 (일)
MAX_PER_CATEGORY = 500                      # 카테고리별 최대 보관 건수 (안전망)
WINDOW_HOURS     = RETENTION_DAYS * 24      # 수집 시간 범위 = 보존 기간과 동일 (72시간)
SIMILARITY_THRESH      = 0.90  # 문자 유사도 기준 (엄격)
SIMILARITY_THRESH_SOFT = 0.45  # 문자 유사도 기준 (완화) — 단어 겹침과 조합
WORD_JACCARD_THRESH    = 0.20  # 단어 Jaccard 유사도 기준

NAVER_CLIENT_ID     = os.environ.get('NAVER_CLIENT_ID', '')
NAVER_CLIENT_SECRET = os.environ.get('NAVER_CLIENT_SECRET', '')
GEMINI_API_KEY      = os.environ.get('GEMINI_API_KEY', '')
GROQ_API_KEY        = os.environ.get('GROQ_API_KEY', '')

# 카카오 알림톡 설정 (GitHub Secrets)
KAKAO_URL         = os.environ.get('KAKAO_URL', '')
KAKAO_SENDER_KEY  = os.environ.get('KAKAO_SENDER_KEY', '')
KAKAO_BEARER      = os.environ.get('KAKAO_BEARER', '')
KAKAO_TEMPLATE    = os.environ.get('KAKAO_TEMPLATE', 'EFCSC_001')
KAKAO_RECEIVERS   = [r.strip() for r in os.environ.get('KAKAO_RECEIVERS', '').split(',') if r.strip()]

FEEDS_PATH    = 'feeds.json'                          # 레포 루트
KEYWORDS_PATH = os.path.join(os.path.dirname(__file__), 'reputation_keywords.json')

# ================================================================
# RSS 피드 목록
# ================================================================

SECURITY_NEWS_FEEDS = [
    # ── 국내 ──────────────────────────────────────────────────
    {'url': 'https://openapi.naver.com/v1/search/news.xml?query=%ED%95%B4%ED%82%B9&display=20',
     'source': 'naver', 'naver': True},
    {'url': 'https://openapi.naver.com/v1/search/news.xml?query=%EB%B3%B4%EC%95%88&display=20',
     'source': 'naver', 'naver': True},
    {'url': 'https://openapi.naver.com/v1/search/news.xml?query=%EC%82%AC%EC%9D%B4%EB%B2%84&display=20',
     'source': 'naver', 'naver': True},
    {'url': 'https://www.boannews.com/media/news_rss.xml',
     'source': 'boannews', 'naver': False},
    {'url': 'https://www.dailysecu.com/rss/allArticle.xml',
     'source': 'dailysecu', 'naver': False},
    # ── 해외 ──────────────────────────────────────────────────
    {'url': 'https://feeds.feedburner.com/TheHackersNews',
     'source': 'thehackernews', 'naver': False},
    {'url': 'https://www.bleepingcomputer.com/feed/',
     'source': 'bleepingcomputer', 'naver': False},
    {'url': 'https://krebsonsecurity.com/feed/',
     'source': 'krebsonsecurity', 'naver': False},
    {'url': 'https://www.darkreading.com/rss.xml',
     'source': 'darkreading', 'naver': False},
    {'url': 'https://feeds.feedburner.com/securityweek',
     'source': 'securityweek', 'naver': False},
]

SECURITY_KEYWORDS = [
    '해킹', '북한', '유출', '개인정보', 'cve', '취약점', '디도스',
    '사이버보안', 'ddos', 'ransomware', 'malware', 'phishing',
    'breach', 'exploit', 'vulnerability', 'backdoor', 'zero-day',
    'zero day', '악성코드', '랜섬웨어', '피싱',
]

VULNERABILITY_FEEDS = [
    # ── 국내 (KISA 보호나라 공식 RSS: /kr/rss.do?bbsId=) ─────
    # 보안공지 — 보안 업데이트 권고, 취약점 패치 안내
    {'url': 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000133',
     'source': 'krcert_notice', 'naver': False},
    # 취약점 정보 — CVE 분석, 취약점 상세 정보
    {'url': 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000302',
     'source': 'krcert_vuln', 'naver': False},
    # 경보단계 — 사이버 위협 경보 (관심/주의/경계/심각)
    {'url': 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000342',
     'source': 'krcert_alert', 'naver': False},
    # ── 해외 ──────────────────────────────────────────────────
    # Microsoft MSRC (보안 업데이트 가이드) — 공식 확인 URL
    {'url': 'https://api.msrc.microsoft.com/update-guide/rss',
     'source': 'msrc', 'naver': False},
    # Exploit-DB (공개 PoC 코드)
    {'url': 'https://www.exploit-db.com/rss.xml',
     'source': 'exploitdb', 'naver': False},
    # CISA — 2025.05.12 공식 RSS 폐지, all.xml로 대체 시도
    {'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
     'source': 'cisa', 'naver': False},
    # SANS Internet Storm Center (CVE 실시간 분석)
    {'url': 'https://isc.sans.edu/rssfeed.xml',
     'source': 'sans_isc', 'naver': False},
    # CVE Feed (커뮤니티 CVE 통합 피드)
    {'url': 'https://cvefeed.io/rssfeed/latest.xml',
     'source': 'cvefeed', 'naver': False},
]

# ================================================================
# 공통 유틸
# ================================================================

def clean_html(text: str) -> str:
    if not text or not isinstance(text, str):
        return ''
    # 태그가 없는 일반 텍스트는 BeautifulSoup 불필요 (경고 방지)
    if '<' not in text and '>' not in text:
        return html_lib.unescape(text.strip())
    result = BeautifulSoup(text, 'html.parser').get_text().strip()
    # feedparser가 미처 디코딩 못한 HTML 엔티티 2차 처리
    # ex) &quot; → "  &amp; → &  &#39; → '
    return html_lib.unescape(result)


def _word_jaccard(t1: str, t2: str) -> float:
    """단어 단위 Jaccard 유사도 (같은 토픽의 다르게 표현된 제목 감지)"""
    def _clean(t):
        # 알파벳/숫자/한글 외 문자를 공백으로 치환 후 분리
        import re
        return set(re.sub('[^가-힣a-zA-Z0-9]', ' ', t).split())
    w1, w2 = _clean(t1), _clean(t2)
    if not w1 or not w2:
        return 0.0
    return len(w1 & w2) / len(w1 | w2)


def is_similar_title(t1: str, t2: str) -> bool:
    """
    두 가지 기준 중 하나라도 충족하면 유사 제목으로 판단
    ① 문자 유사도 ≥ 0.90  (엄격: 거의 동일한 제목)
    ② 문자 유사도 ≥ 0.55  AND  단어 Jaccard ≥ 0.20
       (완화: 같은 사건을 다르게 표현한 제목)
    """
    char_ratio = SequenceMatcher(None, t1, t2).ratio()
    if char_ratio >= SIMILARITY_THRESH:
        return True
    if char_ratio >= SIMILARITY_THRESH_SOFT:
        if _word_jaccard(t1, t2) >= WORD_JACCARD_THRESH:
            return True
    return False


TITLE_SOFT_THRESH   = 0.45  # 키워드 체크 발동 제목 유사도 하한
KEYWORD_JACCARD_THRESH = 0.50  # 한국어 키워드 Jaccard 유사도 임계값

def _korean_keywords(text: str) -> set:
    """한국어 2자 이상 단어 추출 (키워드 지문)"""
    return set(re.findall(r'[가-힣]{2,}', text))

def _jaccard(set1: set, set2: set) -> float:
    if not set1 or not set2:
        return 0.0
    return len(set1 & set2) / len(set1 | set2)

def is_duplicate(link: str, title: str,
                 visited_links: set, visited_titles: list,
                 summary: str = '', visited_summaries: list = None) -> bool:
    # 1단계: 링크 일치
    if link in visited_links:
        return True
    # 2단계: 제목 유사도 체크 (is_similar_title 내부에서 복합 기준 적용)
    for vt in visited_titles:
        if is_similar_title(title, vt):
            return True
    # 3단계: 제목 유사도 0.45 이상 + 한국어 키워드 Jaccard 0.50 이상
    if summary and visited_summaries:
        kw_new = _korean_keywords(title + ' ' + summary)
        for i, vt in enumerate(visited_titles):
            title_ratio = SequenceMatcher(None, title, vt).ratio()
            if title_ratio >= TITLE_SOFT_THRESH:
                vs = visited_summaries[i] if i < len(visited_summaries) else ''
                kw_old = _korean_keywords(vt + ' ' + vs)
                if _jaccard(kw_new, kw_old) >= KEYWORD_JACCARD_THRESH:
                    return True
        # 4단계: 제목이 달라도 내용이 비슷하면 중복
        # 제목+요약 조합 Jaccard 비교 — 같은 사건을 다른 각도로 쓴 기사 감지
        combined_new = title + ' ' + summary
        for i, vs in enumerate(visited_summaries):
            vt = visited_titles[i] if i < len(visited_titles) else ''
            combined_old = vt + ' ' + vs
            if combined_old and _word_jaccard(combined_new, combined_old) >= 0.22:
                return True
    return False


def extract_cve_id(text: str) -> str:
    m = re.search(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
    return m.group(0).upper() if m else ''


def fetch_kisa_overview(url: str) -> str:
    """KISA 보안공지 글 페이지에서 □ 개요 섹션 추출
    - RSS에 summary가 없어 직접 크롤링 필요
    - o 항목을 1./2./3. 번호 형식으로 변환
    """
    try:
        resp = requests.get(
            url.strip(), timeout=10, verify=False,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        if resp.status_code != 200:
            return ''

        soup = BeautifulSoup(resp.text, 'html.parser')

        # 본문 영역: class에 s-prose 포함하는 div
        content_div = soup.find('div', class_='s-prose')
        if not content_div:
            return ''

        text = content_div.get_text(separator=' ', strip=True)

        # □ 개요 ~ 다음 □ 섹션 사이 내용 추출
        m = re.search(r'□\s*개요(.+?)(?=□\s*\S|$)', text, re.DOTALL)
        if not m:
            m = re.search(r'개요(.+?)(?=□|\Z)', text, re.DOTALL)
        if not m:
            return ''

        overview_raw = m.group(1)

        # "o " 로 시작하는 항목 추출
        items = re.findall(r'o\s+(.+?)(?=o\s+|$)', overview_raw, re.DOTALL)
        if not items:
            # o 항목 없으면 전체 텍스트 정리
            cleaned = re.sub(r'\[\d+\]', '', overview_raw)
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            return cleaned[:200]

        # 참조번호 제거 + 공백 정리 + 50자 제한
        lines = []
        for i, item in enumerate(items[:3], 1):
            line = re.sub(r'\[\d+\]', '', item)
            line = re.sub(r'\s+', ' ', line).strip()
            if line:
                lines.append(f"{i}. {line[:50]}")

        return '\n'.join(lines)

    except Exception as e:
        return ''


def extract_cvss(text: str) -> tuple:
    """
    Returns: (score_str, severity_str)
    e.g. ('9.8', 'Critical')
    """
    m = re.search(r'CVSS[^:]*:\s*([\d.]+)', text, re.IGNORECASE)
    if not m:
        m = re.search(r'\b(10(?:\.0)?|[0-9]\.\d)\s*/\s*10', text)
    if not m:
        m = re.search(r'score[^:]*:\s*([\d.]+)', text, re.IGNORECASE)
    if m:
        try:
            score = float(m.group(1))
        except ValueError:
            return '', ''
        if score >= 9.0:   severity = 'Critical'
        elif score >= 7.0: severity = 'High'
        elif score >= 4.0: severity = 'Medium'
        else:              severity = 'Low'
        return str(score), severity
    return '', ''


def parse_published(entry) -> str:
    raw = entry.get('published', entry.get('updated', ''))
    try:
        dt = parse_date(raw)
        if dt.tzinfo is None:
            # 타임존 표기 없는 경우:
            # 해외 피드는 항상 UTC 오프셋(+0000 등)을 명시하므로
            # 표기 없으면 국내 KST로 간주 (이중 변환 방지)
            dt = KST.localize(dt)
        else:
            dt = dt.astimezone(KST)
        return dt.isoformat()
    except Exception:
        return datetime.now(KST).isoformat()


def format_korean_dt(iso_str: str) -> str:
    """ISO 날짜 문자열 → 한국어 형식 (예: 2026년 5월 27일 오전 2시 16분)"""
    try:
        dt = datetime.fromisoformat(iso_str).astimezone(KST)
        am_pm = '오전' if dt.hour < 12 else '오후'
        h12   = dt.hour % 12 or 12
        return f"{dt.year}년 {dt.month}월 {dt.day}일 {am_pm} {h12}시 {dt.minute}분"
    except Exception:
        return iso_str

# ================================================================
# 피드 Fetch
# ================================================================

def fetch_naver(url: str) -> feedparser.FeedParserDict:
    if not NAVER_CLIENT_ID:
        print('  [경고] NAVER_CLIENT_ID 미설정 — 네이버 API 건너뜀')
        return feedparser.FeedParserDict({'entries': []})
    try:
        req = urllib.request.Request(url)
        req.add_header('X-Naver-Client-Id', NAVER_CLIENT_ID)
        req.add_header('X-Naver-Client-Secret', NAVER_CLIENT_SECRET)
        resp = urllib.request.urlopen(req, timeout=10)
        return feedparser.parse(resp.read())
    except Exception as e:
        print(f'  [네이버 오류] {e}')
        return feedparser.FeedParserDict({'entries': []})


def fetch_rss(url: str) -> feedparser.FeedParserDict:
    try:
        resp = requests.get(
            url, timeout=10, verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; RSSBot/1.0)'}
        )
        resp.raise_for_status()
        return feedparser.parse(resp.content)
    except Exception as e:
        print(f'  [RSS 오류] {url[:55]}... — {e}')
        return feedparser.FeedParserDict({'entries': []})

# ================================================================
# 번역 + 요약 (enrich)
# ================================================================

def enrich(item: dict) -> dict:
    """번역 · 3줄 요약을 item에 추가"""
    title_ko, lang   = translate_to_korean(item['title'])
    summary_ko, _    = translate_to_korean(item['summary'])

    item['title_ko']   = title_ko
    item['summary_ko'] = summary_ko
    item['lang']       = lang

    # _skip_summarize 플래그가 있으면 summary_3lines를 이미 직접 설정한 것
    if not item.pop('_skip_summarize', False):
        # title + description + summary + content 합쳐서 맥락 제공
        # 레이블(제목:, 내용:) 없이 연결 — 레이블이 있으면 모델이 에코할 수 있음
        title_text   = item.get('title', '')
        desc_text    = item.get('description', '')
        summary_text = item.get('summary', '')
        content_text = item.get('content', '')

        parts = []
        if title_text:
            parts.append(title_text)
        if desc_text and desc_text != summary_text:
            parts.append(desc_text)
        if summary_text:
            parts.append(summary_text)
        if content_text and content_text not in (summary_text, desc_text):
            parts.append(content_text[:1000])

        full_text = '\n\n'.join(p for p in parts if p)

        item['summary_3lines'] = summarize_3lines(
            full_text,
            lang=lang,
            translator_fn=translate_to_korean,
            gemini_api_key=GEMINI_API_KEY,
            groq_api_key=GROQ_API_KEY,
        )
    time.sleep(7)    # Gemini 10 RPM 제한 대응 (60초/10 = 6초 + 여유 1초)
    return item

# ================================================================
# 카테고리별 수집
# ================================================================

def collect_security_news(visited_links: set, visited_titles: list, visited_summaries: list = None) -> list:
    if visited_summaries is None:
        visited_summaries = []
    print('\n── [보안뉴스] 수집 ──')
    cutoff  = datetime.now(KST) - timedelta(hours=WINDOW_HOURS)
    results = []

    for cfg in SECURITY_NEWS_FEEDS:
        print(f'  {cfg["source"]:20s} {cfg["url"][:55]}...')
        feed = fetch_naver(cfg['url']) if cfg['naver'] else fetch_rss(cfg['url'])

        for entry in feed.entries:
            title       = clean_html(entry.get('title', ''))
            summary     = clean_html(entry.get('summary', ''))
            description = clean_html(entry.get('description', ''))
            link        = entry.get('link', '')
            if not title or not link:
                continue

            # 시간 필터
            try:
                pub = parse_date(
                    entry.get('published', entry.get('updated', ''))
                ).astimezone(KST)
                if pub < cutoff:
                    continue
            except Exception:
                pass

            # 키워드 필터 (2개 이상 매칭)
            combined = (title + ' ' + summary).lower()
            if sum(1 for kw in SECURITY_KEYWORDS if kw in combined) < 2:
                continue

            if is_duplicate(link, title, visited_links, visited_titles,
                           summary=summary, visited_summaries=visited_summaries):
                continue

            # Atom 피드(BleepingComputer 등)는 content 필드에 본문 제공
            content_list = entry.get('content', [])
            content_full = clean_html(
                content_list[0].get('value', '') if content_list else ''
            )

            item = {
                'title':          title,
                'summary':        summary,
                'content':        content_full,   # 본문 (있을 때만)
                'title_ko':       None,
                'summary_ko':     None,
                'summary_3lines': '',
                'link':           link,
                'source':         cfg['source'],
                'published':      parse_published(entry),
                'lang':           'unknown',
            }
            item = enrich(item)
            results.append(item)
            visited_links.add(link)
            visited_titles.append(title)
            visited_summaries.append(summary)
            print(f'    ✓ {title[:55]}')

    print(f'  → {len(results)}건 신규 수집')
    return results


def collect_vulnerability(visited_links: set, visited_titles: list, visited_summaries: list = None) -> list:
    if visited_summaries is None:
        visited_summaries = []
    print('\n── [취약점] 수집 ──')
    cutoff  = datetime.now(KST) - timedelta(hours=WINDOW_HOURS)
    results = []

    for cfg in VULNERABILITY_FEEDS:
        print(f'  {cfg["source"]:20s} {cfg["url"][:55]}...')
        feed = fetch_rss(cfg['url'])

        for entry in feed.entries:
            title       = clean_html(entry.get('title', ''))
            summary     = clean_html(entry.get('summary', entry.get('description', '')))
            description = clean_html(entry.get('description', ''))
            link        = entry.get('link', '')
            if not title or not link:
                continue

            # 시간 필터
            try:
                pub = parse_date(
                    entry.get('published', entry.get('updated', ''))
                ).astimezone(KST)
                if pub < cutoff:
                    continue
            except Exception:
                pass

            if is_duplicate(link, title, visited_links, visited_titles,
                           summary=summary, visited_summaries=visited_summaries):
                continue

            combined  = title + ' ' + summary
            cve_id    = extract_cve_id(combined)
            cvss, sev = extract_cvss(combined)

            published_iso = parse_published(entry)
            item = {
                'title':          title,
                'summary':        summary,
                'description':    description,
                'title_ko':       None,
                'summary_ko':     None,
                'summary_3lines': '',
                'cve_id':         cve_id,
                'cvss':           cvss,
                'severity':       sev,
                'link':           link,
                'source':         cfg['source'],
                'published':      published_iso,
                'lang':           'unknown',
            }

            # ── 모든 취약점: Gemini 사용 안 함, 구조화 포맷으로 직접 생성 ──
            def _t50v(s):
                s = re.sub(r'\s+', ' ', str(s)).strip()
                return s[:50] if len(s) > 50 else s

            if cfg['source'] == 'cvefeed':
                # cvefeed: CVE ID / 게시일 / Description 추출
                cve_from_summary = ''
                m_cve = re.search(r'CVE ID\s*:\s*(CVE-[\d-]+)', summary, re.I)
                if m_cve:
                    cve_from_summary = m_cve.group(1).strip()
                line1 = _t50v(cve_from_summary or cve_id or 'CVE 정보 없음')

                try:
                    from datetime import datetime as _dt
                    _d  = _dt.fromisoformat(published_iso).astimezone(KST)
                    _ap = '오전' if _d.hour < 12 else '오후'
                    _h  = _d.hour % 12 or 12
                    line2 = _t50v(f"{str(_d.year)[2:]}.{_d.month:02d}.{_d.day:02d} {_ap}{_h}:{_d.minute:02d}")
                except Exception:
                    line2 = _t50v(published_iso[:10])

                m_desc = re.search(r'Description\s*:\s*(.+)', summary, re.I | re.DOTALL)
                if m_desc:
                    desc_text = re.sub(r'\s+', ' ', m_desc.group(1)).strip()
                else:
                    lines_filtered = [
                        l.strip() for l in summary.splitlines()
                        if l.strip()
                        and not re.match(r'CVE\s*ID\s*:', l, re.I)
                        and not re.match(r'Published\s*:', l, re.I)
                    ]
                    desc_text = re.sub(r'\s+', ' ', ' '.join(lines_filtered)).strip()
                line3 = _t50v(desc_text or '설명 없음')

            elif cfg['source'] in ('krcert_notice', 'krcert_vuln',
                                      'krcert_alert', 'krcert_guide'):
                # KISA 보호나라: 기사 페이지에서 □ 개요 직접 크롤링
                # RSS에 summary 없음 → link 페이지에서 개요 추출
                overview = fetch_kisa_overview(link)
                if overview:
                    # 이미 1./2./3. 번호 형식으로 반환됨
                    item['summary_3lines'] = overview
                    item['summary'] = overview  # summary도 개요로 대체
                    item['_skip_summarize'] = True
                    item = enrich(item)
                    item['summary_3lines'] = overview  # enrich 후 복원
                    results.append(item)
                    visited_links.add(link)
                    visited_titles.append(title)
                    visited_summaries.append(overview)
                    print(f'    ✓ {title[:55]}')
                    continue
                else:
                    # 크롤링 실패 시 기본 구조화 포맷
                    line1 = _t50v(title)
                    line2 = _t50v(cfg['source'].upper())
                    line3 = _t50v('개요를 불러올 수 없습니다.')

            else:
                # msrc / exploitdb / cisa / sans_isc:
                # 1. CVE ID 또는 제목
                # 2. 심각도 + CVSS (없으면 출처)
                # 3. 요약 앞부분
                line1 = _t50v(cve_id or title)
                if sev and cvss:
                    line2 = _t50v(f"{sev} / CVSS {cvss}")
                elif sev:
                    line2 = _t50v(sev)
                else:
                    line2 = _t50v(cfg['source'].upper())
                line3 = _t50v(re.sub(r'\s+', ' ', summary).strip() or '설명 없음')

            item['summary_3lines'] = f"1. {line1}\n2. {line2}\n3. {line3}"
            item['_skip_summarize'] = True  # 취약점 전체 Gemini 사용 안 함

            item = enrich(item)
            results.append(item)
            visited_links.add(link)
            visited_titles.append(title)
            visited_summaries.append(summary)
            tag = f'[{cve_id}]' if cve_id else '[CVE-미상]'
            print(f'    ✓ {tag} {title[:50]}')

    print(f'  → {len(results)}건 신규 수집')
    return results


def collect_reputation(visited_links: set, visited_titles: list, visited_summaries: list = None) -> list:
    if visited_summaries is None:
        visited_summaries = []
    print('\n── [평판] 수집 ──')

    try:
        with open(KEYWORDS_PATH, 'r', encoding='utf-8') as f:
            config   = json.load(f)
        keywords = config.get('keywords', [])
    except Exception as e:
        print(f'  [오류] {KEYWORDS_PATH} 로드 실패: {e}')
        return []

    cutoff  = datetime.now(KST) - timedelta(hours=WINDOW_HOURS)
    results = []

    # 평판 보안 필터 키워드 (기관 키워드와 AND 조합)
    SEC_FILTER = ['해킹', '사고', '유출', '개인정보', '침해', '취약점', '랜섬웨어', '악성코드', '공격']

    for kw in keywords:
        encoded_kw  = urllib.parse.quote(kw)
        # 구글뉴스: "기관명 (해킹 OR 사고 OR 유출 OR 개인정보 OR 침해)"
        sec_or      = ' OR '.join(SEC_FILTER[:6])
        google_q    = urllib.parse.quote(f'{kw} ({sec_or})')
        # 네이버: "기관명 침해사고" (OR 연산자 미지원 → 대표 키워드 조합)
        naver_q     = urllib.parse.quote(f'{kw} 침해사고')

        sources = [
            {
                'url': f'https://news.google.com/rss/search?q={google_q}&hl=ko&gl=KR&ceid=KR:ko',
                'source': 'google_rep', 'naver': False
            },
            {
                'url': f'https://openapi.naver.com/v1/search/news.xml?query={naver_q}&display=10',
                'source': 'naver_rep', 'naver': True
            },
        ]
        print(f'  키워드: "{kw}" + 보안 필터')

        for cfg in sources:
            feed = fetch_naver(cfg['url']) if cfg['naver'] else fetch_rss(cfg['url'])

            for entry in feed.entries:
                title       = clean_html(entry.get('title', ''))
                summary     = clean_html(entry.get('summary', ''))
                description = clean_html(entry.get('description', ''))
                link        = entry.get('link', '')
                if not title or not link:
                    continue

                # 시간 필터
                try:
                    pub = parse_date(
                        entry.get('published', entry.get('updated', ''))
                    ).astimezone(KST)
                    if pub < cutoff:
                        continue
                except Exception:
                    pass

                if is_duplicate(link, title, visited_links, visited_titles,
                               summary=summary, visited_summaries=visited_summaries):
                    continue

                # 제목+요약에 보안 키워드 최소 1개 포함 여부 2차 필터
                combined_check = (title + ' ' + summary).lower()
                if not any(sk in combined_check for sk in SEC_FILTER):
                    continue

                content_list = entry.get('content', [])
                content_full = clean_html(
                    content_list[0].get('value', '') if content_list else ''
                )

                item = {
                    'title':           title,
                    'summary':         summary,
                    'description':     description,
                    'content':         content_full,
                    'title_ko':        None,
                    'summary_ko':      None,
                    'summary_3lines':  '',
                    'keyword_matched': kw,
                    'link':            link,
                    'source':          cfg['source'],
                    'published':       parse_published(entry),
                    'lang':            'unknown',
                }
                item = enrich(item)
                results.append(item)
                visited_links.add(link)
                visited_titles.append(title)
                visited_summaries.append(summary)
                print(f'    ✓ [{kw}] {title[:50]}')

    print(f'  → {len(results)}건 신규 수집')
    return results

# ================================================================
# Retention Policy
# ================================================================

def apply_retention(items: list) -> list:
    cutoff   = datetime.now(KST) - timedelta(days=RETENTION_DAYS)
    retained = []
    removed  = 0

    for item in items:
        try:
            pub = datetime.fromisoformat(item['published'])
            if pub.tzinfo is None:
                pub = KST.localize(pub)
            if pub >= cutoff:
                retained.append(item)
            else:
                removed += 1
        except Exception:
            retained.append(item)   # 날짜 파싱 실패 시 보존

    if removed:
        print(f'    만료 삭제 {removed}건 (기준: {cutoff.strftime("%Y-%m-%d %H:%M")} KST)')
    return retained

# ================================================================
# feeds.json 로드 / 저장
# ================================================================

def load_feeds() -> dict:
    try:
        with open(FEEDS_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {'fetched_at': '', 'security_news': [], 'vulnerability': [], 'reputation': []}


# ================================================================
# 카카오 알림톡 전송
# ================================================================

def send_kakao(title: str, summary: str, link: str):
    """카카오 알림톡 전송 (GitHub Actions 환경에서 실행)"""
    if not KAKAO_URL or not KAKAO_BEARER:
        return  # Secrets 미설정 시 스킵

    # http → https 변환
    if link.startswith('http://'):
        link = 'https://' + link[7:]

    message = f'☞ (제목) {title}\n☞ (요약) {summary}'

    send_data = [
        {
            'custMsgSn':    'boannews001',
            'senderKey':    KAKAO_SENDER_KEY,
            'phoneNum':     receiver,
            'templateCode': KAKAO_TEMPLATE,
            'msgType':      'AI',
            'message':      message,
            'button': [{
                'name':       '바로가기',
                'type':       'WL',
                'url_pc':     link,
                'url_mobile': link,
            }],
        }
        for receiver in KAKAO_RECEIVERS
    ]

    try:
        resp = requests.post(
            KAKAO_URL,
            json=send_data,
            headers={
                'Content-Type':  'application/json; charset=utf-8',
                'Authorization': f'Bearer {KAKAO_BEARER}',
            },
            verify=False,
            timeout=10,
        )
        if resp.status_code == 200:
            print(f'    📨 카카오 전송 성공: {title[:40]}')
        else:
            print(f'    ⚠️  카카오 전송 실패 ({resp.status_code}): {resp.text[:100]}')
    except Exception as e:
        print(f'    ⚠️  카카오 전송 오류: {e}')


def save_feeds(data: dict):
    print('\n── [저장] ──')
    for cat in ['security_news', 'vulnerability', 'reputation']:
        before = len(data.get(cat, []))
        data[cat] = apply_retention(data[cat])
        data[cat] = data[cat][:MAX_PER_CATEGORY]
        print(f'  {cat:20s}: {before} → {len(data[cat])}건')

    data['fetched_at'] = datetime.now(KST).isoformat()

    with open(FEEDS_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f'  ✅ {FEEDS_PATH} 저장 완료')

# ================================================================
# Main
# ================================================================

def main():
    ssl._create_default_https_context = ssl._create_unverified_context

    now_str = datetime.now(KST).strftime('%Y-%m-%d %H:%M:%S')
    print('=' * 60)
    print(f'  보안뉴스 RSS 수집 시작  ({now_str} KST)')
    print('=' * 60)

    setup_nltk()

    # 기존 데이터 로드 + 방문 목록 초기화
    existing       = load_feeds()
    visited_links     = set()
    visited_titles    = []
    visited_summaries = []
    for cat in ['security_news', 'vulnerability', 'reputation']:
        for item in existing.get(cat, []):
            visited_links.add(item.get('link', ''))
            visited_titles.append(item.get('title', ''))
            visited_summaries.append(item.get('summary', ''))

    # 카테고리별 수집
    new_sec  = collect_security_news(visited_links, visited_titles, visited_summaries)
    new_vuln = collect_vulnerability(visited_links, visited_titles, visited_summaries)
    new_rep  = collect_reputation(visited_links, visited_titles, visited_summaries)

    # 신규 항목 병합 후 published 기준 내림차순 정렬
    def merge_sorted(new_items, old_items):
        merged = new_items + old_items
        merged.sort(key=lambda x: x.get('published', ''), reverse=True)
        return merged

    existing['security_news'] = merge_sorted(new_sec,  existing.get('security_news', []))
    existing['vulnerability']  = merge_sorted(new_vuln, existing.get('vulnerability',  []))
    existing['reputation']     = merge_sorted(new_rep,  existing.get('reputation',     []))

    save_feeds(existing)

    # ── 신규 항목 카카오 자동 전송 ──────────────────────────
    if KAKAO_URL and KAKAO_BEARER:
        all_new = new_sec + new_vuln + new_rep
        if all_new:
            print(f'\n── [카카오 전송] 신규 {len(all_new)}건 ──')
            for item in all_new:
                title   = item.get('title_ko') or item.get('title', '')
                summary = item.get('summary_ko') or item.get('summary', '')
                link    = item.get('link', '')
                send_kakao(title, summary, link)
        else:
            print('\n── [카카오 전송] 신규 항목 없음 — 스킵')
    else:
        print('\n── [카카오 전송] Secrets 미설정 — 스킵')

    print('\n── 수집 요약 ──')
    print(f'  보안뉴스 신규: {len(new_sec):3d}건')
    print(f'  취약점   신규: {len(new_vuln):3d}건')
    print(f'  평판     신규: {len(new_rep):3d}건')
    print('=' * 60)


if __name__ == '__main__':
    main()
