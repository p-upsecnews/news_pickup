"""各情報源からの取得処理。すべて共通形式の item（dict）のリストを返す"""
import hashlib
import html
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .http_util import fetch, fetch_json

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
SUMMARY_MAX = 400  # 判定に必要な分だけ残す（本文全体は保持しない）


# ---------- 共通ユーティリティ ----------

def make_item(source, category, lang, title, url, published, summary="", cves=None, meta=None, item_id=None):
    text = f"{title} {summary}"
    found = {c.upper() for c in CVE_RE.findall(text)}
    if cves:
        found |= {c.upper() for c in cves}
    return {
        "id": item_id or "url:" + hashlib.sha1(url.encode("utf-8")).hexdigest()[:12],
        "source": source,
        "category": category,  # kev / nvd / jp_alert / news
        "lang": lang,
        "title": title.strip(),
        "url": url,
        "published": published.astimezone(timezone.utc).isoformat() if published else None,
        "summary": summary[:SUMMARY_MAX],
        "cves": sorted(found),
        "meta": meta or {},
    }


def clean_text(s):
    """HTMLタグと余分な空白を除去する"""
    if not s:
        return ""
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def parse_date(s):
    """RSS2(RFC822) / RDF・Atom(ISO8601) の日付を解釈する。失敗時は None"""
    if not s:
        return None
    s = s.strip()
    try:
        dt = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _local(tag):
    # 名前空間を除いたタグ名
    return tag.rsplit("}", 1)[-1]


def _child_text(el, *names):
    for child in el:
        if _local(child.tag) in names and (child.text or "").strip():
            return child.text
    return ""


def _atom_link(el):
    for child in el:
        if _local(child.tag) == "link":
            if child.get("href") and child.get("rel", "alternate") == "alternate":
                return child.get("href")
            if child.text:
                return child.text
    return ""


# ---------- RSS / RDF / Atom ----------

def fetch_feed(conf, since):
    root = ET.fromstring(fetch(conf["url"]))
    entries = [el for el in root.iter() if _local(el.tag) in ("item", "entry")]
    # 週次まとめなど、既報の再掲で重複が増える項目は除外する
    excludes = [re.compile(p) for p in conf.get("exclude_title_patterns", [])]
    items = []
    for el in entries:
        title = clean_text(_child_text(el, "title"))
        url = (_atom_link(el) or "").strip()
        published = parse_date(_child_text(el, "pubDate", "date", "published", "updated"))
        summary = clean_text(_child_text(el, "description", "summary", "encoded", "content"))
        if not title or not url or any(p.search(title) for p in excludes):
            continue
        # 日付不明のものは判断できないため除外する
        if published is None or published < since:
            continue
        items.append(make_item(conf["name"], conf["category"], conf["lang"], title, url, published, summary))
    return items


# ---------- CISA KEV ----------

def fetch_kev(conf, since):
    """期間内に追加されたKEV項目と、カタログ全体のCVE集合を返す"""
    data = fetch_json(conf["url"])
    all_cves = set()
    items = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID", "").upper()
        all_cves.add(cve)
        added = parse_date(v.get("dateAdded", "") + "T00:00:00+00:00") if v.get("dateAdded") else None
        if added is None or added.date() < since.date():
            continue
        title = f"{v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')}"
        url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        meta = {
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "ransomware": v.get("knownRansomwareCampaignUse"),
            "due_date": v.get("dueDate"),
            "required_action": v.get("requiredAction"),
        }
        items.append(make_item(conf["name"], "kev", "en", title, url, added,
                               v.get("shortDescription", ""), [cve], meta, item_id=f"kev:{cve}"))
    return items, all_cves


# ---------- NVD ----------

def _nvd_cvss(cve_obj):
    """CVSS の基本値（v4 → v3.1 → v3.0 の順で採用）を返す"""
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []):
            d = m.get("cvssData", {})
            if d.get("baseScore") is not None:
                return d.get("baseScore"), d.get("baseSeverity")
    return None, None


def _nvd_desc(cve_obj):
    for d in cve_obj.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _nvd_time(dt):
    return urllib.parse.quote(dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"))


def fetch_nvd_recent(conf, since, now):
    """期間内に公開された CRITICAL の CVE を取得する"""
    url = (f"{conf['url']}?pubStartDate={_nvd_time(since)}&pubEndDate={_nvd_time(now)}"
           f"&cvssV3Severity={conf['severity']}&resultsPerPage=200")
    data = fetch_json(url)
    items, cvss_map = [], {}
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        cve = c.get("id", "").upper()
        score, sev = _nvd_cvss(c)
        cvss_map[cve] = score
        items.append(make_item(conf["name"], "nvd", "en", f"{cve} (CVSS {score})",
                               f"https://nvd.nist.gov/vuln/detail/{cve}", parse_date(c.get("published")),
                               clean_text(_nvd_desc(c)), [cve], {"cvss": score, "severity": sev},
                               item_id=f"nvd:{cve}"))
    return items, cvss_map


def lookup_nvd_cvss(conf, cves):
    """ニュースで言及された CVE の CVSS を個別に引く（APIキーなしは30秒5件の制限があるため間隔を空ける）"""
    result = {}
    for i, cve in enumerate(cves[: conf.get("max_cve_lookups", 15)]):
        if i:
            time.sleep(6.5)
        try:
            data = fetch_json(f"{conf['url']}?cveId={cve}", retries=1)
            vulns = data.get("vulnerabilities", [])
            if vulns:
                result[cve] = _nvd_cvss(vulns[0].get("cve", {}))[0]
        except Exception:
            result[cve] = None  # 取得できなくても全体は止めない
    return result


# ---------- EPSS ----------

def fetch_epss(conf, cves):
    """CVE ごとの EPSS（30日以内に悪用される確率）とパーセンタイルを返す"""
    result = {}
    cves = sorted(cves)
    for i in range(0, len(cves), 100):
        batch = ",".join(cves[i:i + 100])
        data = fetch_json(f"{conf['url']}?cve={batch}")
        for d in data.get("data", []):
            result[d["cve"].upper()] = {"epss": float(d["epss"]), "percentile": float(d["percentile"])}
    return result
