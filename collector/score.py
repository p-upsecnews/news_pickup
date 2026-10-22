"""事前採点と重複統合

収集した候補（items）を同一事案ごとにまとめ（クラスタ）、客観的シグナルで点数を付けて上位だけを残す。
最終的な統合・優先度の判断は Claude が行うため、ここでは「取りこぼさずに量を減らす」ことを目的とする。

使い方:
    python -m collector.score [--in data/candidates/YYYY-MM-DD.json] [--top 30]
"""
import argparse
import glob
import json
import os
import re
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------- 採点の重み（調整しやすいよう1か所にまとめる） ----------
W = {
    "in_kev": 40,           # CISA KEV 掲載（悪用確認済み）
    "kev_ransomware": 10,   # KEV でランサムウェアでの悪用が既知
    "jp_alert": 20,         # JPCERT/CC・IPA の注意喚起
    "jp_vuln": 10,          # JVN の国内向け脆弱性情報（件数が多いため注意喚起より軽く）
    "outage": 10,           # クラウド事業者の障害情報（公式発表があること自体が根拠）
    "per_extra_source": 10, # 2媒体目以降、1媒体ごと
    "extra_source_cap": 40,
    "cvss_critical": 15,    # CVSS 9.0 以上
    "cvss_high": 5,         # CVSS 7.0 以上
    "epss_high": 20,        # EPSS 0.5 以上
    "epss_mid": 10,         # EPSS 0.1 以上
    "exploited_word": 15,   # 本文に「悪用」「ゼロデイ」等の記述
    "incident_word": 10,    # 漏洩・不正アクセス・ランサム・停止等の事件
    "large_scale": 15,      # 被害規模が1万（件・人・台など）以上と書かれている
    "nvd_only": -15,        # NVD だけに出ている（報道されていない）脆弱性
}

# 採点用の語句（フィルタではなく加点のみに使う）
EXPLOITED_RE = re.compile(
    r"exploit(ed|ation|s)?\b|in the wild|actively|zero[- ]day|0-day|\bpoc\b|悪用|ゼロデイ|攻撃を確認|実証コード",
    re.IGNORECASE)
INCIDENT_RE = re.compile(
    r"breach|leak|hack(ed|ers)?\b|ransomware|outage|stolen|compromis|backdoor|supply chain|"
    r"流出|漏洩|漏えい|不正アクセス|ランサム|サイバー攻撃|障害|停止|侵害|紛失",
    re.IGNORECASE)

# 被害規模の記述（例：「最大約420万件」「3.2 million records」「27,000 servers」）
# 1つの媒体しか報じない国内の大型流出が埋もれないよう、規模そのものを加点する
LARGE_SCALE_RE = re.compile(
    r"\d+(?:\.\d+)?\s*(?:万|億)\s*(?:件|人|台|社|アカウント|ユーザー)|"
    r"(?<![$€¥£\d.])\d+(?:\.\d+)?\s*(?:million|billion)\b(?!\s*(?:seed|funding|series|round|valuation))|"
    r"\b(?:\d{2,3}(?:,\d{3})+|\d(?:,\d{3}){2,})\s*(?:customers|users|records|accounts|servers|sites|organizations|orgs|devices)\b",
    re.IGNORECASE)


# 同一事案判定から除外する一般的な語（媒体間で頻出し誤統合の原因になる）
STOPWORDS = set("""
the and for with from that this into over after before about their have has are was were will can could
new now how why what when who its via amid more most than also just says said use used uses using
flaw flaws bug bugs vulnerability vulnerabilities security patch patches patched update updates fix fixes fixed
critical attack attacks attacker attackers hacker hackers hackers' exploit exploits exploited users user
data cyber malware remote code execution rce issue issues release releases released version versions
google microsoft apple cisa warns warn report reports researchers campaign
脆弱性 修正 公開 複数 深刻 注意喚起 アップデート 情報 対策 クリティカル セキュリティ
""".split())

# 誤統合を避けるため、語の共有だけで結ぶ場合は3語以上を要求する
# （2語だと "orders" "federal" のような一般語の偶然一致で別事案が連鎖的に結ばれた）
MIN_SHARED_TOKENS = 3

TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9\-\.]{2,}|[ァ-ヴー]{3,}|[一-龠ぁ-んァ-ヴー]{2,}(?=」)")
# 日本語記事は製品名を「」で囲む慣習があるため、その中身を固有名として扱う
BRACKET_RE = re.compile(r"「([^」]{2,40})」")


def bracket_names(text):
    """「」内の名称（例：「PHP」「Plex Media Server」）ごとの語集合のリストを返す"""
    out = []
    for name in BRACKET_RE.findall(text):
        ts = frozenset(tokens(name))
        if ts:
            out.append(ts)
    return out


def _bracket_match(names, toks):
    # 名称を構成する語がすべて相手のタイトルに含まれるときだけ一致とみなす
    # （「Claude Agent SDK」が "agent" だけで別記事と結ばれるのを防ぐ）
    return any(ts <= toks for ts in names)


def tokens(text):
    out = set()
    for t in TOKEN_RE.findall(text):
        t = t.lower().strip(".-")
        if len(t) >= 3 and t not in STOPWORDS and not t.startswith("cve-"):
            out.add(t)
    return out


# ---------- 重複統合 ----------

class UnionFind:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def cluster(items):
    """CVE の共有、または珍しい語の共有で同一事案とみなしてまとめる"""
    n = len(items)
    uf = UnionFind(n)
    # 1) 同じ CVE を含むものは同一事案
    by_cve = {}
    for i, it in enumerate(items):
        for c in it["cves"]:
            if c in by_cve:
                uf.union(i, by_cve[c])
            else:
                by_cve[c] = i
    # 2) タイトルの珍しい語を複数共有、「〜2Shell」のような固有名を共有、または「」の製品名が一致
    toks = [tokens(it["title"]) for it in items]
    names = [bracket_names(it["title"]) for it in items]
    df = Counter(t for ts in toks for t in ts)
    rare = [{t for t in ts if df[t] <= 6} for ts in toks]
    for i in range(n):
        if items[i]["category"] == "nvd":
            continue  # NVD の項目はタイトルが CVE 番号のみのため語では結ばない
        for j in range(i + 1, n):
            if items[j]["category"] == "nvd":
                continue
            shared = rare[i] & rare[j]
            named = any(re.search(r"2shell|shell$|^[a-z]+bleed$", t) for t in shared)
            # 「」の製品名が相手のタイトルにも出てくる（日英の記事をまたいで結ぶため）
            bracket = _bracket_match(names[i], toks[j]) or _bracket_match(names[j], toks[i])
            if len(shared) >= MIN_SHARED_TOKENS or named or bracket:
                uf.union(i, j)
    groups = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(items[i])
    return list(groups.values())


# ---------- 採点 ----------

def score_cluster(members, cve_info):
    cves = sorted({c for it in members for c in it["cves"]})
    infos = [cve_info.get(c, {}) for c in cves]
    sources = sorted({it["source"] for it in members})
    cats = {it["category"] for it in members}
    text = " ".join(f"{it['title']} {it['summary']}" for it in members if it["category"] != "nvd")

    breakdown = {}
    if any(i.get("in_kev") for i in infos) or "kev" in cats:
        breakdown["in_kev"] = W["in_kev"]
    if any((it["meta"].get("ransomware") or "").lower() == "known" for it in members):
        breakdown["kev_ransomware"] = W["kev_ransomware"]
    if "jp_alert" in cats:
        breakdown["jp_alert"] = W["jp_alert"]
    if "jp_vuln" in cats:
        breakdown["jp_vuln"] = W["jp_vuln"]
    if "outage" in cats:
        breakdown["outage"] = W["outage"]
    if len(sources) > 1:
        breakdown["multi_source"] = min((len(sources) - 1) * W["per_extra_source"], W["extra_source_cap"])
    cvss = max([i.get("cvss") or 0 for i in infos] + [it["meta"].get("cvss") or 0 for it in members])
    if cvss >= 9.0:
        breakdown["cvss"] = W["cvss_critical"]
    elif cvss >= 7.0:
        breakdown["cvss"] = W["cvss_high"]
    epss = max([i.get("epss") or 0 for i in infos] or [0])
    if epss >= 0.5:
        breakdown["epss"] = W["epss_high"]
    elif epss >= 0.1:
        breakdown["epss"] = W["epss_mid"]
    if EXPLOITED_RE.search(text):
        breakdown["exploited_word"] = W["exploited_word"]
    if INCIDENT_RE.search(text):
        breakdown["incident_word"] = W["incident_word"]
    if LARGE_SCALE_RE.search(text):
        breakdown["large_scale"] = W["large_scale"]
    if cats == {"nvd"}:
        breakdown["nvd_only"] = W["nvd_only"]

    # 代表タイトル：報道 → 注意喚起 → KEV → NVD の順で、媒体の多い言語を優先せず最初のもの
    order = {"news": 0, "jp_alert": 1, "jp_vuln": 2, "outage": 3, "kev": 4, "nvd": 5}
    rep = sorted(members, key=lambda it: (order.get(it["category"], 9), it["published"] or ""))[0]
    return {
        "score": sum(breakdown.values()),
        "score_breakdown": breakdown,
        "title": rep["title"],
        "sources": sources,
        "categories": sorted(cats),
        "max_cvss": cvss or None,
        "max_epss": epss or None,
        "cves": {c: cve_info.get(c, {}) for c in cves},
        "items": [
            {k: it[k] for k in ("source", "category", "lang", "title", "url", "published", "summary", "meta")}
            for it in sorted(members, key=lambda it: it["published"] or "", reverse=True)
        ],
    }


def run(data, top, nvd_only_max=5, outage_only_max=3):
    clusters = [score_cluster(m, data["cve_info"]) for m in cluster(data["items"])]
    clusters.sort(key=lambda c: (-c["score"], -len(c["sources"]), -(c["max_epss"] or 0), c["title"]))
    for i, c in enumerate(clusters, 1):
        c["cluster_id"] = f"c{i:03d}"
    # 単一種別だけの事案は数が多くなりがちなので、種別ごとに候補へ入れる数を制限する
    # - NVD 単独（未報道）：無名製品が大半
    # - 障害情報単独（報道なし）：小規模な遅延・一部機能の不具合が大半
    caps = {"nvd": nvd_only_max, "outage": outage_only_max}
    used = {k: 0 for k in caps}
    picked, rest = [], []
    for c in clusters:
        only = c["categories"][0] if len(c["categories"]) == 1 and c["categories"][0] in caps else None
        if len(picked) < top and (only is None or used[only] < caps[only]):
            picked.append(c)
            if only:
                used[only] += 1
        else:
            rest.append(c)
    return {
        "generated_at": data["generated_at"],
        "window_hours": data["window_hours"],
        "source_status": data["source_status"],
        "item_count": data["item_count"],
        "cluster_count": len(clusters),
        "weights": W,
        "candidates": picked,
        # 落とした事案もタイトルだけは残し、Claude が拾い直せるようにする
        "others": [
            {"cluster_id": c["cluster_id"], "score": c["score"], "title": c["title"],
             "sources": c["sources"], "url": c["items"][0]["url"]}
            for c in rest
        ],
    }


def latest_candidates():
    files = sorted(f for f in glob.glob(os.path.join(ROOT, "data", "candidates", "*.json"))
                   if not f.endswith(".scored.json"))
    if not files:
        raise SystemExit("候補ファイルがありません。先に python -m collector.collect を実行してください")
    return files[-1]


def main():
    p = argparse.ArgumentParser(description="候補を重複統合・事前採点して上位を残す")
    p.add_argument("--in", dest="src", help="入力JSON（省略時は data/candidates の最新）")
    p.add_argument("--out", help="出力JSON（省略時は入力名.scored.json）")
    p.add_argument("--top", type=int, default=30, help="残す事案数")
    p.add_argument("--nvd-only-max", type=int, default=5, help="未報道のNVD単独事案を残す上限")
    p.add_argument("--outage-only-max", type=int, default=3, help="未報道の障害情報単独事案を残す上限")
    args = p.parse_args()

    src = args.src or latest_candidates()
    with open(src, encoding="utf-8") as f:
        data = json.load(f)
    result = run(data, args.top, args.nvd_only_max, args.outage_only_max)
    out = args.out or src[:-5] + ".scored.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)

    print(f"items={result['item_count']} clusters={result['cluster_count']} "
          f"candidates={len(result['candidates'])} -> {out}")
    for c in result["candidates"]:
        print(f"  {c['score']:>4} [{len(c['sources'])}媒体] {c['title'][:70]}")


if __name__ == "__main__":
    main()
