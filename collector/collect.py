"""収集のエントリポイント

使い方:
    python -m collector.collect [--hours 48] [--out data/candidates/YYYY-MM-DD.json] [--no-nvd-lookup]
"""
import argparse
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

from . import sources

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JST = timezone(timedelta(hours=9))


def load_config():
    with open(os.path.join(ROOT, "config", "sources.json"), encoding="utf-8") as f:
        return json.load(f)


def run(hours, nvd_lookup=True):
    conf = load_config()
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    items, status = [], []
    kev_cves, cvss_map = set(), {}

    def record(name, func):
        # 1つの情報源が失敗しても全体は止めず、結果に記録する
        try:
            got = func()
            status.append({"name": name, "ok": True, "count": len(got)})
            items.extend(got)
        except Exception as e:
            status.append({"name": name, "ok": False, "count": 0, "error": repr(e)[:200]})

    def kev():
        got, all_cves = sources.fetch_kev(conf["kev"], since)
        kev_cves.update(all_cves)
        return got

    def nvd():
        got, m = sources.fetch_nvd_recent(conf["nvd"], since, now)
        cvss_map.update(m)
        return got

    record(conf["kev"]["name"], kev)
    record(conf["nvd"]["name"], nvd)
    for feed in conf["feeds"]:
        record(feed["name"], lambda feed=feed: sources.fetch_feed(feed, since))

    # 言及されたCVEの補足情報（KEV掲載・CVSS・EPSS）
    mentions = Counter(c for it in items for c in it["cves"])
    if nvd_lookup:
        # CVSS 未取得のものを、言及数の多い順に個別取得する
        missing = [c for c, _ in mentions.most_common() if c not in cvss_map]
        cvss_map.update(sources.lookup_nvd_cvss(conf["nvd"], missing))
    epss = {}
    try:
        epss = sources.fetch_epss(conf["epss"], mentions.keys())
        status.append({"name": "EPSS", "ok": True, "count": len(epss)})
    except Exception as e:
        status.append({"name": "EPSS", "ok": False, "count": 0, "error": repr(e)[:200]})

    cve_info = {
        c: {
            "mentions": n,
            "in_kev": c in kev_cves,
            "cvss": cvss_map.get(c),
            "epss": epss.get(c, {}).get("epss"),
            "epss_percentile": epss.get(c, {}).get("percentile"),
        }
        for c, n in mentions.items()
    }

    return {
        "generated_at": now.isoformat(),
        "window_hours": hours,
        "since": since.isoformat(),
        "source_status": status,
        "item_count": len(items),
        "items": items,
        "cve_info": cve_info,
    }


def main():
    p = argparse.ArgumentParser(description="セキュリティ情報の候補を収集する")
    p.add_argument("--hours", type=int, default=48, help="収集対象の期間（時間）")
    p.add_argument("--out", help="出力先JSON（省略時は data/candidates/<JST日付>.json）")
    p.add_argument("--no-nvd-lookup", action="store_true", help="CVSSの個別取得を省略する（動作確認用）")
    args = p.parse_args()

    result = run(args.hours, nvd_lookup=not args.no_nvd_lookup)
    out = args.out or os.path.join(ROOT, "data", "candidates", datetime.now(JST).strftime("%Y-%m-%d") + ".json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)

    # 実行結果の概要（ルーティンのログ確認用）
    print(f"items={result['item_count']} cves={len(result['cve_info'])} -> {out}")
    for s in result["source_status"]:
        mark = "OK" if s["ok"] else "NG"
        print(f"  [{mark}] {s['name']}: {s['count']}" + (f"  {s.get('error')}" if not s["ok"] else ""))


if __name__ == "__main__":
    main()
