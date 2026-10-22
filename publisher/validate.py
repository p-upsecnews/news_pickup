"""Claude が書いたレポートJSONを検証し、表示ページ用の目次（docs/data/index.json）を更新する

レポートは公開ページにそのまま載るため、形式・文字数・URLを機械的に確認してから公開する。
（収集した記事は外部の文章なので、不正なURLや想定外の値が紛れ込む可能性を前提にする）

使い方:
    python -m publisher.validate docs/data/YYYY-MM-DD.json
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "docs", "data")

LEVELS = {"critical": 5, "notable": 10, "other": 15}  # 区分ごとの上限件数
KINDS = {"vulnerability", "incident", "outage", "other"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
URL_RE = re.compile(r"^https?://[^\s\"'<>]+$")
TEXT_MAX = {"headline": 200, "title": 80, "what": 200, "who": 200, "action": 200}


def _check_text(errors, where, value, key, required=True):
    if value is None or value == "":
        if required:
            errors.append(f"{where}: {key} が空です")
        return
    if not isinstance(value, str):
        errors.append(f"{where}: {key} は文字列である必要があります")
    elif len(value) > TEXT_MAX[key]:
        errors.append(f"{where}: {key} が長すぎます（{len(value)}文字 > {TEXT_MAX[key]}）")


def known_urls(date):
    """その日の候補データに含まれるURLの集合。候補ファイルがなければ None（照合しない）"""
    path = os.path.join(ROOT, "data", "candidates", f"{date}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {it["url"] for it in data.get("items", [])}


def validate(report, urls=None):
    """urls を渡すと、出典URLが候補データに実在するかも確認する（AIによるURLの創作・取り違え対策）"""
    errors = []
    if not DATE_RE.match(str(report.get("date", ""))):
        errors.append("date が YYYY-MM-DD 形式ではありません")
    _check_text(errors, "report", report.get("headline"), "headline")
    items = report.get("items")
    if not isinstance(items, list):
        return errors + ["items が配列ではありません"]

    counts = {k: 0 for k in LEVELS}
    for n, it in enumerate(items):
        where = f"items[{n}]"
        level = it.get("level")
        if level not in LEVELS:
            errors.append(f"{where}: level が不正です（{level}）")
        else:
            counts[level] += 1
        if it.get("kind") not in KINDS:
            errors.append(f"{where}: kind が不正です（{it.get('kind')}）")
        for key in ("title", "what", "who", "action"):
            # ⚪ は見出しと概要だけでよい
            _check_text(errors, where, it.get(key), key, required=(key in ("title", "what") or level != "other"))
        for c in it.get("cves", []):
            if not CVE_RE.match(str(c)):
                errors.append(f"{where}: CVE番号の形式が不正です（{c}）")
        if not isinstance(it.get("is_update", False), bool):
            errors.append(f"{where}: is_update は true/false です")
        srcs = it.get("sources")
        if not isinstance(srcs, list) or not srcs:
            errors.append(f"{where}: sources が空です")
            continue
        for s in srcs:
            if not isinstance(s, dict) or not s.get("name") or not URL_RE.match(str(s.get("url", ""))):
                errors.append(f"{where}: sources の name/url が不正です（{s}）")
            elif urls is not None and s["url"] not in urls:
                errors.append(f"{where}: 候補データにないURLです（{s['url']}）")

    for level, limit in LEVELS.items():
        if counts[level] > limit:
            errors.append(f"{level} が多すぎます（{counts[level]}件 > {limit}件）")
    return errors


def update_index(report):
    """表示ページが読む日付一覧を更新する（新しい日付が先頭）"""
    path = os.path.join(DATA_DIR, "index.json")
    index = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            index = json.load(f)
    index = [d for d in index if d["date"] != report["date"]]
    counts = {k: sum(1 for it in report["items"] if it["level"] == k) for k in LEVELS}
    index.append({"date": report["date"], "headline": report["headline"], **counts})
    index.sort(key=lambda d: d["date"], reverse=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=1)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("使い方: python -m publisher.validate docs/data/YYYY-MM-DD.json")
    path = sys.argv[1]
    with open(path, encoding="utf-8") as f:
        report = json.load(f)
    urls = known_urls(report.get("date"))
    if urls is None:
        print("注意: 候補データがないため、出典URLの照合を省略します")
    errors = validate(report, urls)
    if os.path.basename(path) != f"{report.get('date')}.json":
        errors.append("ファイル名と date が一致しません")
    if errors:
        print("NG: レポートに問題があります。修正して再実行してください")
        for e in errors:
            print("  -", e)
        sys.exit(1)
    update_index(report)
    crit = [it for it in report["items"] if it["level"] == "critical"]
    print(f"OK: {report['date']} critical={len(crit)} items={len(report['items'])}")
    for it in crit:
        print(f"  🔴 {it['title']}")


if __name__ == "__main__":
    main()
