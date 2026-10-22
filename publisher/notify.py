"""🔴（緊急）の項目を通知する

通知方法は config/notify.json の mode で切り替える。
- connector：通知文を出力するだけ。ルーティンのClaudeが claude.ai の Slack コネクタで投稿する
- webhook  ：環境変数 SLACK_WEBHOOK_URL の Incoming Webhook へ送信する

秘密情報（Webhook URL）はリポジトリに置かず、環境変数からのみ読む。

使い方:
    python -m publisher.notify docs/data/YYYY-MM-DD.json [--dry-run]
"""
import argparse
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 送信先を Slack に限定する（設定ミスや改ざんで任意のURLへ内容が送られるのを防ぐ）
WEBHOOK_RE = re.compile(r"^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+$")
LEVEL_MARK = {"critical": "🔴", "notable": "🟡", "other": "⚪"}


def load_config():
    with open(os.path.join(ROOT, "config", "notify.json"), encoding="utf-8") as f:
        return json.load(f)


def build_message(report, conf):
    """通知本文を作る。対象がなければ None"""
    targets = [it for it in report["items"] if it["level"] in conf.get("levels", ["critical"])]
    if not targets:
        return None
    lines = [f"*セキュリティニュース {report['date']}*　{LEVEL_MARK['critical']} {len(targets)}件"]
    for it in targets:
        mark = LEVEL_MARK.get(it["level"], "")
        update = "【続報】" if it.get("is_update") else ""
        lines.append(f"{mark} {update}{it['title']}")
        if it.get("action"):
            lines.append(f"　→ {it['action']}")
    page = conf.get("page_url")
    if page:
        lines.append(f"詳細: {page}#{report['date']}")
    return "\n".join(lines)


def send_webhook(text):
    url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not WEBHOOK_RE.match(url):
        raise RuntimeError("SLACK_WEBHOOK_URL が未設定、または Slack の Webhook URL ではありません")
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        if r.status != 200:
            raise RuntimeError(f"Slack への送信に失敗しました（HTTP {r.status}）")


def main():
    p = argparse.ArgumentParser(description="緊急項目を通知する")
    p.add_argument("report", help="docs/data/YYYY-MM-DD.json")
    p.add_argument("--dry-run", action="store_true", help="送信せずに通知文だけ表示する（設定が無効でも表示）")
    args = p.parse_args()

    conf = load_config()
    with open(args.report, encoding="utf-8") as f:
        report = json.load(f)
    text = build_message(report, conf)

    if args.dry_run:
        print(text or "通知対象なし")
        return
    if not conf.get("enabled"):
        print("通知は無効です（config/notify.json の enabled が false）")
        return
    if text is None:
        print("通知対象なし")
        return

    mode = conf.get("mode")
    if mode == "connector":
        # ルーティンのClaudeがこの出力を Slack コネクタで投稿する
        print(f"NOTIFY_VIA_CONNECTOR channel={conf.get('slack_channel', '')}")
        print("----- message -----")
        print(text)
    elif mode == "webhook":
        send_webhook(text)
        print("Slack へ通知しました")
    else:
        print(f"未知の mode です: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
