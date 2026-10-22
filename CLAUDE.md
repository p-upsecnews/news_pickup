# news_pickup — セキュリティニュース自動ピックアップ

## 目的
脆弱性・サービス停止・情報漏洩などのセキュリティニュースを毎朝自動で収集し、
**「AIに直近のニュースをまとめてと頼んだ程度の情報量」**に絞って、PC・スマホのブラウザで把握できるようにする。

- 対象は自社だけでなく客先の製品・サービスも含むため、特定製品の加点はせず**「一般的に影響が大きいもの」**を優先する
- 例：psps2shell のように広く影響し悪用が進んでいるものは最優先で扱う

## 全体構成（方式B：収集スクリプト＋Claude）
```
毎朝 10:00 JST（= 01:00 UTC, cron `0 1 * * *`）クラウドルーティンが起動
  ├─ 収集スクリプト（Python）を実行 → 候補JSON
  ├─ 事前採点・重複統合 → 上位30件前後に絞る
  ├─ Claude が最終判定（🔴🟡⚪）と3行要約
  ├─ レポートHTMLを生成して commit & push
  └─ 🔴があれば通知（設定されるまで無効）
表示：GitHub Pages（予定）
```

### 役割分担の考え方
- **機械的に確実に拾うべきもの**（KEV掲載、公的機関の注意喚起、スコア）はスクリプトで取得する。取りこぼしと日ごとのムラを防ぐため
- **判断が必要なもの**（同一事案の統合、影響の大きさ、要約）はClaudeが担う
- キーワードでの記事フィルタは使わない。ノイズが増えるため、客観的シグナルで優先度を付ける

## 情報源
| 種類 | 情報源 | 用途 |
|---|---|---|
| 悪用確認済み脆弱性 | CISA KEV | 最重要シグナル |
| 国内公的機関 | JPCERT/CC 注意喚起、IPA 重要なセキュリティ情報 | 国内影響 |
| スコア | NVD（CVSS）、FIRST EPSS | 深刻度・悪用可能性 |
| ニュース | Security NEXT、BleepingComputer、The Hacker News 等のRSS | 事件（漏洩・停止など） |

**情報源を追加・変更したら、クラウド環境（claude.ai/code の環境 `Default`）のネットワーク許可リストも更新すること。**
クラウド環境は Custom（許可ドメインのみ＋既定のパッケージ管理系）で運用しており、未許可のホストは 403 で拒否される。
現在の許可ドメイン：`www.cisa.gov` `services.nvd.nist.gov` `api.first.org` `www.jpcert.or.jp` `www.ipa.go.jp`
`www.security-next.com` `piyolog.hatenadiary.jp` `www.bleepingcomputer.com` `feeds.feedburner.com` `www.securityweek.com`
`jvn.jp` `rss.itmedia.co.jp` `status.aws.amazon.com` `www.cloudflarestatus.com` `www.githubstatus.com`

追加情報源（2026-10-22）と、その理由：
- JVN（jp_vuln）：国産製品の脆弱性はKEVに載るまで拾えなかった
- ITmedia（news）：国内の大型漏洩（数百万件規模）がSecurity NEXTだけでは漏れていた
- AWS / Cloudflare / GitHub の障害情報（outage）：攻撃ではないサービス停止はセキュリティ媒体に載りにくい。
  定期メンテ予告・未来日付・「正常稼働」通知は除外し、報道のない障害単独の事案は候補に3件まで
- Microsoft 365 / Azure の障害フィードは中身がほぼ空だったため見送り

収集範囲は直近48時間（前日分の取りこぼし防止）。過去に掲載済みのものは続報として既存項目に紐付ける。

## 優先度の判断基準
加点シグナル（大きい順の目安）：
1. CISA KEV 掲載／「悪用確認済み」と報道
2. 複数の情報源が同一事案を報道（大きな事案ほど多くの媒体に載る）
3. CVSS 9.0以上、EPSS が高い、PoC公開済み
4. JPCERT/CC・IPA が注意喚起を出している
5. 大規模な情報漏洩・広範なサービス停止

表示区分：
- 🔴 緊急：今日中に影響確認・対応が必要
- 🟡 注目：把握しておくべき
- ⚪ その他：折りたたみ表示

各項目の要約は3行：**何が起きたか／誰に影響するか／何をすべきか**。

## 通知
- 🔴のみ通知する。モジュールは実装するが、**設定されるまで無効**
- Slack は未連携。連携時は claude.ai の Slack コネクタをルーティンに追加する方式とする
- Webhook URL・トークン等の秘密情報はリポジトリに書かない

## 実装ルール
- 言語：Python。コメントは日本語
- ファイル入出力は `encoding="utf-8"` を明示する（Windows の既定 cp932 対策）
- ローカルで日本語を表示確認するときは `PYTHONIOENCODING=utf-8` を付ける
- クラウドルーティンはローカルファイル・環境変数にアクセスできない前提で設計する
- 外部APIはレート制限に配慮し、取得失敗した情報源があっても全体は止めずにレポートに明記する

## 実装ステップ
1. [x] CLAUDE.md 作成
2. [x] 土台（フォルダ構成、git init）
3. [x] 収集スクリプト（`python -m collector.collect` → `data/candidates/<JST日付>.json`）
4. [x] 事前採点＋重複統合（`python -m collector.score` → `<日付>.scored.json`。重みは `collector/score.py` の `W`）
   - 統合は誤統合（別事案の混入）を避ける側に倒している。統合漏れはClaudeが最終判定で補う
5. [x] ルーティン用プロンプト（`prompts/routine.md`。ルーティン本体には「この手順書に従え」とだけ書き、手順はリポジトリで版管理する）
6. [x] 表示ページ（`docs/index.html` が `docs/data/index.json` と `<日付>.json` を読む静的ページ）
   - レポートは `python -m publisher.validate docs/data/<日付>.json` で検証してから公開する
   - 検証では形式・件数上限・URLスキームに加え、**出典URLがその日の候補データに実在するか**を照合する（AIのURL取り違え対策。試作時に実際に発生した）
   - 選択日の下に過去7日分を続けて表示（過去の日はキーワード一覧のみ、詳細は折りたたみ）。PCでは最大幅1400px・文字17〜18px
   - 「キーワード一覧 → タップで詳細」の2段構成。読む時間がなくても上部の一覧だけで話題を把握できることを優先する
     - 各項目の `keyword`（最大16文字、製品名・攻撃の通称）と `target`（最大10文字、影響範囲）を一覧に使う。2026-10-22以降は必須
   - ページはレポート内の文字列を textContent でのみ描画する（外部記事由来の文字列をHTMLとして解釈しない）
   - ローカル確認：`python -m http.server 8765 --directory docs`
7. [x] 通知モジュール（無効状態。`publisher/notify.py`、設定は `config/notify.json`）
   - 既定は connector 方式（claude.ai の Slack コネクタをルーティンに追加し、Claudeが投稿）。APIキー等の秘密情報が不要なため
   - webhook 方式は環境変数 `SLACK_WEBHOOK_URL` のみから読み、送信先を hooks.slack.com に限定
   - 有効化手順：Slackコネクタ連携 → ルーティンに接続を追加 → `enabled: true`・`slack_channel`・`page_url` を設定
8. [x] GitHub push → Pages → ルーティン作成 → 試運転（2026-10-22 成功）
   - リポジトリ：https://github.com/p-upsecnews/news_pickup （公開ページ：https://p-upsecnews.github.io/news_pickup/ ）
   - ルーティン：「セキュリティニュース朝刊」 https://claude.ai/code/routines/trig_01TFMphgCNX9TyxL1KZKaAgH
     - 毎日 01:00 UTC（10:00 JST）、Sonnet 5.5、ツールは Bash/Read/Write/Edit/Glob/Grep のみ、MCPコネクタなし
     - 作成時に既存のコネクタ（Google Calendar 等）が自動付与されたため外した。設定変更時は再付与されていないか確認する
   - クラウドのルーティンは main へ直接 push できる（ブランチ制限なし）
   - ローカルから main へ push する場合は、先に `git pull` してルーティンのコミットを取り込むこと

## 決定事項
- 公開リポジトリ＋GitHub Pages で公開する
  - 公開されるため、元記事の本文・RSS要約はコミットしない（候補JSONは .gitignore）。コミットするのはClaudeが書いた要約とリンクのみ（著作権配慮）
- 土日も含め毎日配信（cron `0 1 * * *` UTC）
- 使用モデル：Sonnet 5.5

## 未決事項
- GitHub アカウントの確認（リポジトリ作成時）
