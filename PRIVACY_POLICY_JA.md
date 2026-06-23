# プライバシーポリシー

CISA KEV Viewer for GitHub Pages は、米国 CISA が公開する Known Exploited Vulnerabilities Catalog の JSON データを表形式で表示する静的 Web アプリです。

## 取得する情報

本アプリは、ユーザーの個人情報、閲覧履歴、Cookie、認証情報、フォーム入力、位置情報、ファイル内容、通信内容を収集しません。

## 外部通信

本アプリは、以下の公開データを取得するために外部通信を行います。

- CISA Known Exploited Vulnerabilities Catalog JSON
- CISA GitHub ミラー上の KEV JSON
- Vulnrichment、NVD、JVN、CISA 等への外部リンクをユーザーが明示的に開いた場合の通信

## ローカル保存

本アプリは、CISA KEV データの取得回数を抑えるため、取得した公開 JSON データと取得日時をブラウザの `localStorage` に保存します。このデータはユーザー個人を識別するものではありません。

## 第三者提供

本アプリは、ユーザーデータを第三者に販売、共有、提供しません。
