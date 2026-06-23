# CISA KEV Viewer for GitHub Pages

CISA Known Exploited Vulnerabilities Catalog の JSON を、検索・絞り込み可能な表形式で表示する GitHub Pages 専用の静的 Web アプリです。

## 主な機能

- CISA KEV 公式 JSON の取得
- CISA 公式 JSON が取得できない場合の GitHub ミラーへのフォールバック
- ブラウザ `localStorage` による 24 時間キャッシュ
- CVE、ベンダ、製品、脆弱性名、脆弱性種別、影響対象ジャンル、CWE、必要な対応、備考の検索
- ベンダ、CWE、脆弱性種別、影響対象ジャンル、ランサムウェア利用、対応期限による絞り込み
- Vulnrichment Raw JSON、JVN CWE 説明ページ、CISA/NIST/関連情報等へのリンク
- CSV 出力

## ファイル構成

```text
.
├── index.html
├── app.js
├── style.css
├── icons/
└── .github/workflows/deploy-pages.yml
```

## GitHub Pages での公開

1. このフォルダの内容を GitHub リポジトリに push します。
2. GitHub の `Settings` → `Pages` を開きます。
3. `Build and deployment` の `Source` を `GitHub Actions` にします。
4. `main` ブランチに push すると、`.github/workflows/deploy-pages.yml` が実行されます。
5. デプロイ完了後、Pages の URL から `index.html` が表示されます。

## ローカル確認

```bash
node --check app.js
python3 -m http.server 8000
```

その後、ブラウザで `http://localhost:8000/` を開きます。

## セキュリティ・プライバシー方針

- ユーザーの閲覧履歴、Cookie、フォーム入力、個人情報は取得しません。
- 外部送信するのは CISA KEV JSON と GitHub ミラーの取得リクエストのみです。
- キャッシュはブラウザの `localStorage` に保存されます。
- CWE 名称はアプリ内の固定辞書を利用します。実行時に JVN ページを巡回取得する処理はありません。
- DOM 生成は `textContent` と `createElement` を使用し、取得データを `innerHTML` に直接挿入しません。
- 外部リンクは `target="_blank"`、`rel="noopener noreferrer"`、`referrerPolicy="no-referrer"` を設定します。
