# セキュリティレビュー

## 対象

GitHub Pages 専用の静的 Web アプリとしての CISA KEV Viewer を対象にしています。Chrome 拡張機能の権限、manifest、declarativeNetRequest は使用しません。

## 外部入力

- CISA KEV JSON
- CISA GitHub ミラーの KEV JSON

## XSS 対策

- 取得した JSON の値は、原則として `textContent` と `createElement` で DOM に反映します。
- 外部データを `innerHTML` に直接挿入しません。
- 外部リンクは `target="_blank"`、`rel="noopener noreferrer"`、`referrerPolicy="no-referrer"` を設定します。

## ローカル保存

- キャッシュはブラウザの `localStorage` に保存します。
- 保存対象は CISA KEV の公開データと取得日時のみです。
- 個人情報や認証情報は保存しません。

## 権限

GitHub Pages 専用のため、ブラウザ拡張機能の権限はありません。

## GitHub Actions

- `app.js` の構文チェックを行います。
- Pages へのデプロイに必要な `pages: write` と `id-token: write` のみを付与しています。
