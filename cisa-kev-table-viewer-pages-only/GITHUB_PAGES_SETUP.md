# GitHub Pages 公開手順

この版は GitHub Pages 専用です。Chrome 拡張機能用の `manifest.json`、`rules.json`、`popup.html` は含めていません。

## 1. リポジトリへ配置

このフォルダの内容を GitHub リポジトリのルートに配置して push します。

```bash
git add .
git commit -m "Add CISA KEV Viewer for GitHub Pages"
git push origin main
```

## 2. GitHub Pages の設定

1. GitHub のリポジトリ画面で `Settings` → `Pages` を開きます。
2. `Build and deployment` の `Source` を `GitHub Actions` にします。
3. `main` ブランチへ push すると、`Deploy KEV Viewer to GitHub Pages` ワークフローが実行されます。
4. デプロイ完了後、Pages 設定画面または Actions の出力に表示される URL を開きます。

## 3. ワークフローの内容

`.github/workflows/deploy-pages.yml` は以下を行います。

- `app.js` の構文チェック
- `index.html`、`app.js`、`style.css`、`icons/` を Pages artifact として作成
- GitHub Pages へデプロイ

## 4. データ取得

アプリはブラウザから CISA 公式 KEV JSON を取得します。取得に失敗した場合は、CISA が GitHub で公開している KEV データへフォールバックします。

取得結果はブラウザの `localStorage` に 24 時間キャッシュされます。サーバ側にデータは保存しません。

## 5. 定期実行について

現在のワークフローには `schedule` を入れていません。データはユーザーのブラウザが表示時に取得するため、GitHub Actions で日次更新する必要はありません。
