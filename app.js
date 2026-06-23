const CISA_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const GITHUB_FALLBACK_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";
const VULNRICHMENT_RAW_URL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop";
const CACHE_KEY = "cisaKevCache";
const CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

const CWE_NAME_JA = {
  "CWE-16": "設定",
  "CWE-19": "データ処理の不備",
  "CWE-20": "不適切な入力検証",
  "CWE-22": "パストラバーサル",
  "CWE-23": "相対パストラバーサル",
  "CWE-24": "パストラバーサルの制限不備",
  "CWE-25": "パストラバーサル: /../filedir",
  "CWE-27": "パストラバーサル: dir/../../filename",
  "CWE-35": "パストラバーサル",
  "CWE-36": "絶対パストラバーサル",
  "CWE-39": "パストラバーサル: C:dirname",
  "CWE-40": "パストラバーサル: UNC共有",
  "CWE-44": "パス同等性: 内部ドットの複数使用",
  "CWE-55": "パス同等性: 末尾ドット",
  "CWE-59": "リンク解釈の不備",
  "CWE-61": "UNIXシンボリックリンク追跡",
  "CWE-73": "外部制御によるファイル名またはパス名",
  "CWE-74": "特殊要素の不適切な無害化",
  "CWE-77": "コマンドにおける特殊要素の不適切な無害化",
  "CWE-78": "OSコマンドインジェクション",
  "CWE-79": "クロスサイトスクリプティング",
  "CWE-80": "HTMLスクリプト関連要素の不適切な無害化",
  "CWE-88": "引数インジェクション",
  "CWE-89": "SQLインジェクション",
  "CWE-90": "LDAPインジェクション",
  "CWE-91": "XMLインジェクション",
  "CWE-93": "CRLFシーケンスの不適切な無害化",
  "CWE-94": "コードインジェクション",
  "CWE-95": "evalインジェクション",
  "CWE-96": "静的に保存されるコードにおける特殊要素の不適切な無害化",
  "CWE-98": "PHPリモートファイルインクルード",
  "CWE-113": "HTTPレスポンス分割",
  "CWE-114": "プロセス制御",
  "CWE-116": "出力の不適切なエンコードまたはエスケープ",
  "CWE-119": "メモリバッファ境界内の操作制限不備",
  "CWE-120": "境界チェックなしのバッファコピー",
  "CWE-121": "スタックベースのバッファオーバーフロー",
  "CWE-122": "ヒープベースのバッファオーバーフロー",
  "CWE-123": "任意位置書き込み",
  "CWE-124": "バッファアンダーライト（バッファアンダーフロー）",
  "CWE-125": "境界外読み取り",
  "CWE-129": "配列インデックスの不適切な検証",
  "CWE-130": "長さパラメータの不適切な処理",
  "CWE-131": "バッファサイズ計算の誤り",
  "CWE-134": "書式文字列の不備",
  "CWE-138": "特殊要素の不適切な無害化",
  "CWE-158": "NULLバイトまたはNUL文字の不適切な無害化",
  "CWE-178": "大文字小文字の不適切な処理",
  "CWE-184": "禁止された入力の不完全なリスト",
  "CWE-189": "数値処理の不備",
  "CWE-190": "整数オーバーフローまたはラップアラウンド",
  "CWE-191": "整数アンダーフロー",
  "CWE-193": "オフバイワンエラー",
  "CWE-197": "数値切り捨てエラー",
  "CWE-200": "情報漏えい",
  "CWE-203": "観測可能な不一致による情報漏えい",
  "CWE-208": "タイミング差による情報漏えい",
  "CWE-209": "エラーメッセージによる情報漏えい",
  "CWE-250": "不必要な権限での実行",
  "CWE-252": "戻り値の未チェック",
  "CWE-254": "セキュリティ機能",
  "CWE-255": "認証情報管理の不備",
  "CWE-257": "復元可能な形式でのパスワード保存",
  "CWE-259": "ハードコードされたパスワードの使用",
  "CWE-264": "権限・特権・アクセス制御の不備",
  "CWE-266": "不適切な権限割り当て",
  "CWE-267": "権限定義が不十分な権限の使用",
  "CWE-269": "不適切な権限管理",
  "CWE-273": "ドロップされた権限の不適切な処理",
  "CWE-274": "不十分な特権の不適切な処理",
  "CWE-276": "デフォルト権限の不備",
  "CWE-280": "不十分な権限または特権の不適切な処理",
  "CWE-281": "不適切な権限保持",
  "CWE-282": "所有権管理の不備",
  "CWE-284": "不適切なアクセス制御",
  "CWE-285": "不適切な認可",
  "CWE-287": "不適切な認証",
  "CWE-288": "代替パスやチャネルによる認証回避",
  "CWE-290": "スプーフィングによる認証回避",
  "CWE-294": "認証バイパス",
  "CWE-295": "証明書検証の不備",
  "CWE-303": "認証アルゴリズムの実装不備",
  "CWE-305": "認証回避",
  "CWE-306": "重要機能に対する認証欠如",
  "CWE-307": "過度な認証試行の不適切な制限",
  "CWE-310": "暗号処理の不備",
  "CWE-311": "機密データの暗号化欠如",
  "CWE-312": "平文での機密情報保存",
  "CWE-319": "平文での機密情報送信",
  "CWE-320": "鍵管理の不備",
  "CWE-321": "ハードコードされた暗号鍵の使用",
  "CWE-324": "重要なステップでの乱数使用",
  "CWE-326": "暗号強度の不足",
  "CWE-327": "危殆化した暗号アルゴリズムの使用",
  "CWE-330": "不十分な乱数値の使用",
  "CWE-331": "エントロピー不足",
  "CWE-345": "データ真正性の検証不備",
  "CWE-346": "発信元検証エラー",
  "CWE-347": "暗号署名の不適切な検証",
  "CWE-351": "型の区別不足",
  "CWE-352": "クロスサイトリクエストフォージェリ",
  "CWE-353": "完全性チェックのサポート欠如",
  "CWE-357": "危険な操作に対するUI警告不足",
  "CWE-358": "不適切に実装されたセキュリティチェック",
  "CWE-362": "競合状態",
  "CWE-367": "検査時刻と使用時刻の競合状態",
  "CWE-369": "ゼロ除算",
  "CWE-384": "セッション固定",
  "CWE-388": "エラー処理",
  "CWE-390": "エラー状態検出なし",
  "CWE-399": "リソース管理の不備",
  "CWE-400": "制御されないリソース消費",
  "CWE-401": "メモリリーク",
  "CWE-404": "リソースの不適切なシャットダウンまたは解放",
  "CWE-406": "リソース管理エラー",
  "CWE-415": "二重解放",
  "CWE-416": "解放済みメモリ使用",
  "CWE-420": "保護されていない代替チャネル",
  "CWE-424": "代替パスまたはチャネルによる保護メカニズム回避",
  "CWE-425": "直接リクエストによる認可回避",
  "CWE-426": "信頼できない検索パス",
  "CWE-427": "制御されない検索パス要素",
  "CWE-434": "危険な種類のファイルの無制限アップロード",
  "CWE-436": "解釈の競合",
  "CWE-441": "意図しないプロキシまたは中間者",
  "CWE-444": "HTTPリクエストスマグリング",
  "CWE-451": "ユーザインタフェースにおける重要情報の誤表示",
  "CWE-457": "初期化されていない変数の使用",
  "CWE-459": "不完全なクリーンアップ",
  "CWE-470": "外部制御によるクラスやコードの選択",
  "CWE-472": "外部制御による不変と想定されたWebパラメータ",
  "CWE-473": "PHP外部変数の改ざん",
  "CWE-476": "NULLポインタデリファレンス",
  "CWE-494": "整合性チェックなしのコードダウンロード",
  "CWE-497": "システムデータの外部公開",
  "CWE-502": "信頼できないデータのデシリアライゼーション",
  "CWE-506": "埋め込まれた悪意のあるコード",
  "CWE-521": "脆弱なパスワード要件",
  "CWE-522": "認証情報の保護不備",
  "CWE-528": "コアダンプファイルの認可されていない制御領域への公開",
  "CWE-532": "ログファイルへの機密情報挿入",
  "CWE-552": "外部向けディレクトリやファイルの公開",
  "CWE-565": "Cookieへの依存によるセキュリティ判断",
  "CWE-591": "機微情報を含むデバッグコード",
  "CWE-601": "オープンリダイレクト",
  "CWE-610": "外部制御によるリソース識別子への参照",
  "CWE-611": "XML外部エンティティ参照の不適切な制限",
  "CWE-613": "不十分なセッション期限切れ",
  "CWE-617": "到達可能なアサーション",
  "CWE-639": "ユーザー制御キーによる認可回避",
  "CWE-640": "脆弱なパスワード復旧機構",
  "CWE-641": "外部制御による状態データの不適切な制限",
  "CWE-647": "不正な初期化",
  "CWE-648": "WebサービスにおけるSOAPアクションの信頼",
  "CWE-653": "隔離またはコンパートメント化の不備",
  "CWE-664": "ライフタイムを通じたリソースの不適切な制御",
  "CWE-665": "初期化の不備",
  "CWE-667": "不適切なロック",
  "CWE-668": "誤った領域へのリソース公開",
  "CWE-669": "リソースの不適切な移譲",
  "CWE-693": "保護メカニズムの不備",
  "CWE-697": "比較の不備",
  "CWE-703": "例外条件の不適切なチェックまたは処理",
  "CWE-704": "不正な型変換またはキャスト",
  "CWE-706": "名前または参照の解決不備",
  "CWE-707": "不適切な無害化",
  "CWE-732": "重要リソースに対する不適切な権限設定",
  "CWE-749": "危険なメソッドまたは関数の公開",
  "CWE-754": "例外状態チェックの不備",
  "CWE-755": "例外状態の不適切な処理",
  "CWE-772": "有効期限後のリソース解放漏れ",
  "CWE-782": "アクセス制御が不十分なIOCTLの公開",
  "CWE-783": "演算子優先順位の誤り",
  "CWE-785": "パスワード再利用の不適切な制限",
  "CWE-787": "境界外書き込み",
  "CWE-790": "特殊要素の不適切なフィルタリング",
  "CWE-798": "ハードコードされた認証情報の使用",
  "CWE-807": "セキュリティ決定の信頼できない入力への依存",
  "CWE-822": "信頼できないポインタのデリファレンス",
  "CWE-823": "範囲外ポインタオフセットの使用",
  "CWE-824": "初期化されていないポインタへのアクセス",
  "CWE-829": "信頼できない制御領域からの機能取り込み",
  "CWE-835": "無限ループ",
  "CWE-843": "型の混同",
  "CWE-862": "認証欠如",
  "CWE-863": "不適切な認可",
  "CWE-908": "初期化されていないリソースの使用",
  "CWE-912": "隠し機能",
  "CWE-913": "動的に管理されるコードリソースの不適切な制御",
  "CWE-917": "式言語インジェクション",
  "CWE-918": "サーバサイドリクエストフォージェリ",
  "CWE-922": "機密情報の安全でない保存",
  "CWE-923": "通信チャネルの不適切な制限",
  "CWE-940": "通信チャネルの不適切な検証",
  "CWE-943": "データクエリロジックの不適切な無害化",
  "CWE-1021": "UIレイヤやフレームの不適切な制限",
  "CWE-1023": "通信チャネルの同期不備",
  "CWE-1173": "検証フレームワークの不適切な使用",
  "CWE-1188": "リソースの安全ではないデフォルト値への初期化",
  "CWE-1203": "物理的に観測可能な不一致",
  "CWE-1220": "アクセス制御の粒度不足",
  "CWE-1285": "ユーザー制御による大文字小文字変換",
  "CWE-1287": "指定された量を超える入力の不適切な検証",
  "CWE-1321": "プロトタイプ汚染",
  "CWE-1333": "非効率な正規表現による過度な計算量",
  "CWE-1336": "テンプレートエンジンにおける式の不適切な無害化",
  "CWE-1386": "安全でないデフォルト動作を伴うコマンド",
  "CWE-1390": "弱い認証",
  "CWE-1393": "参照解決における安全でないデフォルト動作",
};

const state = {
  allRows: [],
  filteredRows: [],
  sortKey: "dateAdded",
  sortDirection: "desc",
  page: 1,
  pageSize: 100,
  catalogMeta: null,
};

const els = {
  summary: document.getElementById("summary"),
  refreshButton: document.getElementById("refreshButton"),
  searchInput: document.getElementById("searchInput"),
  ransomFilter: document.getElementById("ransomFilter"),
  vendorFilter: document.getElementById("vendorFilter"),
  cweFilter: document.getElementById("cweFilter"),
  vulnerabilityTypeFilter: document.getElementById("vulnerabilityTypeFilter"),
  impactTargetFilter: document.getElementById("impactTargetFilter"),
  deadlineFilter: document.getElementById("deadlineFilter"),
  pageSizeSelect: document.getElementById("pageSizeSelect"),
  clearFiltersButton: document.getElementById("clearFiltersButton"),
  exportButton: document.getElementById("exportButton"),
  status: document.getElementById("status"),
  lastUpdated: document.getElementById("lastUpdated"),
  tableBody: document.getElementById("tableBody"),
  prevButton: document.getElementById("prevButton"),
  nextButton: document.getElementById("nextButton"),
  pageInfo: document.getElementById("pageInfo"),
  emptyTemplate: document.getElementById("emptyTemplate"),
};

init();

function init() {
  els.refreshButton?.addEventListener("click", () => loadKev({ forceRefresh: true }));
  els.searchInput?.addEventListener("input", debounce(applyFilters, 150));
  els.ransomFilter?.addEventListener("change", applyFilters);
  els.vendorFilter?.addEventListener("change", applyFilters);
  els.cweFilter?.addEventListener("change", applyFilters);
  els.vulnerabilityTypeFilter?.addEventListener("change", applyFilters);
  els.impactTargetFilter?.addEventListener("change", applyFilters);
  els.deadlineFilter?.addEventListener("change", applyFilters);
  els.pageSizeSelect?.addEventListener("change", () => {
    state.pageSize = els.pageSizeSelect.value === "all" ? "all" : Number(els.pageSizeSelect.value);
    state.page = 1;
    render();
  });
  els.clearFiltersButton?.addEventListener("click", clearFilters);
  els.exportButton?.addEventListener("click", exportCsv);
  els.prevButton?.addEventListener("click", () => {
    state.page = Math.max(1, state.page - 1);
    render();
  });
  els.nextButton?.addEventListener("click", () => {
    state.page += 1;
    render();
  });
  document.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => setSort(th.dataset.sort));
  });

  loadKev({ forceRefresh: false });
}

async function loadKev({ forceRefresh }) {
  setBusy(true, forceRefresh ? "CISA KEVを更新中..." : "CISA KEVを読み込み中...");

  try {
    const cached = await readCache();
    if (!forceRefresh && cached && Date.now() - cached.fetchedAt < CACHE_MAX_AGE_MS) {
      useCatalog(cached.catalog, cached.fetchedAt, "");
      return;
    }

    const catalog = await fetchCatalog();
    await writeCache(catalog);
    useCatalog(catalog, Date.now(), "");
  } catch (error) {
    const cached = await readCache();
    if (cached) {
      useCatalog(cached.catalog, cached.fetchedAt, `取得に失敗したためキャッシュを表示しています: ${error.message}`);
    } else {
      setStatus(`取得に失敗しました: ${error.message}`);
      els.summary.textContent = "データを表示できませんでした。";
    }
  } finally {
    setBusy(false);
  }
}

async function fetchCatalog() {
  const primary = await fetchJson(CISA_JSON_URL).catch(async (primaryError) => {
    return fetchJson(GITHUB_FALLBACK_URL);
  });

  if (!primary || !Array.isArray(primary.vulnerabilities)) {
    throw new Error("KEV JSONの形式が想定と異なります。");
  }

  return primary;
}

async function fetchJson(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(url, { cache: "no-store", signal: controller.signal });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function useCatalog(catalog, fetchedAt, message) {
  state.catalogMeta = {
    title: catalog.title || "CISA Known Exploited Vulnerabilities Catalog",
    count: catalog.count || catalog.vulnerabilities.length,
    catalogVersion: catalog.catalogVersion || "不明",
    dateReleased: catalog.dateReleased || "不明",
    fetchedAt,
  };
  state.allRows = catalog.vulnerabilities.map(normalizeRow);
  state.page = 1;
  populateFilterOptions();
  applyFilters();
  setStatus(message);
  els.lastUpdated.textContent = `取得: ${formatDateTime(fetchedAt)}`;
}

function normalizeRow(v) {
  const cweValues = normalizeCwes(v.cwes);
  const { notes, cwesFromNotes } = splitNotesAndCwes(v.notes || "");
  const allCwes = mergeUnique([...cweValues, ...cwesFromNotes]);

  return {
    cveID: v.cveID || "",
    vendorProject: v.vendorProject || "",
    product: v.product || "",
    impactTargets: categorizeImpactTargets(v.vendorProject || "", v.product || "", v.vulnerabilityName || "", v.shortDescription || ""),
    impactTargetText: categorizeImpactTargets(v.vendorProject || "", v.product || "", v.vulnerabilityName || "", v.shortDescription || "").join(" "),
    vulnerabilityName: v.vulnerabilityName || "",
    vulnerabilityType: categorizeVulnerabilityName(v.vulnerabilityName || ""),
    vulnerabilityTypeLabel: categorizeVulnerabilityName(v.vulnerabilityName || "").label,
    dateAdded: v.dateAdded || "",
    dateAddedDisplay: formatJapaneseDate(v.dateAdded || ""),
    shortDescription: v.shortDescription || "",
    requiredAction: summarizeRequiredAction(v.requiredAction || ""),
    requiredActionOriginal: v.requiredAction || "",
    requiredActionCategories: categorizeRequiredAction(v.requiredAction || "").categories,
    requiredActionCategory: categorizeRequiredAction(v.requiredAction || "").categories.join(" / "),
    dueDate: v.dueDate || "",
    dueDateInfo: createDueDateInfo(v.dateAdded || "", v.dueDate || ""),
    knownRansomwareCampaignUse: v.knownRansomwareCampaignUse || "Unknown",
    ransomwareLabel: formatRansomwareUse(v.knownRansomwareCampaignUse || "Unknown"),
    notes,
    cwes: allCwes,
    cwesText: allCwes.join(" "),
    cwesDisplayText: allCwes.map(formatCweLabel).join(" "),
  };
}

function normalizeCwes(value) {
  if (Array.isArray(value)) return value.map(String).map((v) => v.trim()).filter(Boolean);
  if (!value) return [];
  return String(value)
    .split(/[;,]/)
    .map((v) => v.trim())
    .filter(Boolean);
}

function splitNotesAndCwes(notes) {
  const text = String(notes || "").trim();
  if (!text) return { notes: "", cwesFromNotes: [] };

  const cwesFromNotes = text.match(/CWE-\d+/gi) || [];
  let cleanedNotes = text
    .replace(/(?:CWE(?:s)?\s*:?\s*)?(?:CWE-\d+)(?:\s*[,;/]\s*CWE-\d+)*/gi, " ")
    .replace(/\s*[,;/]\s*(?=$)/g, "")
    .replace(/\s{2,}/g, " ")
    .trim();

  cleanedNotes = cleanedNotes.replace(/[;；]+/g, " ").replace(/^(?:[,/\-]\s*)+|(?:\s*[,/\-])+$/g, "").replace(/\s{2,}/g, " ").trim();
  return { notes: cleanedNotes, cwesFromNotes };
}

function mergeUnique(values) {
  const seen = new Set();
  return values
    .map((value) => String(value || "").trim().toUpperCase())
    .filter((value) => {
      if (!value || seen.has(value)) return false;
      seen.add(value);
      return true;
    });
}


function categorizeVulnerabilityName(name) {
  const original = String(name || "").replace(/\s+/g, " ").trim();
  const lower = original.toLowerCase();

  if (!original) {
    return { label: "未記載", category: "未記載", original };
  }

  const rules = [
    { label: "リモートコード実行", category: "リモートコード実行", patterns: [/remote code execution|\brce\b|code execution/i] },
    { label: "権限昇格", category: "権限昇格", patterns: [/privilege escalation|elevation of privilege|escalation of privilege/i] },
    { label: "認証回避", category: "認証回避", patterns: [/authentication bypass|auth bypass|improper authentication|missing authentication|authorization bypass|access control bypass|improper authorization/i] },
    { label: "コマンドインジェクション", category: "コマンドインジェクション", patterns: [/command injection|os command/i] },
    { label: "SQLインジェクション", category: "SQLインジェクション", patterns: [/sql injection|\bsqli\b/i] },
    { label: "クロスサイトスクリプティング", category: "クロスサイトスクリプティング", patterns: [/cross-site scripting|cross site scripting|\bxss\b/i] },
    { label: "パストラバーサル", category: "パストラバーサル", patterns: [/path traversal|directory traversal|relative path traversal/i] },
    { label: "ファイル操作の不備", category: "ファイル操作の不備", patterns: [/arbitrary file (?:read|write|upload|download|deletion)|file upload|file inclusion|local file inclusion|remote file inclusion/i] },
    { label: "情報漏えい", category: "情報漏えい", patterns: [/information disclosure|information leak|sensitive information|exposure of sensitive/i] },
    { label: "デシリアライゼーション", category: "デシリアライゼーション", patterns: [/deserialization|unserialize|serialization/i] },
    { label: "SSRF", category: "SSRF", patterns: [/server-side request forgery|server side request forgery|\bssrf\b/i] },
    { label: "XXE", category: "XXE", patterns: [/xml external entity|\bxxe\b/i] },
    { label: "CSRF", category: "CSRF", patterns: [/cross-site request forgery|cross site request forgery|\bcsrf\b/i] },
    { label: "バッファオーバーフロー", category: "バッファオーバーフロー", patterns: [/buffer overflow|heap overflow|stack overflow/i] },
    { label: "解放済みメモリ使用", category: "解放済みメモリ使用", patterns: [/use-after-free|use after free/i] },
    { label: "メモリ破壊", category: "メモリ破壊", patterns: [/memory corruption|out-of-bounds|out of bounds|integer overflow|type confusion|null pointer/i] },
    { label: "入力検証不備", category: "入力検証不備", patterns: [/input validation|improper neutralization|improper restriction/i] },
    { label: "資格情報・認証情報の問題", category: "資格情報・認証情報の問題", patterns: [/hard-coded credentials|hardcoded credentials|default credentials|weak password|credential/i] },
    { label: "暗号処理の問題", category: "暗号処理の問題", patterns: [/cryptographic|certificate|tls|ssl|encryption/i] },
    { label: "サービス運用妨害", category: "サービス運用妨害", patterns: [/denial of service|\bdos\b|resource exhaustion/i] },
    { label: "テンプレートインジェクション", category: "テンプレートインジェクション", patterns: [/template injection|ssti/i] },
    { label: "サンドボックス回避", category: "サンドボックス回避", patterns: [/sandbox escape|sandbox bypass/i] },
  ];

  const matched = rules.find((rule) => rule.patterns.some((pattern) => pattern.test(lower)));
  if (matched) return { ...matched, original };

  return { label: "その他の脆弱性", category: "その他", original };
}


function createVendorProductCell(row) {
  const wrap = document.createElement("div");
  wrap.className = "productCell vendorProductCell";

  const vendor = document.createElement("div");
  vendor.className = "vendorName";
  vendor.textContent = row.vendorProject || "-";
  wrap.appendChild(vendor);

  const product = document.createElement("div");
  product.className = "productName";
  product.textContent = row.product || "-";
  wrap.appendChild(product);

  const tags = document.createElement("div");
  tags.className = "impactTags";
  (row.impactTargets || ["その他"]).forEach((label) => {
    const tag = document.createElement("span");
    tag.className = `impactTag impactTag${impactTargetClass(label)}`;
    tag.textContent = label;
    tags.appendChild(tag);
  });
  wrap.appendChild(tags);
  return wrap;
}

function impactTargetClass(label) {
  const map = {
    "サーバーソフトウェア": "Server",
    "クライアントソフトウェア": "Client",
    "Windows": "Windows",
    "macOS": "Macos",
    "Linux": "Linux",
    "ブラウザ": "Browser",
    "IoT": "Iot",
    "ネットワークデバイス": "Network",
    "その他": "Other",
  };
  return map[label] || "Other";
}

function createVulnerabilityNameCell(row) {
  const wrap = document.createElement("div");
  wrap.className = "vulnNameCell";

  const topLine = document.createElement("div");
  topLine.className = "vulnTopLine";

  const badge = document.createElement("span");
  badge.className = "vulnTypeBadge";
  badge.textContent = row.vulnerabilityTypeLabel || "その他の脆弱性";
  topLine.appendChild(badge);

  const cveWrap = document.createElement("span");
  cveWrap.className = "vulnCveLink";
  cveWrap.appendChild(createCveLink(row.cveID));
  topLine.appendChild(cveWrap);
  wrap.appendChild(topLine);

  const original = document.createElement("div");
  original.className = "vulnOriginalName";
  original.textContent = row.vulnerabilityName || "-";
  wrap.appendChild(original);

  if (Array.isArray(row.cwes) && row.cwes.length > 0) {
    const cweBlock = document.createElement("div");
    cweBlock.className = "vulnCweBlock";
    cweBlock.appendChild(createCweCell(row.cwes));
    wrap.appendChild(cweBlock);
  }

  return wrap;
}


function categorizeImpactTargets(vendor, product, vulnerabilityName, description) {
  const text = [vendor, product, vulnerabilityName, description].join(" ").toLowerCase();
  const labels = [];
  const add = (label) => {
    if (!labels.includes(label)) labels.push(label);
  };

  if (/\bwindows\b|win32k|directx|exchange server|sharepoint/i.test(text)) {
    if (/exchange server|sharepoint/i.test(text)) add("サーバーソフトウェア");
    else add("Windows");
  }
  if (/\bmacos\b|mac os|os x|safari|webkit/i.test(text)) {
    if (/safari|webkit/i.test(text)) add("ブラウザ");
    else add("macOS");
  }
  if (/\blinux\b|linux kernel|ubuntu|debian|red hat|rhel|centos|suse|gnu\/linux/i.test(text)) add("Linux");
  if (/chrome|chromium|firefox|internet explorer|microsoft edge|\bedge\b|safari|webkit|v8/i.test(text)) add("ブラウザ");

  if (/cisco|juniper|fortinet|fortios|fortigate|palo alto|pan-os|sonicwall|zyxel|d-link|tp-link|netgear|mikrotik|router|switch|firewall|vpn|ssl-vpn|pulse secure|ivanti connect secure|citrix adc|netscaler|f5 big-ip|big-ip|load balancer|gateway|network/i.test(text)) {
    add("ネットワークデバイス");
  }

  if (/iot|camera|ip camera|nas|qnap|synology|dvr|nvr|printer|embedded|firmware|router|smart/i.test(text)) add("IoT");

  if (/server|weblogic|apache|tomcat|nginx|iis|jenkins|confluence|jira|gitlab|bitbucket|wordpress|drupal|joomla|magento|cms|sql server|mysql|postgresql|oracle e-business|e-business|sap|sharepoint|exchange|vmware|vcenter|esxi|kubernetes|docker|container|web application|application server/i.test(text)) {
    add("サーバーソフトウェア");
  }

  if (/office|microsoft 365|word|excel|powerpoint|outlook|adobe|acrobat|reader|flash player|photoshop|illustrator|zoom|teams|skype|itunes|client|desktop|workstation|media player|winrar|7-zip|email client/i.test(text)) {
    add("クライアントソフトウェア");
  }

  if (labels.length === 0) add("その他");
  return labels;
}

function categorizeRequiredAction(action) {
  const original = String(action || "").trim();
  const normalized = original.replace(/\s+/g, " ").trim();
  const lower = normalized.toLowerCase();

  if (!normalized) {
    return {
      categories: ["未記載"],
      summary: "必要な対応は記載されていません。",
      original,
    };
  }

  const categories = [];
  const add = (label) => {
    if (!categories.includes(label)) categories.push(label);
  };

  const hasUpdates = /apply updates|apply patches|security updates?|security patches?|update to|upgrade to|install .*updates?|patched version|fix(ed)? version/i.test(normalized);
  const hasMitigations = /apply mitigations?|mitigations? .*vendor|workarounds?|temporary mitigations?|compensating controls?/i.test(normalized);
  const hasDiscontinue = /discontinue use|stop using|remove .*product|decommission|disable .*product|uninstall/i.test(normalized);
  const hasUnavailableCondition = /if .*unavailable|if .*not available|where .*unavailable|when .*unavailable/i.test(normalized);

  if (hasUpdates) add("更新適用");
  if (hasMitigations) add("緩和策適用");

  if (/forensics? triage|triage requirements?|forensic analysis|forensic evidence|incident response/i.test(normalized)) {
    add("フォレンジックトリアージ");
  }

  if (/internet exposure|internet-facing|externally exposed|publicly accessible|external exposure|exposed to the internet/i.test(normalized)) {
    add("インターネット露出評価");
  }

  if (/(end-of-life|end of life|eol|unsupported).*(disconnect|discontinue|remove|replace|isolate)|(?:disconnect|discontinue|remove|replace|isolate).*(end-of-life|end of life|eol|unsupported)/i.test(normalized)) {
    add("EOL製品の隔離・使用中止");
  }

  if (/(disconnect|remove|isolate).*(network|internet)|network.*(disconnect|remove|isolate)/i.test(normalized)) {
    add("ネットワークから切り離し");
  }

  if (hasDiscontinue) {
    add(hasUnavailableCondition ? "使用中止（代替策なし）" : "使用中止");
  }

  if (/specified version|specific version|upgrade to|update to/i.test(normalized)) {
    add("指定バージョンへ更新");
  }

  if (categories.length === 0) add("個別確認");

  return {
    categories,
    summary: summarizeRequiredActionText(normalized, categories),
    original,
  };
}

function summarizeRequiredActionText(normalized, categories) {
  if (!normalized) return "必要な対応は記載されていません。";

  const parts = [];
  const has = (label) => categories.includes(label);

  if (has("更新適用")) parts.push("更新プログラムの適用");
  if (has("緩和策適用")) parts.push("緩和策の適用");
  if (has("フォレンジックトリアージ")) parts.push("フォレンジックトリアージ要件の確認");
  if (has("インターネット露出評価")) parts.push("インターネット露出の評価");
  if (has("EOL製品の隔離・使用中止")) parts.push("EOL製品の隔離または使用中止");
  if (has("ネットワークから切り離し")) parts.push("ネットワークからの切り離し");
  if (has("使用中止（代替策なし）")) parts.push("更新・緩和策が利用できない場合の使用中止");
  if (has("使用中止")) parts.push("使用中止");
  if (has("指定バージョンへ更新") && !has("更新適用")) parts.push("指定バージョンへの更新");

  if (parts.length === 0 || has("個別確認")) {
    return "CISA原文を確認して個別に対応してください。";
  }

  return `${parts.join("、")}を実施してください。`;
}

function summarizeRequiredAction(action) {
  return categorizeRequiredAction(action).summary;
}

function populateFilterOptions() {
  fillSelect(els.vendorFilter, uniqueSorted(state.allRows.map((row) => row.vendorProject)));
  fillSelect(els.cweFilter, uniqueSorted(state.allRows.flatMap((row) => row.cwes || [])), formatCweLabel);
  fillSelect(els.vulnerabilityTypeFilter, uniqueSorted(state.allRows.map((row) => row.vulnerabilityTypeLabel)));
  fillSelect(els.impactTargetFilter, uniqueSorted(state.allRows.flatMap((row) => row.impactTargets || [])));
}

function fillSelect(select, values, labelFormatter = (value) => value) {
  if (!select) return;
  const current = select.value || "all";
  select.textContent = "";
  const all = document.createElement("option");
  all.value = "all";
  all.textContent = "すべて";
  select.appendChild(all);
  values.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = labelFormatter(value);
    select.appendChild(option);
  });
  select.value = values.includes(current) ? current : "all";
}

function uniqueSorted(values) {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, "ja", { numeric: true }));
}

function selectedValues(select) {
  if (!select) return [];
  if (select.selectedOptions) {
    return [...select.selectedOptions].map((option) => option.value).filter(Boolean);
  }
  return [...select.querySelectorAll("input:checked")].map((input) => input.value).filter(Boolean);
}

function clearFilters() {
  if (els.searchInput) els.searchInput.value = "";
  [
    els.ransomFilter,
    els.vendorFilter,
    els.cweFilter,
    els.vulnerabilityTypeFilter,
    els.impactTargetFilter,
  ].forEach((select) => {
    if (select) select.value = "all";
  });
  els.deadlineFilter?.querySelectorAll('input[type="checkbox"]').forEach((input) => {
    input.checked = false;
  });
  if (els.pageSizeSelect) {
    els.pageSizeSelect.value = "100";
    state.pageSize = 100;
  }
  state.page = 1;
  applyFilters();
  els.searchInput?.focus();
}

function applyFilters() {
  const q = (els.searchInput?.value || "").trim().toLowerCase();
  const ransom = els.ransomFilter?.value || "all";
  const vendor = els.vendorFilter?.value || "all";
  const cwe = els.cweFilter?.value || "all";
  const vulnerabilityType = els.vulnerabilityTypeFilter?.value || "all";
  const impactTarget = els.impactTargetFilter?.value || "all";
  const deadlineCategories = selectedValues(els.deadlineFilter);

  state.filteredRows = state.allRows.filter((row) => {
    const matchesQuery = !q || [
      row.cveID,
      row.vendorProject,
      row.product,
      row.vulnerabilityName,
      row.vulnerabilityTypeLabel,
      row.impactTargetText,
      row.shortDescription,
      row.requiredAction,
      row.requiredActionOriginal,
      row.requiredActionCategory,
      Array.isArray(row.requiredActionCategories) ? row.requiredActionCategories.join(" ") : "",
      row.notes,
      row.cwesText,
      row.cwesDisplayText,
      row.dateAddedDisplay,
      row.dueDateInfo?.label,
      row.dueDateInfo?.dateLabel,
      row.ransomwareLabel,
    ].some((value) => String(value).toLowerCase().includes(q));

    const matchesRansom = ransom === "all" || row.knownRansomwareCampaignUse === ransom;
    const matchesVendor = vendor === "all" || row.vendorProject === vendor;
    const matchesCwe = cwe === "all" || (row.cwes || []).includes(cwe);
    const matchesVulnerabilityType = vulnerabilityType === "all" || row.vulnerabilityTypeLabel === vulnerabilityType;
    const matchesImpactTarget = impactTarget === "all" || (row.impactTargets || []).includes(impactTarget);
    const matchesDeadline = deadlineCategories.length === 0 || deadlineCategories.includes(row.dueDateInfo?.category || "unknown");
    return matchesQuery && matchesRansom && matchesVendor && matchesCwe && matchesVulnerabilityType && matchesImpactTarget && matchesDeadline;
  });

  sortRows();
  state.page = 1;
  render();
}

function setSort(key) {
  if (state.sortKey === key) {
    state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
  } else {
    state.sortKey = key;
    state.sortDirection = "asc";
  }
  sortRows();
  render();
}

function sortRows() {
  const direction = state.sortDirection === "asc" ? 1 : -1;
  const key = state.sortKey;
  state.filteredRows.sort((a, b) => {
    const av = a[key] || "";
    const bv = b[key] || "";
    return String(av).localeCompare(String(bv), "ja", { numeric: true }) * direction;
  });
}

function render() {
  renderSummary();
  renderTable();
  renderPagination();
}

function renderSummary() {
  const meta = state.catalogMeta;
  if (!meta) return;
  els.summary.textContent = `${state.filteredRows.length.toLocaleString()} / ${state.allRows.length.toLocaleString()}件を表示 ・ カタログ版 ${meta.catalogVersion} ・ 公開日 ${formatJapaneseDate(meta.dateReleased)}`;
}

function renderTable() {
  els.tableBody.textContent = "";
  const rows = getPageRows();

  if (rows.length === 0) {
    els.tableBody.appendChild(els.emptyTemplate.content.cloneNode(true));
    return;
  }

  const fragment = document.createDocumentFragment();
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    appendCell(tr, createVulnerabilityNameCell(row));
    appendCell(tr, createVendorProductCell(row));
    appendCell(tr, createDateAndDeadlineCell(row));
    appendCell(tr, createRansomBadge(row.knownRansomwareCampaignUse));
    appendCell(tr, createRequiredActionCell(row));
    appendCell(tr, createNotesCell(row.notes));
    fragment.appendChild(tr);
  });
  els.tableBody.appendChild(fragment);
}

function appendCell(tr, content) {
  const td = document.createElement("td");
  if (content instanceof Node) {
    td.appendChild(content);
  } else {
    td.textContent = content || "-";
  }
  tr.appendChild(td);
}

function createCveLink(cveID) {
  if (!cveID) return document.createTextNode("-");
  const link = document.createElement("a");
  link.href = createVulnrichmentUrl(cveID);
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.referrerPolicy = "no-referrer";
  link.title = "Vulnrichment ProjectのRaw JSONを開く";
  link.textContent = cveID;
  return link;
}

function normalizeCweId(value) {
  const match = String(value || "").trim().toUpperCase().match(/^CWE-?(\d+)$/);
  return match ? `CWE-${match[1]}` : String(value || "").trim().toUpperCase();
}

function getCweName(value) {
  const id = normalizeCweId(value);
  return CWE_NAME_JA[id] || "";
}

function formatCweLabel(value) {
  const id = normalizeCweId(value);
  const name = getCweName(id);
  return name ? `${id}: ${name}` : id;
}

function createJvnCweUrl(value) {
  const id = normalizeCweId(value);
  const match = id.match(/^CWE-(\d+)$/);
  return match ? `https://jvndb.jvn.jp/ja/cwe/CWE-${match[1]}.html` : "";
}

function createCweCell(cwes) {
  const values = Array.isArray(cwes) ? cwes : normalizeCwes(cwes);
  if (values.length === 0) return document.createTextNode("-");

  const wrap = document.createElement("div");
  wrap.className = "cweList";
  values.forEach((value) => {
    const item = document.createElement("div");
    const url = createJvnCweUrl(value);
    if (url) {
      const link = document.createElement("a");
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.referrerPolicy = "no-referrer";
      link.title = "JVNのCWE説明ページを開く";
      link.textContent = formatCweLabel(value);
      item.appendChild(link);
    } else {
      item.textContent = formatCweLabel(value);
    }
    wrap.appendChild(item);
  });
  return wrap;
}

function createNotesCell(notes) {
  const text = String(notes || "").replace(/[;；]+/g, "\n").trim();
  if (!text) return document.createTextNode("-");

  const wrap = document.createElement("div");
  wrap.className = "notesCell";

  const parts = splitTextByUrls(text);
  const list = document.createElement("ul");
  list.className = "noteUrlList";
  let pendingText = "";

  parts.forEach((part) => {
    if (part.type === "text") {
      const normalized = part.value
        .split(/\n+/)
        .map((line) => line.replace(/\s+/g, " ").trim())
        .filter(Boolean)
        .join(" ");
      if (normalized) pendingText = [pendingText, normalized].filter(Boolean).join(" ");
      return;
    }

    const source = classifyNoteUrl(part.value);
    const item = document.createElement("li");
    item.className = `noteItem noteSource${source.key}`;

    const badge = document.createElement("span");
    badge.className = `noteSourceBadge noteSourceBadge${source.key}`;
    badge.textContent = source.label;
    badge.title = source.description;
    item.appendChild(badge);

    const body = document.createElement("span");
    body.className = "noteBody";

    if (pendingText) {
      const memo = document.createElement("span");
      memo.className = "noteUrlMemo";
      memo.textContent = pendingText;
      body.appendChild(memo);
      pendingText = "";
    }

    const link = document.createElement("a");
    link.href = part.value;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.referrerPolicy = "no-referrer";
    link.textContent = part.value;
    body.appendChild(link);
    item.appendChild(body);
    list.appendChild(item);
  });

  if (list.childNodes.length > 0) wrap.appendChild(list);

  if (pendingText) {
    const textLine = document.createElement("div");
    textLine.className = "noteText";
    textLine.textContent = pendingText;
    wrap.appendChild(textLine);
  }

  return wrap.childNodes.length ? wrap : document.createTextNode("-");
}

function classifyNoteUrl(url) {
  let host = "";
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    host = "";
  }

  if (host.endsWith("cisa.gov")) {
    return { key: "Cisa", label: "CISA", description: "CISA関連情報" };
  }
  if (host.endsWith("nist.gov")) {
    return { key: "Nist", label: "NIST", description: "NIST / NVD関連情報" };
  }
  return { key: "Other", label: "関連情報等", description: "ベンダやプロジェクト等の一次情報候補" };
}

function splitTextByUrls(text) {
  const urlPattern = /https?:\/\/[^\s<>"')]+/gi;
  const parts = [];
  let lastIndex = 0;
  for (const match of text.matchAll(urlPattern)) {
    if (match.index > lastIndex) {
      parts.push({ type: "text", value: text.slice(lastIndex, match.index) });
    }
    parts.push({ type: "url", value: match[0].replace(/[.,;:]+$/, "") });
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < text.length) {
    parts.push({ type: "text", value: text.slice(lastIndex) });
  }
  return parts;
}

function createDueDateInfo(dateAdded, dueDate) {
  const start = parseIsoDateOnly(dateAdded);
  const end = parseIsoDateOnly(dueDate);
  if (!end) {
    return { label: "-", dateLabel: "-", days: null, category: "unknown", urgencyClass: "deadlineUnknown", sortValue: "" };
  }

  const days = start ? Math.round((end - start) / 86400000) : null;
  const dateLabel = formatJapaneseDate(dueDate);
  const label = days === null ? `（${dateLabel}）` : `${days}日以内（${dateLabel}）`;
  const category = getDeadlineCategory(days);
  return {
    label,
    dateLabel,
    days,
    category,
    categoryLabel: getDeadlineCategoryLabel(category),
    urgencyClass: getDeadlineUrgencyClass(days),
    sortValue: dueDate,
  };
}

function parseIsoDateOnly(value) {
  const match = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return null;
  return Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
}

function getDeadlineCategory(days) {
  if (days === null || Number.isNaN(days)) return "unknown";
  if (days <= 3) return "immediate";
  if (days <= 14) return "critical";
  if (days <= 21) return "high";
  if (days <= 45) return "medium";
  return "low";
}

function getDeadlineCategoryLabel(category) {
  const labels = {
    immediate: "3日以内",
    critical: "4〜14日以内",
    high: "15〜21日以内",
    medium: "22〜45日以内",
    low: "46日以上",
    unknown: "不明",
  };
  return labels[category] || "不明";
}

function getDeadlineUrgencyClass(days) {
  if (days === null || Number.isNaN(days)) return "deadlineUnknown";
  if (days <= 3) return "deadlineImmediate";
  if (days <= 14) return "deadlineCritical";
  if (days <= 21) return "deadlineHigh";
  if (days <= 45) return "deadlineMedium";
  return "deadlineLow";
}

function createDateAndDeadlineCell(row) {
  const wrap = document.createElement("div");
  wrap.className = "dateDeadlineCell";

  const added = document.createElement("div");
  added.className = "dateLine dateAddedLine";

  const addedLabel = document.createElement("span");
  addedLabel.className = "dateMetaLabel";
  addedLabel.textContent = "追加日";
  added.appendChild(addedLabel);

  const addedValue = document.createElement("span");
  addedValue.className = "dateValue";
  addedValue.textContent = row.dateAddedDisplay || row.dateAdded || "-";
  added.appendChild(addedValue);
  wrap.appendChild(added);

  const due = document.createElement("div");
  due.className = "dateLine dueDateLine";

  const dueLabel = document.createElement("span");
  dueLabel.className = "dateMetaLabel";
  dueLabel.textContent = "期限";
  due.appendChild(dueLabel);

  due.appendChild(createDueDateCell(row));
  wrap.appendChild(due);

  return wrap;
}

function createDueDateCell(row) {
  const info = row.dueDateInfo || createDueDateInfo(row.dateAdded, row.dueDate);
  const span = document.createElement("span");
  span.className = `deadlineBadge ${info.urgencyClass}`;
  span.title = info.days === null
    ? "対応期限の日数を算出できませんでした。"
    : `KEV追加日から対応期限まで: ${info.days}日`;
  span.textContent = info.label || "-";
  return span;
}

function createVulnrichmentUrl(cveID) {
  const match = String(cveID).match(/^CVE-(\d{4})-(\d{4,})$/i);
  if (!match) {
    return `${VULNRICHMENT_RAW_URL}/`;
  }

  const year = match[1];
  const sequence = match[2];
  const bucket = `${sequence.slice(0, -3)}xxx`;
  return `${VULNRICHMENT_RAW_URL}/${year}/${bucket}/${encodeURIComponent(cveID.toUpperCase())}.json`;
}

function createRansomBadge(value) {
  const span = document.createElement("span");
  span.className = `badge ${value === "Known" ? "known" : ""}`;
  span.textContent = formatRansomwareUse(value);
  return span;
}

function formatRansomwareUse(value) {
  return value === "Known" ? "確認済" : "未確認";
}

function formatJapaneseDate(value) {
  const parsed = parseIsoDateOnly(value);
  if (!parsed) return value || "不明";
  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "long",
    day: "numeric",
  }).format(new Date(parsed));
}

function createRequiredActionCell(row) {
  const wrap = document.createElement("div");
  wrap.className = "actionCell";

  const tags = document.createElement("div");
  tags.className = "actionCategoryList";
  const categories = Array.isArray(row.requiredActionCategories) && row.requiredActionCategories.length > 0
    ? row.requiredActionCategories
    : [row.requiredActionCategory || "個別確認"];
  categories.forEach((label) => {
    const tag = document.createElement("span");
    tag.className = "actionCategory";
    tag.textContent = label;
    tags.appendChild(tag);
  });
  wrap.appendChild(tags);

  const text = document.createElement("div");
  text.className = "actionSummary";
  text.textContent = row.requiredAction || "-";
  wrap.appendChild(text);

  if (row.requiredActionOriginal && row.requiredActionOriginal !== row.requiredAction) {
    const original = document.createElement("details");
    original.className = "originalAction";
    const summary = document.createElement("summary");
    summary.textContent = "原文";
    const body = document.createElement("div");
    body.textContent = row.requiredActionOriginal;
    original.append(summary, body);
    wrap.appendChild(original);
  }

  return wrap;
}

function getPageRows() {
  if (state.pageSize === "all") return state.filteredRows;
  const start = (state.page - 1) * state.pageSize;
  return state.filteredRows.slice(start, start + state.pageSize);
}

function renderPagination() {
  const total = state.filteredRows.length;
  const totalPages = state.pageSize === "all" ? 1 : Math.max(1, Math.ceil(total / state.pageSize));
  state.page = Math.min(state.page, totalPages);
  els.prevButton.disabled = state.page <= 1 || state.pageSize === "all";
  els.nextButton.disabled = state.page >= totalPages || state.pageSize === "all";
  els.pageInfo.textContent = state.pageSize === "all"
    ? `${total.toLocaleString()}件すべて表示`
    : `${state.page} / ${totalPages}ページ`;
}

function exportCsv() {
  const header = [
    "CVE番号",
    "ベンダ/プロジェクト",
    "製品",
    "脆弱性名",
    "脆弱性種別",
    "影響対象ジャンル",
    "KEV追加日",
    "対応期限",
    "対応期限（日数）",
    "対応期限（日付）",
    "対応期限区分",
    "ランサムウェア利用",
    "必要な対応",
    "対応類型",
    "必要な対応（原文）",
    "CWE",
    "備考",
  ];

  const records = state.filteredRows.map((row) => [
    row.cveID,
    row.vendorProject,
    row.product,
    row.vulnerabilityName,
    row.vulnerabilityTypeLabel,
    Array.isArray(row.impactTargets) ? row.impactTargets.join(" / ") : "",
    row.dateAddedDisplay || row.dateAdded,
    row.dueDateInfo?.label || row.dueDate,
    row.dueDateInfo?.days ?? "",
    row.dueDateInfo?.dateLabel || formatJapaneseDate(row.dueDate),
    row.dueDateInfo?.categoryLabel || "不明",
    row.ransomwareLabel || formatRansomwareUse(row.knownRansomwareCampaignUse),
    row.requiredAction,
    Array.isArray(row.requiredActionCategories) ? row.requiredActionCategories.join(" / ") : row.requiredActionCategory,
    row.requiredActionOriginal,
    Array.isArray(row.cwes) ? row.cwes.map(formatCweLabel).join("\n") : formatCweLabel(row.cwes),
    row.notes,
  ]);

  const csv = [header, ...records].map((line) => line.map(csvEscape).join(",")).join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cisa-kev-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function csvEscape(value) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}

function setBusy(isBusy, message) {
  els.refreshButton.disabled = isBusy;
  if (message) setStatus(message);
}

function setStatus(message) {
  els.status.textContent = message || "";
  els.status.parentElement.hidden = !message;
}

function readCache() {
  try {
    const raw = globalThis.localStorage?.getItem(CACHE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (error) {
    console.warn("Failed to read KEV cache from localStorage", error);
    return null;
  }
}

function writeCache(catalog) {
  try {
    const value = { catalog, fetchedAt: Date.now() };
    globalThis.localStorage?.setItem(CACHE_KEY, JSON.stringify(value));
  } catch (error) {
    console.warn("Failed to write KEV cache to localStorage", error);
  }
}

function formatDateTime(timestamp) {
  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(timestamp));
}

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}
