# macOS MDM

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。

</details>
{% endhint %}

**macOS MDMについて学ぶ:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## 基本

### **MDM (Mobile Device Management) 概要**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) は、スマートフォン、ノートパソコン、タブレットなどのさまざまなエンドユーザーデバイスを管理するために利用されます。特にAppleのプラットフォーム（iOS、macOS、tvOS）では、特殊な機能、API、およびプラクティスが関与します。MDMの運用は、商用またはオープンソースの互換性のあるMDMサーバーに依存し、[MDMプロトコル](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)をサポートする必要があります。主なポイントは次のとおりです:

* デバイスに対する集中制御。
* MDMプロトコルに準拠するMDMサーバーへの依存。
* MDMサーバーがデバイスにさまざまなコマンドを送信できる能力、たとえばリモートデータ消去や構成のインストール。

### **DEP (Device Enrollment Program) の基本**

Appleが提供する[Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) は、iOS、macOS、tvOSデバイスのゼロタッチ構成を容易にすることで、Mobile Device Management (MDM) の統合を効率化します。DEPは登録プロセスを自動化し、デバイスを最小限のユーザーまたは管理者の介入で即座に操作可能にします。主な側面は次のとおりです:

* デバイスが初回起動時に事前定義されたMDMサーバーに自動的に登録できるようにします。
* 新しいデバイスに特に有益ですが、再構成中のデバイスにも適用できます。
* 簡単なセットアップを容易にし、デバイスを組織での使用に迅速に準備します。

### **セキュリティに関する考慮事項**

DEPによる簡単な登録の利点はありますが、適切な保護措置がMDM登録に適切に施されていない場合、攻撃者はこの簡略化されたプロセスを利用して、企業のMDMサーバーに自分のデバイスを登録し、法人デバイスとして偽装する可能性があります。

{% hint style="danger" %}
**セキュリティアラート**: 簡略化されたDEP登録は、適切な保護措置が施されていない場合、組織のMDMサーバーに認可されていないデバイスの登録を許可する可能性があります。
{% endhint %}

### **SCEP (Simple Certificate Enrolment Protocol) とは**

* TLSやHTTPSが普及する前に作成された比較的古いプロトコル。
* クライアントに証明書署名リクエスト（CSR）を送信し、証明書を取得するための標準化された方法を提供します。クライアントはサーバーに署名された証明書を要求します。

### **構成プロファイルとは（モバイル構成ファイルとも呼ばれる）**

* Appleの公式の方法で**システム構成を設定/強制する**もの。
* 複数のペイロードを含むファイル形式。
* プロパティリスト（XMLタイプ）に基づいています。
* 「起源を検証し、整合性を確保し、内容を保護するために署名と暗号化できます。」Basics — Page 70, iOS Security Guide, January 2018.

## プロトコル

### MDM

* APNs（**Appleサーバー**）+ RESTful API（**MDMベンダーサーバー**）の組み合わせ
* **デバイス**と**デバイス管理製品**に関連するサーバー間での**通信**
* MDMからデバイスへの**コマンド**は**plistエンコードされた辞書**で配信されます
* すべて**HTTPS**経由。MDMサーバーは（通常）ピン留めされています。
* AppleはMDMベンダーにAPNs証明書を認証するために提供します

### DEP

* **3つのAPI**: リセラー用1つ、MDMベンダー用1つ、デバイス識別用1つ（未公開）:
* いわゆる[DEP "クラウドサービス" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。これはMDMサーバーがDEPプロファイルを特定のデバイスに関連付けるために使用されます。
* [Apple認定リセラーが使用するDEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)。デバイスの登録、登録状態の確認、トランザクション状態の確認に使用されます。
* 未公開のプライベートDEP API。これはAppleデバイスがDEPプロファイルをリクエストするために使用されます。macOSでは、`cloudconfigurationd`バイナリがこのAPIを介して通信します。
* より現代的で**JSON**ベース（plistとは異なる）
* AppleはMDMベンダーにOAuthトークンを提供します

**DEP "クラウドサービス" API**

* RESTful
* AppleからMDMサーバーにデバイスレコードを同期
* MDMサーバーからAppleにDEPプロファイルを同期（後でデバイスに配信されます）
* DEP「プロファイル」には次のものが含まれます:
* MDMベンダーサーバーのURL
* サーバーURLの追加信頼された証明書（オプションのピン留め）
* その他の設定（例: 設定アシスタントでスキップする画面）

## シリアル番号

2010年以降に製造されたAppleデバイスは、一般的に**12文字の英数字**のシリアル番号を持ち、**最初の3桁は製造場所**を表し、次の**2桁は製造年**と**週**を示し、次の**3桁は一意の** **識別子**を提供し、**最後の4桁は** **モデル番号**を表します。

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 登録と管理の手順

1. デバイスレコードの作成（リセラー、Apple）: 新しいデバイスのレコードが作成されます
2. デバイスレコードの割り当て（顧客）: デバイスがMDMサーバーに割り当てられます
3. デバイスレコードの同期（MDMベンダー）: MDMがデバイスレコードを同期し、DEPプロファイルをAppleにプッシュします
4. DEPチェックイン（デバイス）: デバイスがDEPプロファイルを取得します
5. プロファイルの取得（デバイス）
6. プロファイルのインストール（デバイス） a. MDM、SCEP、およびルートCAペイロードを含む
7. MDMコマンドの発行（デバイス）

![](<../../../.gitbook/assets/image (694).png>)

ファイル`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` は、登録プロセスの**高レベルな「ステップ」**と見なすことができる関数をエクスポートします。
### ステップ4: DEPチェックイン - アクティベーションレコードの取得

このプロセスのこの部分は、**ユーザーがMacを初めて起動**したとき（または完全に消去した後）

![](<../../../.gitbook/assets/image (1044).png>)

または`sudo profiles show -type enrollment`を実行したときに発生します

* **デバイスがDEP対応かどうかを判断**
* アクティベーションレコードはDEPの「プロファイル」の内部名です
* デバイスがインターネットに接続されるとすぐに開始
* **`CPFetchActivationRecord`** によって駆動
* **`cloudconfigurationd`** によって実装され、XPCを介して。デバイスが最初に起動されたときの **"セットアップアシスタント**" または **`profiles`** コマンドは、このデーモンにアクティベーションレコードを取得するために連絡します。
* LaunchDaemon（常にrootとして実行）

**`MCTeslaConfigurationFetcher`** によって実行されるアクティベーションレコードの取得には、**Absinthe** という暗号化が使用されます

1. **証明書を取得**
1. [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer) からGET
2. 証明書から状態を初期化（**`NACInit`**）
1. 様々なデバイス固有のデータを使用（例：**`IOKit`** 経由のシリアル番号）
3. **セッションキーを取得**
1. [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session) にPOST
4. セッションを確立（**`NACKeyEstablishment`**）
5. リクエストを作成
1. データ `{ "action": "RequestProfileConfiguration", "sn": "" }` を送信して [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) にPOST
2. JSONペイロードはAbsintheを使用して暗号化されます（**`NACSign`**）
3. すべてのリクエストはHTTPs経由で行われ、組み込みのルート証明書が使用されます

![](<../../../.gitbook/assets/image (566) (1).png>)

応答は、以下のような重要なデータを含むJSON辞書です：

* **url**: アクティベーションプロファイルのためのMDMベンダーホストのURL
* **anchor-certs**: 信頼されるアンカーとして使用されるDER証明書の配列

### **ステップ5: プロファイルの取得**

![](<../../../.gitbook/assets/image (444).png>)

* DEPプロファイルで提供された**URL**にリクエストを送信します。
* **アンカー証明書**が提供された場合、**信頼性を評価**するために使用されます。
* リマインダー：DEPプロファイルの **anchor\_certs** プロパティ
* デバイス識別情報を含む、単純な.plist形式のリクエスト
* 例：**UDID、OSバージョン**。
* CMSで署名され、DERでエンコードされています
* **デバイス識別証明書（APNSから）** を使用して署名されています
* **証明書チェーン** には期限切れの **Apple iPhone Device CA** が含まれています

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (
