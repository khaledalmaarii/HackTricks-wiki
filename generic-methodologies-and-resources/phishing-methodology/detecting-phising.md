# フィッシングの検出

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}

## はじめに

フィッシングの試みを検出するには、**現在使用されているフィッシング技術を理解することが重要です**。この投稿の親ページにはこの情報があるので、今日使用されている技術について知らない場合は、親ページに行って少なくともそのセクションを読むことをお勧めします。

この投稿は、**攻撃者が何らかの形で被害者のドメイン名を模倣または使用しようとする**という考えに基づいています。あなたのドメインが `example.com` と呼ばれ、何らかの理由で `youwonthelottery.com` のような全く異なるドメイン名でフィッシングされる場合、これらの技術ではそれを明らかにすることはできません。

## ドメイン名のバリエーション

メール内で**類似のドメイン**名を使用するフィッシングの試みを**明らかにするのは比較的簡単**です。\
攻撃者が使用する可能性のある**最も可能性の高いフィッシング名のリストを生成し**、それが**登録されているかどうかを確認する**か、単にそれを使用している**IP**があるかどうかを確認するだけで十分です。

### 疑わしいドメインの発見

この目的のために、以下のツールのいずれかを使用できます。これらのツールは、ドメインにIPが割り当てられているかどうかを確認するためにDNSリクエストを自動的に実行します：

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### ビットフリッピング

**この技術の簡単な説明は親ページにあります。または、** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) **で元の研究を読むことができます。**

例えば、ドメイン microsoft.com の1ビットの変更は、_windnws.com_ に変換できます。\
**攻撃者は、被害者に関連するビットフリッピングドメインをできるだけ多く登録し、正当なユーザーを自分のインフラにリダイレクトすることができます**。

**すべての可能なビットフリッピングドメイン名も監視する必要があります。**

### 基本的なチェック

潜在的な疑わしいドメイン名のリストができたら、それらを**チェック**する必要があります（主にHTTPおよびHTTPSポート）**被害者のドメインの誰かに似たログインフォームを使用しているかどうかを確認するために**。\
ポート3333が開いていて `gophish` のインスタンスが実行されているかどうかを確認することもできます。\
**発見された疑わしいドメインの各ドメインがどれくらい古いかを知ることも興味深い**です。若いほどリスクが高くなります。\
疑わしいウェブページのHTTPおよび/またはHTTPSの**スクリーンショット**を取得して、それが疑わしいかどうかを確認し、その場合は**アクセスして詳細を確認**することができます。

### 高度なチェック

さらに一歩進みたい場合は、**疑わしいドメインを監視し、時々（毎日？数秒/数分しかかかりません）さらに検索することをお勧めします**。関連するIPのオープン**ポート**も**チェック**し、**`gophish`や類似のツールのインスタンスを検索する**（はい、攻撃者も間違いを犯します）し、**疑わしいドメインとサブドメインのHTTPおよびHTTPSウェブページを監視して、被害者のウェブページからログインフォームをコピーしているかどうかを確認します**。\
これを**自動化するために**、被害者のドメインのログインフォームのリストを持ち、疑わしいウェブページをスパイダーし、疑わしいドメイン内で見つかった各ログインフォームを被害者のドメインの各ログインフォームと比較するために `ssdeep` のようなものを使用することをお勧めします。\
疑わしいドメインのログインフォームを特定した場合、**無効な資格情報を送信し**、**被害者のドメインにリダイレクトされるかどうかを確認**することができます。

## キーワードを使用したドメイン名

親ページでは、**被害者のドメイン名をより大きなドメイン内に入れる**というドメイン名のバリエーション技術についても言及しています（例：paypal-financial.com for paypal.com）。

### 証明書の透明性

以前の「ブルートフォース」アプローチを取ることはできませんが、実際には**そのようなフィッシングの試みを明らかにすることが可能です**。CAによって証明書が発行されるたびに、詳細が公開されます。これは、証明書の透明性を読み取ることによって、またはそれを監視することによって、**名前の中にキーワードを使用しているドメインを見つけることが可能であることを意味します**。例えば、攻撃者が [https://paypal-financial.com](https://paypal-financial.com) の証明書を生成した場合、証明書を見ることで「paypal」というキーワードを見つけ、疑わしいメールが使用されていることを知ることができます。

投稿 [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) は、特定のキーワードに影響を与える証明書を検索し、日付（「新しい」証明書のみ）およびCA発行者「Let's Encrypt」でフィルタリングするためにCensysを使用できることを示唆しています：

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

ただし、無料のウェブ [**crt.sh**](https://crt.sh) を使用して「同じこと」を行うこともできます。**キーワードを検索し**、**日付とCAで結果をフィルタリング**することができます。

![](<../../.gitbook/assets/image (519).png>)

この最後のオプションを使用すると、Matching Identitiesフィールドを使用して、実際のドメインのいずれかのアイデンティティが疑わしいドメインのいずれかと一致するかどうかを確認できます（疑わしいドメインは偽陽性である可能性があることに注意してください）。

**もう一つの代替手段**は、[**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)という素晴らしいプロジェクトです。CertStreamは、新しく生成された証明書のリアルタイムストリームを提供し、指定されたキーワードを（ほぼ）リアルタイムで検出するために使用できます。実際、[**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher)というプロジェクトがそれを実行しています。

### **新しいドメイン**

**最後の代替手段**は、いくつかのTLDの**新しく登録されたドメインのリストを収集し**、これらのドメイン内のキーワードを**チェックすることです**。ただし、長いドメインは通常1つ以上のサブドメインを使用するため、キーワードはFLD内に表示されず、フィッシングサブドメインを見つけることはできません。

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}
