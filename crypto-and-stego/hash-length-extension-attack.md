# ハッシュ長拡張攻撃

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を利用した検索エンジンで、企業やその顧客が**マルウェアによって侵害された**かどうかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目的は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトを確認し、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

***

## 攻撃の概要

サーバーが**データ**に**秘密**を追加してハッシュ化することを**署名**していると想像してください。もしあなたが以下を知っているなら：

* **秘密の長さ**（これは与えられた長さの範囲からもブルートフォース可能です）
* **平文データ**
* **アルゴリズム（この攻撃に対して脆弱である）**
* **パディングが知られている**
* 通常はデフォルトのものが使用されるため、他の3つの要件が満たされていれば、これもそうです
* パディングは秘密+データの長さによって異なるため、秘密の長さが必要です

その場合、**攻撃者**は**データを追加**し、**以前のデータ + 追加データ**の有効な**署名**を**生成**することが可能です。

### どうやって？

基本的に、脆弱なアルゴリズムは、最初に**データのブロックをハッシュ化**し、その後、**以前に作成された**ハッシュ（状態）から**次のデータブロックを追加**して**ハッシュ化**します。

例えば、秘密が「secret」でデータが「data」の場合、「secretdata」のMD5は6036708eba0d11f6ef52ad44e8b74d5bです。\
攻撃者が「append」という文字列を追加したい場合、彼は：

* 64の「A」のMD5を生成する
* 以前に初期化されたハッシュの状態を6036708eba0d11f6ef52ad44e8b74d5bに変更する
* 文字列「append」を追加する
* ハッシュを完了し、結果のハッシュは「secret」 + 「data」 + 「padding」 + 「append」の**有効なもの**になります

### **ツール**

{% embed url="https://github.com/iagox86/hash_extender" %}

### 参考文献

この攻撃については、[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)で詳しく説明されています。

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を利用した検索エンジンで、企業やその顧客が**マルウェアによって侵害された**かどうかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目的は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトを確認し、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
