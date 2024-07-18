# ウェブからの機密情報漏洩の盗難

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

もしあなたが**セッションに基づいて機密情報を表示するウェブページ**を見つけた場合：クッキーを反映しているか、CCの詳細やその他の機密情報を印刷しているかもしれません。あなたはそれを盗むことを試みることができます。\
ここでは、達成するために試すことができる主な方法を紹介します：

* [**CORSバイパス**](../pentesting-web/cors-bypass.md)：CORSヘッダーをバイパスできれば、悪意のあるページに対してAjaxリクエストを行うことで情報を盗むことができます。
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): ページにXSSの脆弱性が見つかれば、それを悪用して情報を盗むことができるかもしれません。
* [**ダンギングマークアップ**](../pentesting-web/dangling-markup-html-scriptless-injection/): XSSタグを注入できない場合でも、他の通常のHTMLタグを使用して情報を盗むことができるかもしれません。
* [**クリックジャッキング**](../pentesting-web/clickjacking.md)：この攻撃に対する保護がない場合、ユーザーを騙して機密データを送信させることができるかもしれません（例は[こちら](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)）。

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
