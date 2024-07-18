# ウェブからの機密情報漏洩

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングテクニックを共有してください。

</details>
{% endhint %}

もし、**セッションに基づいて機密情報を表示するウェブページ**を見つけた場合：おそらくクッキーを反映しているか、またはCC詳細やその他の機密情報を印刷しているかもしれませんが、それを盗むことができます。\
ここでは、それを達成するために試みる主な方法を紹介します：

* [**CORSバイパス**](pentesting-web/cors-bypass.md): CORSヘッダーをバイパスできれば、悪意のあるページにAjaxリクエストを実行して情報を盗むことができます。
* [**XSS**](pentesting-web/xss-cross-site-scripting/): ページでXSS脆弱性を見つけた場合、それを悪用して情報を盗むことができるかもしれません。
* [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): XSSタグを挿入できない場合でも、他の通常のHTMLタグを使用して情報を盗むことができるかもしれません。
* [**Clickjaking**](pentesting-web/clickjacking.md): この攻撃に対する保護がない場合、ユーザーをだまして機密データを送信させることができるかもしれません（例は[こちら](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)）。

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングテクニックを共有してください。

</details>
{% endhint %}
