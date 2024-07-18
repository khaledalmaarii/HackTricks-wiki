# Stehlen von sensiblen Informationslecks von einer Webseite

{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichen.

</details>
{% endhint %}

Wenn Sie irgendwann eine **Webseite finden, die Ihnen sensible Informationen basierend auf Ihrer Sitzung präsentiert**: Möglicherweise spiegelt sie Cookies wider, druckt Kreditkartendetails oder andere sensible Informationen, können Sie versuchen, sie zu stehlen.\
Hier präsentiere ich Ihnen die Hauptwege, um es zu versuchen:

* [**CORS-Bypass**](pentesting-web/cors-bypass.md): Wenn Sie CORS-Header umgehen können, können Sie die Informationen stehlen, indem Sie Ajax-Anfragen für eine bösartige Seite durchführen.
* [**XSS**](pentesting-web/xss-cross-site-scripting/): Wenn Sie eine XSS-Schwachstelle auf der Seite finden, können Sie sie möglicherweise missbrauchen, um die Informationen zu stehlen.
* [**Dangling Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): Wenn Sie keine XSS-Tags einfügen können, können Sie die Informationen möglicherweise mithilfe anderer regulärer HTML-Tags stehlen.
* [**Clickjaking**](pentesting-web/clickjacking.md): Wenn es keinen Schutz gegen diesen Angriff gibt, können Sie den Benutzer möglicherweise dazu bringen, Ihnen die sensiblen Daten zu senden (ein Beispiel [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
Lernen Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichen.

</details>
{% endhint %}
