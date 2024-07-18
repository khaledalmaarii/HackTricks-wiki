# Stealing Sensitive Information Disclosure from a Web

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

Wenn du irgendwann eine **Webseite findest, die dir basierend auf deiner Sitzung sensible Informationen präsentiert**: Vielleicht spiegelt sie Cookies wider, oder druckt Kreditkarteninformationen oder andere sensible Daten aus, dann könntest du versuchen, sie zu stehlen.\
Hier präsentiere ich dir die Hauptwege, wie du dies erreichen kannst:

* [**CORS-Bypass**](../pentesting-web/cors-bypass.md): Wenn du CORS-Header umgehen kannst, wirst du in der Lage sein, die Informationen durch eine Ajax-Anfrage an eine bösartige Seite zu stehlen.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Wenn du eine XSS-Sicherheitsanfälligkeit auf der Seite findest, könntest du sie ausnutzen, um die Informationen zu stehlen.
* [**Dangling Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Wenn du keine XSS-Tags injizieren kannst, könntest du dennoch in der Lage sein, die Informationen mit anderen regulären HTML-Tags zu stehlen.
* [**Clickjacking**](../pentesting-web/clickjacking.md): Wenn es keinen Schutz gegen diesen Angriff gibt, könntest du den Benutzer dazu bringen, dir die sensiblen Daten zu senden (ein Beispiel [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
