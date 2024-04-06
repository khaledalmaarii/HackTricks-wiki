# Stealing Sensitive Information Disclosure from a Web

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

Wenn Sie irgendwann auf eine **Webseite stoßen, die Ihnen sensible Informationen basierend auf Ihrer Sitzung präsentiert**: Möglicherweise werden Cookies reflektiert oder Kreditkartendaten oder andere sensible Informationen gedruckt. In diesem Fall können Sie versuchen, sie zu stehlen.\
Hier sind die Hauptmethoden, die Sie ausprobieren können:

* [**CORS-Bypass**](../pentesting-web/cors-bypass.md): Wenn Sie die CORS-Header umgehen können, können Sie die Informationen stehlen, indem Sie eine Ajax-Anfrage für eine bösartige Seite durchführen.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Wenn Sie eine XSS-Schwachstelle auf der Seite finden, können Sie sie möglicherweise missbrauchen, um die Informationen zu stehlen.
* [**Dangling Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Wenn Sie keine XSS-Tags einfügen können, können Sie möglicherweise trotzdem die Informationen stehlen, indem Sie andere reguläre HTML-Tags verwenden.
* [**Clickjacking**](../pentesting-web/clickjacking.md): Wenn es keinen Schutz gegen diesen Angriff gibt, können Sie möglicherweise den Benutzer dazu bringen, Ihnen die sensiblen Daten zu senden (ein Beispiel [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
