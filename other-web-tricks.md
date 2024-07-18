# Andere Web-Tricks

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>
{% endhint %}

### Host-Header

Oft vertraut das Backend dem **Host-Header**, um bestimmte Aktionen auszuführen. Zum Beispiel könnte es dessen Wert als **Domain zum Senden eines Passwort-Reset** verwenden. Wenn Sie also eine E-Mail mit einem Link zum Zurücksetzen Ihres Passworts erhalten, wird die verwendete Domain diejenige sein, die Sie im Host-Header angegeben haben. Dann können Sie den Passwort-Reset anderer Benutzer anfordern und die Domain auf eine von Ihnen kontrollierte ändern, um ihre Passwort-Reset-Codes zu stehlen. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Beachten Sie, dass es möglich ist, dass Sie möglicherweise nicht einmal darauf warten müssen, dass der Benutzer auf den Link zum Zurücksetzen des Passworts klickt, um das Token zu erhalten, da möglicherweise sogar **Spamfilter oder andere Zwischengeräte/Bots darauf klicken, um es zu analysieren**.
{% endhint %}

### Sitzungs-Booleans

Manchmal fügt das Backend einfach einen Booleschen Wert "True" zu einem Sicherheitsattribut Ihrer Sitzung hinzu, wenn Sie einige Überprüfungen korrekt abschließen. Dann weiß ein anderer Endpunkt, ob Sie diese Überprüfung erfolgreich bestanden haben.\
Wenn Sie jedoch die Überprüfung bestehen und Ihre Sitzung diesen "True"-Wert im Sicherheitsattribut erhält, können Sie versuchen, auf andere Ressourcen zuzugreifen, die **vom selben Attribut abhängen**, auf die Sie jedoch **keine Berechtigungen haben sollten**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Registrierungsfunktionalität

Versuchen Sie, sich als bereits vorhandener Benutzer zu registrieren. Versuchen Sie auch, äquivalente Zeichen (Punkte, viele Leerzeichen und Unicode) zu verwenden.

### Übernahme von E-Mails

Registrieren Sie eine E-Mail, ändern Sie sie, bevor Sie sie bestätigen. Wenn die neue Bestätigungs-E-Mail an die zuerst registrierte E-Mail gesendet wird, können Sie jede E-Mail übernehmen. Oder wenn Sie die zweite E-Mail aktivieren können, die die erste bestätigt, können Sie auch jedes Konto übernehmen.

### Zugriff auf den internen Servicedesk von Unternehmen, die Atlassian verwenden

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE-Methode

Entwickler vergessen möglicherweise, verschiedene Debugging-Optionen in der Produktionsumgebung zu deaktivieren. Zum Beispiel ist die HTTP `TRACE`-Methode für Diagnosezwecke vorgesehen. Wenn sie aktiviert ist, antwortet der Webserver auf Anfragen, die die `TRACE`-Methode verwenden, indem er in der Antwort die genaue Anfrage wiedergibt, die empfangen wurde. Dieses Verhalten ist oft harmlos, führt aber gelegentlich zu Informationslecks, wie dem Namen interner Authentifizierungsheader, die Anfragen von Reverse-Proxies angehängt werden können.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>
{% endhint %}
