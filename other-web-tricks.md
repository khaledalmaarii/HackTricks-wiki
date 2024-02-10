# Weitere Web-Tricks

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

### Host-Header

Oftmals vertraut das Backend dem **Host-Header**, um bestimmte Aktionen auszuführen. Zum Beispiel kann es dessen Wert verwenden, um eine **Passwortzurücksetzung an die angegebene Domain** zu senden. Wenn Sie also eine E-Mail mit einem Link zur Passwortzurücksetzung erhalten, wird die Domain verwendet, die Sie im Host-Header angegeben haben. Sie können dann die Passwortzurücksetzung für andere Benutzer anfordern und die Domain auf eine von Ihnen kontrollierte Domain ändern, um ihre Passwortzurücksetzungscodes zu stehlen. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Beachten Sie, dass es möglich ist, dass Sie nicht einmal darauf warten müssen, dass der Benutzer auf den Link zur Passwortzurücksetzung klickt, um den Token zu erhalten, da möglicherweise sogar **Spam-Filter oder andere Zwischeninstanzen/Bots darauf klicken, um ihn zu analysieren**.
{% endhint %}

### Sitzungs-Booleans

Manchmal fügt das Backend nach erfolgreicher Überprüfung einfach ein Boolesches mit dem Wert "True" zu einem Sicherheitsattribut Ihrer Sitzung hinzu. Anschließend kann ein anderer Endpunkt anhand dieses Attributs feststellen, ob Sie die Überprüfung erfolgreich bestanden haben.\
Wenn Sie jedoch die Überprüfung bestehen und Ihre Sitzung den Wert "True" im Sicherheitsattribut erhält, können Sie versuchen, auf andere Ressourcen zuzugreifen, die von demselben Attribut abhängen, auf die Sie jedoch keine Berechtigungen haben sollten. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Registrierungsfunktionalität

Versuchen Sie, sich als bereits vorhandener Benutzer zu registrieren. Versuchen Sie auch, äquivalente Zeichen (Punkte, viele Leerzeichen und Unicode) zu verwenden.

### Übernahme von E-Mails

Registrieren Sie eine E-Mail-Adresse, ändern Sie sie, bevor Sie sie bestätigen, und wenn die neue Bestätigungs-E-Mail an die zuerst registrierte E-Mail-Adresse gesendet wird, können Sie jede E-Mail-Adresse übernehmen. Oder wenn Sie die zweite E-Mail aktivieren können, um die erste zu bestätigen, können Sie auch jedes Konto übernehmen.

### Zugriff auf den internen Service Desk von Unternehmen, die Atlassian verwenden

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE-Methode

Entwickler vergessen möglicherweise, verschiedene Debugging-Optionen in der Produktionsumgebung zu deaktivieren. Zum Beispiel ist die HTTP-Methode `TRACE` für Diagnosezwecke vorgesehen. Wenn sie aktiviert ist, antwortet der Webserver auf Anfragen, die die `TRACE`-Methode verwenden, indem er in der Antwort die genaue Anfrage wiedergibt, die empfangen wurde. Dieses Verhalten ist oft harmlos, führt aber gelegentlich zu Informationslecks, wie dem Namen interner Authentifizierungsheader, die Anfragen von Reverse Proxies angehängt werden können.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
