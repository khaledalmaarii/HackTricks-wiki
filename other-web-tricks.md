# Andere Web-Tricks

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (14) (1).png" alt=""><figcaption></figcaption></figure>

**Sofort verfügbare Einrichtung für Schwachstellenbewertung & Penetrationstests**. Führe einen vollständigen Pentest von überall mit 20+ Tools & Funktionen durch, die von Recon bis Reporting reichen. Wir ersetzen keine Pentester - wir entwickeln maßgeschneiderte Tools, Erkennungs- & Ausnutzungs-Module, um ihnen etwas Zeit zurückzugeben, um tiefer zu graben, Shells zu öffnen und Spaß zu haben.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### Host-Header

Mehrmals vertraut das Backend dem **Host-Header**, um einige Aktionen auszuführen. Zum Beispiel könnte es seinen Wert als **Domain zum Senden eines Passwort-Reset** verwenden. Wenn du also eine E-Mail mit einem Link zum Zurücksetzen deines Passworts erhältst, ist die verwendete Domain die, die du im Host-Header angegeben hast. Dann kannst du die Passwortzurücksetzung anderer Benutzer anfordern und die Domain auf eine von dir kontrollierte ändern, um ihre Passwort-Reset-Codes zu stehlen. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Beachte, dass es möglich ist, dass du nicht einmal warten musst, bis der Benutzer auf den Link zum Zurücksetzen des Passworts klickt, um das Token zu erhalten, da möglicherweise sogar **Spam-Filter oder andere Zwischengeräte/Bots darauf klicken, um es zu analysieren**.
{% endhint %}

### Sitzungs-Boolean

Manchmal, wenn du eine Überprüfung korrekt abschließt, wird das Backend **einfach einen Boolean mit dem Wert "True" zu einem Sicherheitsattribut deiner Sitzung hinzufügen**. Dann wird ein anderer Endpunkt wissen, ob du diese Überprüfung erfolgreich bestanden hast.\
Wenn du jedoch **die Überprüfung bestehst** und deine Sitzung diesen "True"-Wert im Sicherheitsattribut erhält, kannst du versuchen, **auf andere Ressourcen zuzugreifen**, die **von demselben Attribut abhängen**, auf die du **keine Berechtigung** haben solltest. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Registrierungsfunktion

Versuche, dich als bereits existierender Benutzer zu registrieren. Versuche auch, äquivalente Zeichen (Punkte, viele Leerzeichen und Unicode) zu verwenden.

### Übernahme von E-Mails

Registriere eine E-Mail, ändere die E-Mail, bevor du sie bestätigst, und wenn die neue Bestätigungs-E-Mail an die zuerst registrierte E-Mail gesendet wird, kannst du jede E-Mail übernehmen. Oder wenn du die zweite E-Mail aktivieren kannst, die die erste bestätigt, kannst du auch jedes Konto übernehmen.

### Zugriff auf den internen Servicedesk von Unternehmen, die Atlassian verwenden

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE-Methode

Entwickler könnten vergessen, verschiedene Debugging-Optionen in der Produktionsumgebung zu deaktivieren. Zum Beispiel ist die HTTP `TRACE`-Methode für Diagnosezwecke gedacht. Wenn sie aktiviert ist, wird der Webserver auf Anfragen, die die `TRACE`-Methode verwenden, mit der genauen Anfrage antworten, die empfangen wurde. Dieses Verhalten ist oft harmlos, führt aber gelegentlich zu Informationslecks, wie z.B. den Namen interner Authentifizierungsheader, die von Reverse-Proxys an Anfragen angehängt werden können.![Bild für den Beitrag](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Bild für den Beitrag](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/image (14) (1).png" alt=""><figcaption></figcaption></figure>

**Sofort verfügbare Einrichtung für Schwachstellenbewertung & Penetrationstests**. Führe einen vollständigen Pentest von überall mit 20+ Tools & Funktionen durch, die von Recon bis Reporting reichen. Wir ersetzen keine Pentester - wir entwickeln maßgeschneiderte Tools, Erkennungs- & Ausnutzungs-Module, um ihnen etwas Zeit zurückzugeben, um tiefer zu graben, Shells zu öffnen und Spaß zu haben.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
