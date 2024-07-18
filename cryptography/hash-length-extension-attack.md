{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}


# Zusammenfassung des Angriffs

Stellen Sie sich einen Server vor, der einige **Daten** durch **Anhängen** eines **Geheimnisses** an einige bekannte Klartextdaten signiert und dann diese Daten hasht. Wenn Sie Folgendes wissen:

* **Die Länge des Geheimnisses** (dies kann auch aus einem gegebenen Längenbereich bruteforce sein)
* **Die Klartextdaten**
* **Der Algorithmus (und er ist anfällig für diesen Angriff)**
* **Das Padding ist bekannt**
* Normalerweise wird ein Standard-Padding verwendet, daher ist dies auch der Fall, wenn die anderen 3 Anforderungen erfüllt sind
* Das Padding variiert je nach Länge des Geheimnisses+Daten, daher ist die Länge des Geheimnisses erforderlich

Dann ist es für einen **Angreifer** möglich, **Daten anzuhängen** und eine gültige **Signatur** für die **vorherigen Daten + angehängte Daten** zu **generieren**.

## Wie?

Grundsätzlich generieren die anfälligen Algorithmen die Hashes, indem sie zunächst einen Block von Daten hashen und dann aus dem zuvor erstellten Hash (Zustand) den nächsten Datenblock hinzufügen und ihn hashen.

Stellen Sie sich vor, das Geheimnis lautet "Geheimnis" und die Daten lauten "Daten", der MD5 von "GeheimnisDaten" lautet 6036708eba0d11f6ef52ad44e8b74d5b.\
Wenn ein Angreifer den String "anhängen" anhängen möchte, kann er:

* Einen MD5 von 64 "A"s generieren
* Ändern Sie den Zustand des zuvor initialisierten Hashs in 6036708eba0d11f6ef52ad44e8b74d5b
* Hängen Sie den String "anhängen" an
* Beenden Sie den Hash und der resultierende Hash wird ein **gültiger Hash für "Geheimnis" + "Daten" + "Padding" + "anhängen"** sein

## **Werkzeug**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referenzen

Sie können diesen Angriff gut erklärt unter [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) finden


{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}
