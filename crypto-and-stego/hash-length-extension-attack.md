# Hash Length Extension Attack

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


## Zusammenfassung des Angriffs

Stell dir einen Server vor, der **Daten** **signiert**, indem er ein **Geheimnis** an einige bekannte Klartextdaten **anhängt** und dann diese Daten hasht. Wenn du weißt:

* **Die Länge des Geheimnisses** (dies kann auch aus einem gegebenen Längenbereich bruteforced werden)
* **Die Klartextdaten**
* **Der Algorithmus (und er ist anfällig für diesen Angriff)**
* **Das Padding ist bekannt**
* Normalerweise wird ein Standard verwendet, also wenn die anderen 3 Anforderungen erfüllt sind, ist dies auch der Fall
* Das Padding variiert je nach Länge des Geheimnisses + Daten, deshalb ist die Länge des Geheimnisses erforderlich

Dann ist es für einen **Angreifer** möglich, **Daten** **anzuhängen** und eine gültige **Signatur** für die **vorherigen Daten + angehängte Daten** zu **generieren**.

### Wie?

Grundsätzlich erzeugen die anfälligen Algorithmen die Hashes, indem sie zuerst einen Block von Daten **hashten** und dann, **aus** dem **zuvor** erstellten **Hash** (Zustand), den **nächsten Block von Daten** **hinzufügen** und **hashen**.

Stell dir vor, das Geheimnis ist "secret" und die Daten sind "data", der MD5 von "secretdata" ist 6036708eba0d11f6ef52ad44e8b74d5b.\
Wenn ein Angreifer die Zeichenfolge "append" anhängen möchte, kann er:

* Einen MD5 von 64 "A"s generieren
* Den Zustand des zuvor initialisierten Hashes auf 6036708eba0d11f6ef52ad44e8b74d5b ändern
* Die Zeichenfolge "append" anhängen
* Den Hash abschließen und der resultierende Hash wird ein **gültiger für "secret" + "data" + "padding" + "append"** sein

### **Werkzeug**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Referenzen

Du kannst diesen Angriff gut erklärt finden unter [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)



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
