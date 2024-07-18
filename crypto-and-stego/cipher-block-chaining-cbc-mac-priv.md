{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
{% endhint %}


# CBC

Wenn das **Cookie** nur der **Benutzername** ist (oder der erste Teil des Cookies der Benutzername ist) und Sie den Benutzernamen "**admin**" vortäuschen möchten. Dann können Sie den Benutzernamen **"bdmin"** erstellen und das **erste Byte** des Cookies **bruteforcen**.

# CBC-MAC

**Cipher Block Chaining Message Authentication Code** (**CBC-MAC**) ist eine in der Kryptographie verwendete Methode. Es funktioniert, indem eine Nachricht blockweise verschlüsselt wird, wobei die Verschlüsselung jedes Blocks mit dem vorherigen verknüpft ist. Dieser Prozess erzeugt eine **Kette von Blöcken**, die sicherstellt, dass bereits eine einzige Bitänderung in der Originalnachricht zu einer unvorhersehbaren Änderung im letzten Block der verschlüsselten Daten führt. Um eine solche Änderung vorzunehmen oder rückgängig zu machen, wird der Verschlüsselungsschlüssel benötigt, um die Sicherheit zu gewährleisten.

Um den CBC-MAC der Nachricht m zu berechnen, verschlüsselt man m im CBC-Modus mit einem Initialisierungsvektor von Null und behält den letzten Block bei. Die folgende Abbildung skizziert die Berechnung des CBC-MAC einer Nachricht, die aus Blöcken besteht![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) unter Verwendung eines geheimen Schlüssels k und einer Blockchiffre E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Schwachstelle

Bei CBC-MAC wird normalerweise der **IV-Wert 0** verwendet.\
Dies ist ein Problem, da 2 bekannte Nachrichten (`m1` und `m2`) unabhängig voneinander 2 Signaturen (`s1` und `s2`) generieren werden. Also:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Dann wird eine Nachricht, die aus m1 und m2 konkateniert ist (m3), 2 Signaturen (s31 und s32) generieren:

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**Was möglich ist, ohne den Schlüssel der Verschlüsselung zu kennen.**

Stellen Sie sich vor, Sie verschlüsseln den Namen **Administrator** in **8-Byte-Blöcken**:

* `Administ`
* `rator\00\00\00`

Sie können einen Benutzernamen namens **Administ** (m1) erstellen und die Signatur (s1) abrufen.\
Dann können Sie einen Benutzernamen erstellen, der das Ergebnis von `rator\00\00\00 XOR s1` ist. Dies wird `E(m2 XOR s1 XOR 0)` generieren, was s32 ist.\
Nun können Sie s32 als die Signatur des vollständigen Namens **Administrator** verwenden.

### Zusammenfassung

1. Holen Sie sich die Signatur des Benutzernamens **Administ** (m1), die s1 ist
2. Holen Sie sich die Signatur des Benutzernamens **rator\x00\x00\x00 XOR s1 XOR 0**, die s32 ist**.**
3. Setzen Sie das Cookie auf s32 und es wird ein gültiges Cookie für den Benutzer **Administrator** sein.

# Angriff zur Steuerung des IV

Wenn Sie den verwendeten IV-Wert steuern können, könnte der Angriff sehr einfach sein.\
Wenn das Cookie nur der verschlüsselte Benutzername ist, um den Benutzer "**Administrator**" zu vortäuschen, können Sie den Benutzer "**Administrator**" erstellen und sein Cookie erhalten.\
Nun, wenn Sie den IV-Wert steuern können, können Sie das erste Byte des IV-Werts ändern, sodass **IV\[0] XOR "A" == IV'\[0] XOR "a"** und das Cookie für den Benutzer **Administrator** neu generieren. Dieses Cookie wird gültig sein, um den Benutzer **administrator** mit dem ursprünglichen **IV** zu **vortäuschen**.

## Referenzen

Weitere Informationen unter [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
{% endhint %}
