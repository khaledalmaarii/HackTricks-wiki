<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die kostenlose Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** kompromittiert wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe zu bekämpfen, die aus informationsstehlender Malware resultieren.

Sie können ihre Website besuchen und ihre Engine kostenlos ausprobieren unter:

{% embed url="https://whiteintel.io" %}

---

# Zusammenfassung des Angriffs

Stellen Sie sich einen Server vor, der einige **Daten** durch **Anhängen** eines **Geheimnisses** an einige bekannte Klartextdaten signiert und dann diese Daten hasht. Wenn Sie wissen:

* **Die Länge des Geheimnisses** (dies kann auch aus einem gegebenen Längenbereich bruteforce sein)
* **Die Klartextdaten**
* **Der Algorithmus (und er ist anfällig für diesen Angriff)**
* **Das Padding ist bekannt**
* Normalerweise wird ein Standard-Padding verwendet, daher ist dies auch der Fall, wenn die anderen 3 Anforderungen erfüllt sind
* Das Padding variiert je nach Länge des Geheimnisses+Daten, daher ist die Länge des Geheimnisses erforderlich

Dann ist es für einen **Angreifer** möglich, **Daten anzuhängen** und eine gültige **Signatur** für die **vorherigen Daten + angehängte Daten** zu **generieren**.

## Wie?

Grundsätzlich generieren die anfälligen Algorithmen die Hashes, indem sie zunächst einen Block von Daten hashen und dann **aus** dem **zuvor** erstellten **Hash** (Zustand) **den nächsten Block von Daten hinzufügen** und **hashen**.

Stellen Sie sich vor, das Geheimnis lautet "Geheimnis" und die Daten lauten "Daten", der MD5 von "GeheimnisDaten" ist 6036708eba0d11f6ef52ad44e8b74d5b.\
Wenn ein Angreifer den String "anhängen" anhängen möchte, kann er:

* Einen MD5 von 64 "A"s generieren
* Den Zustand des zuvor initialisierten Hashs auf 6036708eba0d11f6ef52ad44e8b74d5b ändern
* Den String "anhängen" anhängen
* Den Hash abschließen und der resultierende Hash wird ein **gültiger Hash für "Geheimnis" + "Daten" + "Padding" + "anhängen"** sein

## **Tool**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Referenzen

Sie können diesen Angriff gut erklärt finden unter [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die kostenlose Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** kompromittiert wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe zu bekämpfen, die aus informationsstehlender Malware resultieren.

Sie können ihre Website besuchen und ihre Engine kostenlos ausprobieren unter:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen** möchten oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
