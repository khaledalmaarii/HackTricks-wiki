# Speicherabbildanalyse

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist das relevanteste Cybersicherheitsereignis in **Spanien** und eines der wichtigsten in **Europa**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsfachleute in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

## Start

Beginnen Sie mit der **Suche** nach **Malware** innerhalb des PCAP. Verwenden Sie die in der [**Malware-Analyse**](../malware-analysis.md) erwähnten **Tools**.

## [Volatility](volatility-cheatsheet.md)

**Volatility ist das wichtigste Open-Source-Framework für die Analyse von Speicherabbildern**. Dieses Python-Tool analysiert Dump-Dateien aus externen Quellen oder VMware-VMs und identifiziert Daten wie Prozesse und Passwörter basierend auf dem OS-Profil des Dumps. Es ist mit Plugins erweiterbar, was es für forensische Untersuchungen äußerst vielseitig macht.

[**Hier finden Sie ein Spickzettel**](volatility-cheatsheet.md)

## Mini-Dump-Crashbericht

Wenn der Dump klein ist (nur einige KB, vielleicht ein paar MB), handelt es sich wahrscheinlich um einen Mini-Dump-Crashbericht und nicht um ein Speicherabbild.

![](<../../../.gitbook/assets/image (532).png>)

Wenn Sie Visual Studio installiert haben, können Sie diese Datei öffnen und einige grundlegende Informationen wie Prozessname, Architektur, Ausnahmeinformationen und ausgeführte Module binden:

![](<../../../.gitbook/assets/image (263).png>)

Sie können auch die Ausnahme laden und die dekompilierten Anweisungen anzeigen

![](<../../../.gitbook/assets/image (142).png>)

![](<../../../.gitbook/assets/image (610).png>)

Wie auch immer, Visual Studio ist nicht das beste Tool, um eine Analyse der Tiefe des Dumps durchzuführen.

Sie sollten es mit **IDA** oder **Radare** öffnen, um es in **Tiefe** zu inspizieren.

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist das relevanteste Cybersicherheitsereignis in **Spanien** und eines der wichtigsten in **Europa**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsfachleute in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>
