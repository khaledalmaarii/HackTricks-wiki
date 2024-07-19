# Speicherabbildanalyse

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersecurity-Veranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersecurity-Profis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

## Start

Beginnen Sie **mit der Suche** nach **Malware** im pcap. Verwenden Sie die **Werkzeuge**, die in [**Malware-Analyse**](../malware-analysis.md) erwähnt werden.

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility ist das Haupt-Open-Source-Framework für die Analyse von Speicherabbildern**. Dieses Python-Tool analysiert Dumps von externen Quellen oder VMware-VMs und identifiziert Daten wie Prozesse und Passwörter basierend auf dem OS-Profil des Dumps. Es ist mit Plugins erweiterbar, was es für forensische Untersuchungen äußerst vielseitig macht.

**[Hier finden Sie ein Cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Mini-Dump-Absturzbericht

Wenn der Dump klein ist (nur einige KB, vielleicht ein paar MB), dann handelt es sich wahrscheinlich um einen Mini-Dump-Absturzbericht und nicht um ein Speicherabbild.

![](<../../../.gitbook/assets/image (216).png>)

Wenn Sie Visual Studio installiert haben, können Sie diese Datei öffnen und einige grundlegende Informationen wie Prozessname, Architektur, Ausnahmeinformationen und ausgeführte Module binden:

![](<../../../.gitbook/assets/image (217).png>)

Sie können auch die Ausnahme laden und die dekompilierten Anweisungen ansehen

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

Jedenfalls ist Visual Studio nicht das beste Werkzeug, um eine tiefgehende Analyse des Dumps durchzuführen.

Sie sollten es **mit IDA** oder **Radare** öffnen, um es **gründlich** zu inspizieren.
