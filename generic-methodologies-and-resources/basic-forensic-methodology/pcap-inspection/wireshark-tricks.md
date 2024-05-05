# Wireshark Tricks

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben** sehen möchten oder **HackTricks im PDF-Format herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die **kostenlose** Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware**n **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihren Dienst **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

***

## Verbessern Sie Ihre Wireshark-Fähigkeiten

### Tutorials

Die folgenden Tutorials sind großartig, um einige coole grundlegende Tricks zu lernen:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysierte Informationen

**Experteninformationen**

Durch Klicken auf _**Analysieren** --> **Experteninformationen**_ erhalten Sie einen **Überblick** darüber, was in den **analysierten** Paketen passiert:

![](<../../../.gitbook/assets/image (256).png>)

**Gelöste Adressen**

Unter _**Statistik --> Gelöste Adressen**_ finden Sie verschiedene **Informationen**, die von Wireshark "**gelöst**" wurden, wie Port/Transport zu Protokoll, MAC-Adresse zum Hersteller usw. Es ist interessant zu wissen, was in der Kommunikation involviert ist.

![](<../../../.gitbook/assets/image (893).png>)

**Protokollhierarchie**

Unter _**Statistik --> Protokollhierarchie**_ finden Sie die **Protokolle**, die an der Kommunikation beteiligt sind, und Informationen über sie.

![](<../../../.gitbook/assets/image (586).png>)

**Unterhaltungen**

Unter _**Statistik --> Unterhaltungen**_ finden Sie eine **Zusammenfassung der Unterhaltungen** in der Kommunikation und Informationen darüber.

![](<../../../.gitbook/assets/image (453).png>)

**Endpunkte**

Unter _**Statistik --> Endpunkte**_ finden Sie eine **Zusammenfassung der Endpunkte** in der Kommunikation und Informationen zu jedem von ihnen.

![](<../../../.gitbook/assets/image (896).png>)

**DNS-Informationen**

Unter _**Statistik --> DNS**_ finden Sie Statistiken zu den erfassten DNS-Anfragen.

![](<../../../.gitbook/assets/image (1063).png>)

**I/O-Graph**

Unter _**Statistik --> I/O-Graph**_ finden Sie einen **Graphen der Kommunikation**.

![](<../../../.gitbook/assets/image (992).png>)

### Filter

Hier finden Sie Wireshark-Filter je nach Protokoll: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Andere interessante Filter:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP- und anfänglicher HTTPS-Verkehr
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP- und anfänglicher HTTPS-Verkehr + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP- und anfänglicher HTTPS-Verkehr + TCP SYN + DNS-Anfragen

### Suche

Wenn Sie nach **Inhalten** innerhalb der **Pakete** der Sitzungen suchen möchten, drücken Sie _Strg+f_. Sie können der Hauptinformationsleiste neue Layer hinzufügen (Nr., Zeit, Quelle usw.), indem Sie die rechte Maustaste drücken und dann die Spalte bearbeiten.

### Kostenlose pcap-Labore

**Üben Sie mit den kostenlosen Herausforderungen von:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifizierung von Domains

Sie können eine Spalte hinzufügen, die den Host-HTTP-Header anzeigt:

![](<../../../.gitbook/assets/image (639).png>)

Und eine Spalte hinzufügen, die den Servernamen einer initiierenden HTTPS-Verbindung hinzufügt (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifizierung lokaler Hostnamen

### Aus DHCP

In der aktuellen Wireshark-Version müssen Sie anstelle von `bootp` nach `DHCP` suchen

![](<../../../.gitbook/assets/image (1013).png>)

### Aus NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Entschlüsselung von TLS

### Entschlüsselung des HTTPS-Verkehrs mit dem privaten Serverschlüssel

_Bearbeiten > Einstellungen > Protokoll > SSL >_

![](<../../../.gitbook/assets/image (1103).png>)

Klicken Sie auf _Bearbeiten_ und fügen Sie alle Daten des Servers und des privaten Schlüssels hinzu (_IP, Port, Protokoll, Schlüsseldatei und Passwort_)

### Entschlüsselung des HTTPS-Verkehrs mit symmetrischen Sitzungsschlüsseln

Sowohl Firefox als auch Chrome haben die Möglichkeit, TLS-Sitzungsschlüssel zu protokollieren, die mit Wireshark zur Entschlüsselung des TLS-Verkehrs verwendet werden können. Dies ermöglicht eine eingehende Analyse sicherer Kommunikation. Weitere Details zur Durchführung dieser Entschlüsselung finden Sie in einem Leitfaden bei [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Um dies zu erkennen, suchen Sie in der Umgebung nach der Variablen `SSLKEYLOGFILE`

Eine Datei mit gemeinsamen Schlüsseln sieht so aus:

![](<../../../.gitbook/assets/image (820).png>)

Um dies in Wireshark zu importieren, gehen Sie zu _Bearbeiten > Einstellungen > Protokoll > SSL >_ und importieren Sie es in (Pre)-Master-Secret-Logdateiname:

![](<../../../.gitbook/assets/image (989).png>)
## ADB-Kommunikation

Extrahiere eine APK aus einer ADB-Kommunikation, bei der die APK gesendet wurde:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) ist eine von **Dark Web** angetriebene Suchmaschine, die kostenlose Funktionen bietet, um zu überprüfen, ob ein Unternehmen oder seine Kunden von **Stealer-Malware** **kompromittiert** wurden.

Das Hauptziel von WhiteIntel ist es, Kontoübernahmen und Ransomware-Angriffe aufgrund von informationsstehlender Malware zu bekämpfen.

Sie können ihre Website besuchen und ihre Engine **kostenlos** ausprobieren unter:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Erfahren Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
