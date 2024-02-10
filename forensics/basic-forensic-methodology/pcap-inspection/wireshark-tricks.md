# Wireshark-Tricks

## Wireshark-Tricks

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Verbessern Sie Ihre Wireshark-Fähigkeiten

### Tutorials

Die folgenden Tutorials sind großartig, um einige coole grundlegende Tricks zu lernen:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysierte Informationen

**Experteninformationen**

Durch Klicken auf _**Analyze** --> **Expert Information**_ erhalten Sie einen **Überblick** darüber, was in den analysierten Paketen passiert:

![](<../../../.gitbook/assets/image (570).png>)

**Aufgelöste Adressen**

Unter _**Statistics --> Resolved Addresses**_ finden Sie verschiedene **Informationen**, die von Wireshark "**aufgelöst**" wurden, z. B. Port/Transport zu Protokoll, MAC-Adresse zum Hersteller usw. Es ist interessant zu wissen, was in der Kommunikation impliziert ist.

![](<../../../.gitbook/assets/image (571).png>)

**Protokollhierarchie**

Unter _**Statistics --> Protocol Hierarchy**_ finden Sie die **Protokolle**, die an der Kommunikation beteiligt sind, und Informationen über sie.

![](<../../../.gitbook/assets/image (572).png>)

**Unterhaltungen**

Unter _**Statistics --> Conversations**_ finden Sie eine **Zusammenfassung der Unterhaltungen** in der Kommunikation und Informationen darüber.

![](<../../../.gitbook/assets/image (573).png>)

**Endpunkte**

Unter _**Statistics --> Endpoints**_ finden Sie eine **Zusammenfassung der Endpunkte** in der Kommunikation und Informationen zu jedem von ihnen.

![](<../../../.gitbook/assets/image (575).png>)

**DNS-Informationen**

Unter _**Statistics --> DNS**_ finden Sie Statistiken über die erfassten DNS-Anfragen.

![](<../../../.gitbook/assets/image (577).png>)

**I/O-Graph**

Unter _**Statistics --> I/O Graph**_ finden Sie einen **Graphen der Kommunikation**.

![](<../../../.gitbook/assets/image (574).png>)

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

Wenn Sie nach **Inhalten** in den **Paketen** der Sitzungen suchen möchten, drücken Sie _STRG+f_. Sie können der Hauptinformationsleiste neue Spalten hinzufügen (Nr., Zeit, Quelle usw.), indem Sie mit der rechten Maustaste klicken und dann die Spalte bearbeiten.

### Kostenlose pcap-Labore

**Üben Sie mit den kostenlosen Herausforderungen von: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)**

## Identifizierung von Domains

Sie können eine Spalte hinzufügen, die den Host-HTTP-Header anzeigt:

![](<../../../.gitbook/assets/image (403).png>)

Und eine Spalte, die den Servernamen einer initiierenden HTTPS-Verbindung hinzufügt (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifizierung lokaler Hostnamen

### Von DHCP

In der aktuellen Wireshark-Version müssen Sie anstelle von `bootp` nach `DHCP` suchen

![](<../../../.gitbook/assets/image (404).png>)

### Von NBNS

![](<../../../.gitbook/assets/image (405).png>)

## Entschlüsselung von TLS

### Entschlüsselung von HTTPS-Verkehr mit dem privaten Serverschlüssel

_Bearbeiten > Einstellungen > Protokoll > SSL >_

![](<../../../.gitbook/assets/image (98).png>)

Klicken Sie auf _Bearbeiten_ und fügen Sie alle Daten des Servers und des privaten Schlüssels hinzu (_IP, Port, Protokoll, Schlüsseldatei und Passwort_)

### Entschlüsselung von HTTPS-Verkehr mit symmetrischen Sitzungsschlüsseln

Sowohl Firefox als auch Chrome haben die Möglichkeit, TLS-Sitzungsschlüssel zu protokollieren, die mit Wireshark zur Entschlüsselung des TLS-Verkehrs verwendet werden können. Dies ermöglicht eine eingehende Analyse sicherer Kommunikation. Weitere Details zur Durchführung dieser Entschlüsselung finden Sie in einem Leitfaden von [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Um dies zu erkennen, suchen Sie in der Umgebung nach der Variable `SSLKEYLOGFILE`

Eine Datei mit gemeinsam genutzten Schlüsseln sieht folgendermaßen aus:

![](<../../../.gitbook/assets/image (99).png>)

Um dies in Wireshark zu importieren, gehen Sie zu \_Bearbeiten > Einstellungen > Protokoll > SSL > und importieren Sie es in (Pre)-Master-Secret Log-Dateiname:

![](<../../../.gitbook/assets/image (100).png>)

## ADB-Kommunikation

Extrahieren Sie eine APK aus einer ADB-Kommunikation, bei der die APK gesendet wurde:
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
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
