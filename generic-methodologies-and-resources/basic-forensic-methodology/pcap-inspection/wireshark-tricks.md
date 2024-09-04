# Wireshark-Tricks

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


## Verbessere deine Wireshark-Fähigkeiten

### Tutorials

Die folgenden Tutorials sind großartig, um einige coole grundlegende Tricks zu lernen:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysierte Informationen

**Experteninformationen**

Durch Klicken auf _**Analyse** --> **Experteninformationen**_ erhältst du eine **Übersicht** darüber, was in den **analysierten** Paketen passiert:

![](<../../../.gitbook/assets/image (256).png>)

**Aufgelöste Adressen**

Unter _**Statistiken --> Aufgelöste Adressen**_ findest du mehrere **Informationen**, die von Wireshark "**aufgelöst**" wurden, wie Port/Transport zu Protokoll, MAC zu Hersteller usw. Es ist interessant zu wissen, was an der Kommunikation beteiligt ist.

![](<../../../.gitbook/assets/image (893).png>)

**Protokollhierarchie**

Unter _**Statistiken --> Protokollhierarchie**_ findest du die **Protokolle**, die an der Kommunikation beteiligt sind, sowie Daten über sie.

![](<../../../.gitbook/assets/image (586).png>)

**Gespräche**

Unter _**Statistiken --> Gespräche**_ findest du eine **Zusammenfassung der Gespräche** in der Kommunikation und Daten darüber.

![](<../../../.gitbook/assets/image (453).png>)

**Endpunkte**

Unter _**Statistiken --> Endpunkte**_ findest du eine **Zusammenfassung der Endpunkte** in der Kommunikation und Daten über jeden von ihnen.

![](<../../../.gitbook/assets/image (896).png>)

**DNS-Info**

Unter _**Statistiken --> DNS**_ findest du Statistiken über die erfassten DNS-Anfragen.

![](<../../../.gitbook/assets/image (1063).png>)

**I/O-Diagramm**

Unter _**Statistiken --> I/O-Diagramm**_ findest du ein **Diagramm der Kommunikation.**

![](<../../../.gitbook/assets/image (992).png>)

### Filter

Hier findest du Wireshark-Filter je nach Protokoll: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Weitere interessante Filter:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP- und anfänglicher HTTPS-Verkehr
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP- und anfänglicher HTTPS-Verkehr + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP- und anfänglicher HTTPS-Verkehr + TCP SYN + DNS-Anfragen

### Suche

Wenn du nach **Inhalten** innerhalb der **Pakete** der Sitzungen suchen möchtest, drücke _CTRL+f_. Du kannst neue Ebenen zur Hauptinformationsleiste (Nr., Zeit, Quelle usw.) hinzufügen, indem du mit der rechten Maustaste klickst und dann die Spalte bearbeitest.

### Kostenlose pcap-Labore

**Übe mit den kostenlosen Herausforderungen von:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifizierung von Domains

Du kannst eine Spalte hinzufügen, die den Host-HTTP-Header anzeigt:

![](<../../../.gitbook/assets/image (639).png>)

Und eine Spalte, die den Servernamen von einer initiierenden HTTPS-Verbindung (**ssl.handshake.type == 1**) hinzufügt:

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identifizierung lokaler Hostnamen

### Von DHCP

In der aktuellen Wireshark-Version musst du anstelle von `bootp` nach `DHCP` suchen.

![](<../../../.gitbook/assets/image (1013).png>)

### Von NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## TLS entschlüsseln

### Entschlüsselung von HTTPS-Verkehr mit dem privaten Schlüssel des Servers

_edit>präferenz>protokoll>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Drücke _Bearbeiten_ und füge alle Daten des Servers und den privaten Schlüssel (_IP, Port, Protokoll, Schlüsseldatei und Passwort_) hinzu.

### Entschlüsselung von HTTPS-Verkehr mit symmetrischen Sitzungsschlüsseln

Sowohl Firefox als auch Chrome haben die Fähigkeit, TLS-Sitzungsschlüssel zu protokollieren, die mit Wireshark verwendet werden können, um TLS-Verkehr zu entschlüsseln. Dies ermöglicht eine eingehende Analyse sicherer Kommunikation. Weitere Details zur Durchführung dieser Entschlüsselung findest du in einem Leitfaden bei [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Um dies zu erkennen, suche in der Umgebung nach der Variablen `SSLKEYLOGFILE`.

Eine Datei mit gemeinsamen Schlüsseln sieht so aus:

![](<../../../.gitbook/assets/image (820).png>)

Um dies in Wireshark zu importieren, gehe zu _bearbeiten > präferenz > protokoll > ssl > und importiere es in (Pre)-Master-Secret-Protokolldateinamen:

![](<../../../.gitbook/assets/image (989).png>)

## ADB-Kommunikation

Extrahiere eine APK aus einer ADB-Kommunikation, in der die APK gesendet wurde:
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
