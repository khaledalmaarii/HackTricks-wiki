# Pcap-Inspektion

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Eine Anmerkung zu **PCAP** vs **PCAPNG**: Es gibt zwei Versionen des PCAP-Dateiformats; **PCAPNG ist neuer und wird nicht von allen Tools unterstützt**. Möglicherweise müssen Sie eine Datei von PCAPNG in PCAP konvertieren, um mit ihr in anderen Tools arbeiten zu können, z. B. mit Wireshark oder einem anderen kompatiblen Tool.
{% endhint %}

## Online-Tools für PCAPs

* Wenn der Header Ihrer PCAP **beschädigt** ist, sollten Sie versuchen, ihn mit [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php) zu **reparieren**
* Extrahieren Sie **Informationen** und suchen Sie nach **Malware** in einer PCAP-Datei in [**PacketTotal**](https://packettotal.com)
* Suchen Sie nach **bösartiger Aktivität** mit [**www.virustotal.com**](https://www.virustotal.com) und [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Informationen extrahieren

Die folgenden Tools sind nützlich, um Statistiken, Dateien usw. zu extrahieren.

### Wireshark

{% hint style="info" %}
**Wenn Sie eine PCAP analysieren möchten, müssen Sie im Grunde wissen, wie man Wireshark verwendet**
{% endhint %}

Einige Wireshark-Tricks finden Sie unter:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(nur Linux)_ kann eine PCAP analysieren und Informationen daraus extrahieren. Zum Beispiel extrahiert Xplico aus einer PCAP-Datei jede E-Mail (POP, IMAP und SMTP-Protokolle), alle HTTP-Inhalte, jeden VoIP-Anruf (SIP), FTP, TFTP usw.

**Installation**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Ausführen**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Zugriff auf _**127.0.0.1:9876**_ mit Anmeldeinformationen _**xplico:xplico**_

Erstellen Sie dann einen **neuen Fall**, erstellen Sie eine **neue Sitzung** innerhalb des Falls und **laden Sie die pcap-Datei hoch**.

### NetworkMiner

Wie Xplico ist es ein Tool zum **Analysieren und Extrahieren von Objekten aus pcaps**. Es gibt eine kostenlose Edition, die Sie **hier** herunterladen können (https://www.netresec.com/?page=NetworkMiner). Es funktioniert mit **Windows**.\
Dieses Tool ist auch nützlich, um **weitere analysierte Informationen** aus den Paketen zu erhalten, um schneller herauszufinden, was passiert ist.

### NetWitness Investigator

Sie können [**NetWitness Investigator hier herunterladen**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Es funktioniert unter Windows)**.\
Dies ist ein weiteres nützliches Tool, das die Pakete **analysiert** und die Informationen auf eine nützliche Weise sortiert, um zu **wissen, was drinnen passiert**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Extrahieren und Codieren von Benutzernamen und Passwörtern (HTTP, FTP, Telnet, IMAP, SMTP...)
* Extrahieren von Authentifizierungshashes und Knacken mit Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Erstellen eines visuellen Netzwerkdiagramms (Netzwerkknoten und Benutzer)
* Extrahieren von DNS-Anfragen
* Rekonstruieren aller TCP- und UDP-Sitzungen
* Dateischnitzerei

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Wenn Sie in der pcap-Datei nach etwas suchen möchten, können Sie **ngrep** verwenden. Hier ist ein Beispiel mit den Hauptfiltern:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

Die Verwendung gängiger Carving-Techniken kann nützlich sein, um Dateien und Informationen aus dem pcap zu extrahieren:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Erfassen von Anmeldedaten

Sie können Tools wie [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) verwenden, um Anmeldedaten aus einem pcap oder einer Live-Schnittstelle zu analysieren.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **dem Ziel, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

## Überprüfen von Exploits/Malware

### Suricata

**Installation und Einrichtung**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Überprüfen Sie die pcap-Datei**

Um eine pcap-Datei zu überprüfen, können Sie verschiedene Tools verwenden, um den Inhalt zu analysieren und wichtige Informationen zu extrahieren. Hier sind einige Schritte, die Sie befolgen können:

1. **Wireshark**: Öffnen Sie die pcap-Datei mit Wireshark, einem leistungsstarken Netzwerkanalysetool. Wireshark ermöglicht es Ihnen, den Datenverkehr im Detail zu betrachten, Filter anzuwenden und Protokolle zu analysieren.

2. **TCPDump**: Verwenden Sie das Befehlszeilentool TCPDump, um den Inhalt der pcap-Datei anzuzeigen. Sie können Filter anwenden, um den Datenverkehr auf bestimmte Protokolle oder IP-Adressen zu beschränken.

3. **TShark**: TShark ist ein Konsolenprogramm, das Teil von Wireshark ist. Es ermöglicht Ihnen, pcap-Dateien zu analysieren und wichtige Informationen zu extrahieren, ohne die grafische Benutzeroberfläche von Wireshark verwenden zu müssen.

4. **Zeitstempel überprüfen**: Überprüfen Sie die Zeitstempel in der pcap-Datei, um festzustellen, wann bestimmte Ereignisse stattgefunden haben. Dies kann Ihnen helfen, den Ablauf des Netzwerkverkehrs zu verstehen.

5. **Filter anwenden**: Verwenden Sie Filter, um den Datenverkehr auf bestimmte Protokolle, IP-Adressen oder Ports zu beschränken. Dies kann Ihnen helfen, den relevanten Teil der pcap-Datei zu isolieren.

6. **Analyse von Protokollen**: Untersuchen Sie die Protokolle im pcap-Dateiinhalt, um mögliche Angriffe oder verdächtige Aktivitäten zu identifizieren. Achten Sie auf ungewöhnliche Verhaltensweisen oder Anomalien.

7. **Metadaten überprüfen**: Überprüfen Sie die Metadaten der pcap-Datei, wie z.B. den Ersteller, das Erstellungsdatum und die Dateigröße. Diese Informationen können bei der forensischen Analyse hilfreich sein.

Durch die Überprüfung der pcap-Datei können Sie wertvolle Informationen über den Netzwerkverkehr gewinnen und möglicherweise Angriffe oder Sicherheitsverletzungen erkennen.
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) ist ein Tool, das Folgendes tut:

* Liest eine PCAP-Datei und extrahiert HTTP-Streams.
* Entpackt komprimierte Streams mit gzip.
* Durchsucht jede Datei mit Yara.
* Schreibt einen report.txt.
* Speichert optional übereinstimmende Dateien in einem Verzeichnis.

### Malware-Analyse

Überprüfen Sie, ob Sie einen Fingerabdruck einer bekannten Malware finden können:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) ist ein passiver, Open-Source-Netzwerkverkehrsanalysator. Viele Betreiber verwenden Zeek als Netzwerksicherheitsmonitor (NSM), um Untersuchungen zu verdächtigen oder bösartigen Aktivitäten zu unterstützen. Zeek unterstützt auch eine Vielzahl von Verkehrsanalyseaufgaben jenseits des Sicherheitsbereichs, einschließlich Leistungsmessung und Fehlerbehebung.

Grundsätzlich sind die von `zeek` erstellten Protokolle keine **pcaps**. Daher müssen Sie **andere Tools** verwenden, um die Protokolle zu analysieren, in denen sich die **Informationen** über die pcaps befinden.

### Verbindungsinfo
```bash
#Get info about longest connections (add "grep udp" to see only udp traffic)
#The longest connection might be of malware (constant reverse shell?)
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head -n 10

10.55.100.100   49778   65.52.108.225   443     tcp     -       86222.365445
10.55.100.107   56099   111.221.29.113  443     tcp     -       86220.126151
10.55.100.110   60168   40.77.229.82    443     tcp     -       86160.119664


#Improve the metrics by summing up the total duration time for connections that have the same destination IP and Port.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10

10.55.100.100   65.52.108.225   443     tcp     86222.4
10.55.100.107   111.221.29.113  443     tcp     86220.1
10.55.100.110   40.77.229.82    443     tcp     86160.1

#Get the number of connections summed up per each line
cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3; count[$1 FS $2] += 1 } END{ for (key in arr) printf "%s%s%s%s%s\n", key, FS, count[key], FS, arr[key] }' | sort -nrk 4 | head -n 10

10.55.100.100   65.52.108.225   1       86222.4
10.55.100.107   111.221.29.113  1       86220.1
10.55.100.110   40.77.229.82    134       86160.1

#Check if any IP is connecting to 1.1.1.1
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c

#Get number of connections per source IP, dest IP and dest Port
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10


# RITA
#Something similar can be done with the tool rita
rita show-long-connections -H --limit 10 zeek_logs

+---------------+----------------+--------------------------+----------------+
|   SOURCE IP   | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE |    DURATION    |
+---------------+----------------+--------------------------+----------------+
| 10.55.100.100 | 65.52.108.225  | 443:tcp:-                | 23h57m2.3655s  |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:-                | 23h57m0.1262s  |
| 10.55.100.110 | 40.77.229.82   | 443:tcp:-                | 23h56m0.1197s  |

#Get connections info from rita
rita show-beacons zeek_logs | head -n 10
Score,Source IP,Destination IP,Connections,Avg Bytes,Intvl Range,Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
1,192.168.88.2,165.227.88.15,108858,197,860,182,1,89,53341,108319,0,0,0,0
1,10.55.100.111,165.227.216.194,20054,92,29,52,1,52,7774,20053,0,0,0,0
0.838,10.55.200.10,205.251.194.64,210,69,29398,4,300,70,109,205,0,0,0,0
```
### DNS-Informationen

DNS (Domain Name System) ist ein grundlegender Bestandteil des Internets, der für die Auflösung von Domainnamen in IP-Adressen verantwortlich ist. Bei der Untersuchung von PCAP-Dateien können DNS-Informationen wertvolle Einblicke liefern. Hier sind einige nützliche Techniken, um DNS-Informationen aus PCAP-Dateien zu extrahieren:

#### DNS-Anfragen und -Antworten filtern

Verwenden Sie Filter, um nur DNS-Anfragen und -Antworten anzuzeigen. Dies kann Ihnen helfen, den Datenverkehr zu reduzieren und sich auf relevante Informationen zu konzentrieren.

```bash
tcpdump -r file.pcap 'udp port 53'
```

#### DNS-Anfragen analysieren

Analysieren Sie die DNS-Anfragen, um Informationen über die angeforderten Domains zu erhalten. Dies kann Ihnen helfen, verdächtige Aktivitäten oder ungewöhnliche Muster zu erkennen.

```bash
tshark -r file.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name
```

#### DNS-Antworten analysieren

Analysieren Sie die DNS-Antworten, um Informationen über die aufgelösten IP-Adressen zu erhalten. Dies kann Ihnen helfen, potenzielle Ziele oder Kommunikationskanäle zu identifizieren.

```bash
tshark -r file.pcap -Y 'dns.flags.response == 1' -T fields -e dns.a
```

#### DNS-Cache analysieren

Analysieren Sie den DNS-Cache, um Informationen über zuvor aufgelöste Domains zu erhalten. Dies kann Ihnen helfen, historische Aktivitäten zu untersuchen und mögliche Angriffsziele zu identifizieren.

```bash
tshark -r file.pcap -Y 'dns.flags.response == 1 && dns.flags.rcode == 0' -T fields -e dns.a -e dns.qry.name
```

#### DNS-Verkehr visualisieren

Visualisieren Sie den DNS-Verkehr, um Muster oder Anomalien zu erkennen. Dies kann Ihnen helfen, Zusammenhänge zwischen verschiedenen Domains oder IP-Adressen zu verstehen.

```bash
tshark -r file.pcap -Y 'dns.flags.response == 1' -T fields -e dns.a -e dns.qry.name | awk '{print $2" "$1}' | sort | uniq -c | sort -nr
```

Die Analyse von DNS-Informationen kann bei der forensischen Untersuchung von PCAP-Dateien äußerst nützlich sein, um verdächtige Aktivitäten zu erkennen und mögliche Sicherheitsverletzungen aufzudecken.
```bash
#Get info about each DNS request performed
cat dns.log | zeek-cut -c id.orig_h query qtype_name answers

#Get the number of times each domain was requested and get the top 10
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 10

#Get all the IPs
cat dns.log | zeek-cut id.orig_h query | grep 'example\.com' | cut -f 1 | sort | uniq -c

#Sort the most common DNS record request (should be A)
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr

#See top DNS domain requested with rita
rita show-exploded-dns -H --limit 10 zeek_logs
```
## Weitere Tricks zur Analyse von PCAP-Dateien

{% content-ref url="dnscat-exfiltration.md" %}
[dnscat-exfiltration.md](dnscat-exfiltration.md)
{% endcontent-ref %}

{% content-ref url="wifi-pcap-analysis.md" %}
[wifi-pcap-analysis.md](wifi-pcap-analysis.md)
{% endcontent-ref %}

{% content-ref url="usb-keystrokes.md" %}
[usb-keystrokes.md](usb-keystrokes.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **dem Ziel, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
