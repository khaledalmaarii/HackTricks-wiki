# Inspekcja Pcap

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie z zakresu cyberbezpieczeństwa w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając **misję promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Informacja o **PCAP** vs **PCAPNG**: istnieją dwie wersje formatu pliku PCAP; **PCAPNG jest nowszy i nie jest obsługiwany przez wszystkie narzędzia**. Może być konieczne przekonwertowanie pliku z PCAPNG na PCAP za pomocą Wiresharka lub innego kompatybilnego narzędzia, aby móc pracować z nim w innych narzędziach.
{% endhint %}

## Narzędzia online do plików pcap

* Jeśli nagłówek twojego pcap jest **uszkodzony**, spróbuj go **naprawić** za pomocą: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Wyodrębnij **informacje** i szukaj **złośliwego oprogramowania** w pcap za pomocą [**PacketTotal**](https://packettotal.com)
* Szukaj **działalności złośliwej** za pomocą [**www.virustotal.com**](https://www.virustotal.com) i [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Wyodrębnianie informacji

Następujące narzędzia są przydatne do wyodrębniania statystyk, plików, itp.

### Wireshark

{% hint style="info" %}
**Jeśli zamierzasz analizować PCAP, musisz w zasadzie umieć korzystać z Wiresharka**
{% endhint %}

Możesz znaleźć kilka sztuczek Wiresharka w:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(tylko linux)_ może **analizować** pcap i wyodrębniać z niego informacje. Na przykład z pliku pcap Xplico wyodrębnia każdy e-mail (protokoły POP, IMAP i SMTP), wszystkie treści HTTP, każde połączenie VoIP (SIP), FTP, TFTP, itp.

**Instalacja**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Uruchom**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Dostęp do _**127.0.0.1:9876**_ za pomocą poświadczeń _**xplico:xplico**_

Następnie utwórz **nowe zdarzenie**, utwórz **nową sesję** wewnątrz zdarzenia i **załaduj plik pcap**.

### NetworkMiner

Podobnie jak Xplico, jest to narzędzie do **analizy i wyodrębniania obiektów z plików pcap**. Posiada darmową wersję, którą można **pobrać** [**tutaj**](https://www.netresec.com/?page=NetworkMiner). Działa z systemem **Windows**.\
To narzędzie jest również przydatne do **analizy innych informacji** z pakietów, aby móc szybciej zrozumieć, co działo się w **sposób bardziej efektywny**.

### NetWitness Investigator

Możesz pobrać [**NetWitness Investigator stąd**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Działa w systemie Windows)**.\
To kolejne przydatne narzędzie, które **analizuje pakiety** i sortuje informacje w użyteczny sposób, aby **zrozumieć, co się dzieje wewnątrz**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Wyodrębnianie i kodowanie nazw użytkowników i haseł (HTTP, FTP, Telnet, IMAP, SMTP...)
* Wyodrębnianie skrótów uwierzytelniania i ich łamanie za pomocą Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Budowanie wizualnego diagramu sieci (węzły sieci i użytkownicy)
* Wyodrębnianie zapytań DNS
* Odtwarzanie wszystkich sesji TCP & UDP
* Wycinanie plików

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Jeśli **szukasz** **czegoś** wewnątrz pliku pcap, możesz użyć **ngrep**. Oto przykład użycia głównych filtrów:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Wycinanie

Korzystanie z powszechnych technik wycinania może być przydatne do wyodrębniania plików i informacji z pliku pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Przechwytywanie poświadczeń

Możesz użyć narzędzi takich jak [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) do analizy poświadczeń z pliku pcap lub interfejsu na żywo.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najbardziej istotne wydarzenie z zakresu cyberbezpieczeństwa w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając **misję promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

## Sprawdź Exploity/Malware

### Suricata

**Instalacja i konfiguracja**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Sprawdź plik pcap**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) to narzędzie, które

* Odczytuje plik PCAP i wyodrębnia strumienie HTTP.
* Kompresuje strumienie, które są skompresowane za pomocą gzip.
* Skanuje każdy plik za pomocą yara.
* Tworzy plik raportu report.txt.
* Opcjonalnie zapisuje pasujące pliki do katalogu.

### Analiza złośliwego oprogramowania

Sprawdź, czy możesz znaleźć jakikolwiek odcisk palca znanego złośliwego oprogramowania:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) to pasywny, otwartoźródłowy analizator ruchu sieciowego. Wielu operatorów używa Zeeka jako Monitora Bezpieczeństwa Sieciowego (NSM) do wsparcia dochodzeń w przypadku podejrzanej lub złośliwej aktywności. Zeek obsługuje również szeroki zakres zadań analizy ruchu poza dziedziną bezpieczeństwa, w tym pomiar wydajności i rozwiązywanie problemów.

W skrócie, dzienniki tworzone przez `zeek` nie są **pcapami**. Dlatego będziesz musiał użyć **innych narzędzi** do analizy dzienników, gdzie znajdują się **informacje** o pcapach.
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
### Informacje DNS
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
## Inne sztuczki analizy pcap

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

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie z zakresu cyberbezpieczeństwa w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając **misję promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
