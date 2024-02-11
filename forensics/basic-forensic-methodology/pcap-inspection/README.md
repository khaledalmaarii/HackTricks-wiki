# Inspekcja plików Pcap

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Informacja na temat **PCAP** vs **PCAPNG**: istnieją dwie wersje formatu pliku PCAP; **PCAPNG jest nowszy i nie jest obsługiwany przez wszystkie narzędzia**. Może być konieczne przekonwertowanie pliku z formatu PCAPNG na PCAP za pomocą Wiresharka lub innego kompatybilnego narzędzia, aby móc pracować z nim w innych narzędziach.
{% endhint %}

## Narzędzia online do plików pcap

* Jeśli nagłówek twojego pliku pcap jest **uszkodzony**, spróbuj go **naprawić** za pomocą: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Wyszukaj **informacje** i szukaj **złośliwego oprogramowania** w pliku pcap na stronie [**PacketTotal**](https://packettotal.com)
* Wyszukaj **złośliwe działania** za pomocą [**www.virustotal.com**](https://www.virustotal.com) i [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Wyodrębnianie informacji

Następujące narzędzia są przydatne do wyodrębniania statystyk, plików, itp.

### Wireshark

{% hint style="info" %}
**Jeśli zamierzasz analizować plik PCAP, musisz znać podstawy korzystania z Wiresharka**
{% endhint %}

Niektóre sztuczki związane z Wiresharkiem można znaleźć w:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Framework Xplico

[**Xplico** ](https://github.com/xplico/xplico)_(tylko linux)_ może **analizować** plik **pcap** i wyodrębniać z niego informacje. Na przykład, z pliku pcap Xplico wyodrębnia każdy e-mail (protokoły POP, IMAP i SMTP), wszystkie treści HTTP, każde połączenie VoIP (SIP), FTP, TFTP, itp.

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
Dostęp do _**127.0.0.1:9876**_ z danymi logowania _**xplico:xplico**_

Następnie utwórz **nowe sprawozdanie**, utwórz **nową sesję** w ramach sprawozdania i **załaduj plik pcap**.

### NetworkMiner

Podobnie jak Xplico, jest to narzędzie do **analizy i ekstrakcji obiektów z plików pcap**. Dostępna jest bezpłatna wersja, którą można **pobrać [tutaj](https://www.netresec.com/?page=NetworkMiner)**. Działa na systemie **Windows**.\
To narzędzie jest również przydatne do **analizy innych informacji** z pakietów, aby szybciej dowiedzieć się, co się działo.

### NetWitness Investigator

Możesz pobrać [**NetWitness Investigator stąd**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Działa w systemie Windows)**.\
To kolejne przydatne narzędzie, które **analizuje pakiety** i sortuje informacje w sposób umożliwiający **zrozumienie tego, co się dzieje wewnątrz**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Wyodrębnianie i kodowanie nazw użytkowników i haseł (HTTP, FTP, Telnet, IMAP, SMTP...)
* Wyodrębnianie skrótów uwierzytelniania i łamanie ich za pomocą Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Tworzenie wizualnego diagramu sieci (węzły sieciowe i użytkownicy)
* Wyodrębnianie zapytań DNS
* Rekonstrukcja wszystkich sesji TCP i UDP
* Wycinanie plików

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Jeśli **szukasz** czegoś wewnątrz pliku pcap, możesz użyć **ngrep**. Oto przykład użycia głównych filtrów:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Wycinanie

Używanie powszechnych technik wycinania może być przydatne do wyodrębniania plików i informacji z pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Przechwytywanie poświadczeń

Możesz użyć narzędzi takich jak [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) do analizy poświadczeń z pcap lub interfejsu na żywo.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z misją promowania wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

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

Plik pcap to format przechowujący przechwycone pakiety sieciowe. Może zawierać cenne informacje, takie jak dane logowania, przesyłane hasła, adresy IP i wiele innych. Aby przeprowadzić analizę forensyczną, warto sprawdzić zawartość pliku pcap.

Aby to zrobić, możesz skorzystać z narzędzi takich jak Wireshark lub tcpdump. Otwórz plik pcap za pomocą jednego z tych narzędzi i przejrzyj przechwycone pakiety. Możesz filtrować pakiety według różnych kryteriów, takich jak adres IP, port, protokół itp., aby skupić się na interesujących Cię danych.

Podczas analizy pliku pcap zwróć uwagę na następujące elementy:

1. Adresy IP: Sprawdź, czy w pliku pcap występują podejrzane lub nieznane adresy IP. Mogą wskazywać na aktywność nieautoryzowanego dostępu lub ataku.

2. Protokoły: Zidentyfikuj używane protokoły w przechwyconych pakietach. Może to pomóc w zrozumieniu, jakie usługi były wykorzystywane i jakie działania były podejmowane.

3. Dane logowania: Poszukaj pakietów zawierających dane logowania, takie jak nazwy użytkowników i hasła. Jeśli takie dane są przechwycone, może to wskazywać na próbę ataku lub naruszenie bezpieczeństwa.

4. Zapytania HTTP: Przejrzyj przechwycone zapytania HTTP, aby zidentyfikować odwiedzane strony internetowe, przesyłane dane i inne szczegóły. Może to dostarczyć informacji na temat aktywności użytkownika.

5. Analiza czasu: Zwróć uwagę na znaczniki czasowe pakietów. Może to pomóc w zidentyfikowaniu sekwencji zdarzeń i ustaleniu chronologii działań.

Analiza pliku pcap może dostarczyć cennych informacji na temat aktywności sieciowej i potencjalnych zagrożeń. Pamiętaj jednak, że analiza pliku pcap powinna być przeprowadzana zgodnie z obowiązującymi przepisami i zasadami prywatności.
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) to narzędzie, które:

* Odczytuje plik PCAP i wyodrębnia strumienie HTTP.
* Kompresuje strumienie, które są skompresowane za pomocą gzip.
* Skanuje każdy plik za pomocą Yara.
* Zapisuje raport w pliku report.txt.
* Opcjonalnie zapisuje pasujące pliki do katalogu.

### Analiza złośliwego oprogramowania

Sprawdź, czy możesz znaleźć jakiekolwiek odciski palców znanego złośliwego oprogramowania:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) to pasywny, otwartoźródłowy analizator ruchu sieciowego. Wielu operatorów używa Zeeka jako Monitora Bezpieczeństwa Sieciowego (NSM) do wspierania dochodzeń dotyczących podejrzanej lub złośliwej aktywności. Zeek obsługuje również szeroki zakres zadań analizy ruchu poza dziedziną bezpieczeństwa, w tym pomiaru wydajności i rozwiązywania problemów.

W zasadzie, logi tworzone przez `zeek` nie są **pcapami**. Dlatego będziesz musiał użyć **innych narzędzi** do analizy logów, gdzie znajdują się **informacje** o pcapach.

### Informacje o połączeniach
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
### Informacje o DNS

DNS (Domain Name System) jest systemem, który przypisuje adresy IP do nazw domenowych. Jest to niezwykle przydatne narzędzie w świecie internetu, ponieważ pozwala nam korzystać z łatwo zapamiętywalnych nazw, zamiast pamiętać skomplikowane adresy IP.

Podczas analizy plików pcap, możemy znaleźć wiele informacji na temat ruchu sieciowego związanych z DNS. Poniżej przedstawiam kilka przykładów, jak można wykorzystać te informacje:

#### 1. Zapytania DNS

Analizując plik pcap, możemy zidentyfikować zapytania DNS, które zostały wysłane przez użytkowników. Możemy zobaczyć, jakie nazwy domenowe były wyszukiwane, co może dostarczyć nam informacji na temat zainteresowań lub działań użytkowników.

#### 2. Odpowiedzi DNS

Podobnie jak zapytania DNS, analiza odpowiedzi DNS może dostarczyć nam informacji na temat odwiedzanych stron internetowych. Możemy zobaczyć, jakie adresy IP były przypisane do konkretnych nazw domenowych.

#### 3. Zmienione rekordy DNS

Czasami atakujący próbują zmienić rekordy DNS, aby przekierować użytkowników na złośliwe strony internetowe. Analiza pliku pcap może pomóc nam w identyfikacji takich zmienionych rekordów DNS i zabezpieczeniu naszej sieci przed tego typu atakami.

#### 4. Analiza czasu odpowiedzi DNS

Analiza czasu odpowiedzi DNS może pomóc nam w identyfikacji problemów z wydajnością sieci. Możemy zobaczyć, które zapytania DNS mają długie czasy odpowiedzi i podjąć odpowiednie działania w celu poprawy wydajności.

#### 5. Analiza zapytań rekurencyjnych

Zapytania rekurencyjne to zapytania DNS, w których serwer DNS wykonuje pełne przeszukiwanie hierarchii domen w celu znalezienia adresu IP dla danej nazwy domenowej. Analiza zapytań rekurencyjnych może dostarczyć nam informacji na temat zapytań, które wymagają większej ilości zasobów sieciowych.

#### 6. Analiza zapytań iteracyjnych

Zapytania iteracyjne to zapytania DNS, w których serwer DNS udziela odpowiedzi na podstawie informacji, które posiada w swoim cache lub przekierowuje zapytanie do innego serwera DNS. Analiza zapytań iteracyjnych może dostarczyć nam informacji na temat zapytań, które wymagają komunikacji z innymi serwerami DNS.

#### 7. Analiza zapytań typu AAAA

Zapytania typu AAAA są zapytaniami DNS, które mają na celu znalezienie adresu IPv6 dla danej nazwy domenowej. Analiza zapytań typu AAAA może dostarczyć nam informacji na temat używanych adresów IPv6 w naszej sieci.

#### 8. Analiza zapytań typu MX

Zapytania typu MX są zapytaniami DNS, które mają na celu znalezienie serwera poczty elektronicznej dla danej domeny. Analiza zapytań typu MX może dostarczyć nam informacji na temat konfiguracji poczty elektronicznej w naszej sieci.

#### 9. Analiza zapytań typu NS

Zapytania typu NS są zapytaniami DNS, które mają na celu znalezienie serwera nazw dla danej domeny. Analiza zapytań typu NS może dostarczyć nam informacji na temat konfiguracji serwerów nazw w naszej sieci.

#### 10. Analiza zapytań typu TXT

Zapytania typu TXT są zapytaniami DNS, które mają na celu uzyskanie informacji tekstowych dla danej domeny. Analiza zapytań typu TXT może dostarczyć nam dodatkowych informacji na temat danej domeny, takich jak polityka bezpieczeństwa czy klucze publiczne.

Analiza plików pcap związanych z ruchem DNS może dostarczyć nam wielu cennych informacji na temat naszej sieci. Może nam pomóc w identyfikacji problemów, zabezpieczeniu sieci przed atakami i zrozumieniu zachowań użytkowników.
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

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając na celu promowanie wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
