# Przeglądajka Suricata & Iptables

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć **reklamę Twojej firmy na HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Łańcuchy

W iptables, listy reguł znane jako łańcuchy są przetwarzane sekwencyjnie. Wśród nich istnieją trzy podstawowe łańcuchy, które są powszechnie obecne, a dodatkowe, takie jak NAT, mogą być obsługiwane w zależności od możliwości systemu.

- **Łańcuch Wejściowy**: Wykorzystywany do zarządzania zachowaniem przychodzących połączeń.
- **Łańcuch Przekierowania**: Stosowany do obsługi przychodzących połączeń, które nie są przeznaczone dla lokalnego systemu. Jest to typowe dla urządzeń działających jako routery, gdzie dane otrzymane mają być przekierowane do innego miejsca docelowego. Ten łańcuch jest istotny głównie w przypadku, gdy system jest zaangażowany w routowanie, NATowanie lub podobne działania.
- **Łańcuch Wyjściowy**: Poświęcony regulacji wychodzących połączeń.

Te łańcuchy zapewniają uporządkowane przetwarzanie ruchu sieciowego, umożliwiając określanie szczegółowych reguł dotyczących przepływu danych do, przez i z systemu.
```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```
## Suricata

### Instalacja i konfiguracja

#### Instalacja

1. Zainstaluj Suricatę za pomocą polecenia:

   ```
   sudo apt-get install suricata
   ```

2. Po zakończeniu instalacji, uruchom Suricatę za pomocą polecenia:

   ```
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0
   ```

#### Konfiguracja

1. Otwórz plik konfiguracyjny Suricaty:

   ```
   sudo nano /etc/suricata/suricata.yaml
   ```

2. Skonfiguruj reguły wykrywania ataków, takie jak reguły Snort, w sekcji `rule-files`.

3. Skonfiguruj interfejsy sieciowe, na których Suricata ma nasłuchiwać, w sekcji `af-packet`.

4. Skonfiguruj wyjście zdarzeń, takie jak pliki logów, w sekcji `outputs`.

5. Zapisz plik konfiguracyjny i uruchom Suricatę ponownie.

### Iptables

#### Dodawanie reguł iptables

1. Dodaj regułę iptables za pomocą polecenia:

   ```
   sudo iptables -A INPUT -p tcp --dport 80 -j DROP
   ```

2. Sprawdź, czy reguła została dodana poprawnie:

   ```
   sudo iptables -L
   ```

#### Usuwanie reguł iptables

1. Usuń regułę iptables za pomocą polecenia:

   ```
   sudo iptables -D INPUT -p tcp --dport 80 -j DROP
   ```

2. Sprawdź, czy reguła została usunięta poprawnie:

   ```
   sudo iptables -L
   ```
```bash
# Install details from: https://suricata.readthedocs.io/en/suricata-6.0.0/install.html#install-binary-packages
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
/etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl suricata start
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking
## or set the follogin in /etc/suricata/suricata.yaml
detect-engine:
- rule-reload: true

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure suricata as IPs
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
alerts: yes
flows: all

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```
### Definicje Reguł

[Z dokumentacji:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Reguła/podpis składa się z następujących elementów:

* **Akcja**, określa co się dzieje, gdy reguła pasuje.
* **Nagłówek**, definiuje protokół, adresy IP, porty i kierunek reguły.
* **Opcje reguły**, określają szczegóły reguły.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Dostępne akcje to**

* alert - generuj alert
* pass - zatrzymaj dalszą inspekcję pakietu
* **drop** - odrzuć pakiet i wygeneruj alert
* **reject** - wyślij pakiet RST/ICMP unreachable do nadawcy pasującego pakietu.
* rejectsrc - to samo co _reject_
* rejectdst - wyślij pakiet RST/ICMP error do odbiorcy pasującego pakietu.
* rejectboth - wyślij pakiety RST/ICMP error do obu stron rozmowy.

#### **Protokoły**

* tcp (dla ruchu tcp)
* udp
* icmp
* ip (ip oznacza 'wszystko' lub 'dowolne')
* _protokoły warstwy 7_: http, ftp, tls, smb, dns, ssh... (więcej w [**dokumentacji**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Adresy źródłowe i docelowe

Obsługuje zakresy adresów IP, negacje i listy adresów:

| Przykład                        | Znaczenie                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Każdy adres IP oprócz 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]           | Każdy adres IP oprócz 1.1.1.1 i 1.1.1.2 |
| $HOME\_NET                     | Twój ustawiony HOME\_NET w yaml        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET i nie HOME\_NET          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 oprócz 10.0.0.5          |

#### Porty źródłowe i docelowe

Obsługuje zakresy portów, negacje i listy portów

| Przykład         | Znaczenie                                |
| --------------- | -------------------------------------- |
| any             | dowolny adres                            |
| \[80, 81, 82]   | port 80, 81 i 82                     |
| \[80: 82]       | Zakres od 80 do 82                  |
| \[1024: ]       | Od 1024 do najwyższego numeru portu |
| !80             | Każdy port oprócz 80                      |
| \[80:100,!99]   | Zakres od 80 do 100, ale bez 99 |
| \[1:80,!\[2,4]] | Zakres od 1 do 80, z wyjątkiem portów 2 i 4  |

#### Kierunek

Możliwe jest wskazanie kierunku zastosowania reguły komunikacji:
```
source -> destination
source <> destination  (both directions)
```
#### Słowa kluczowe

W Suricata dostępnych jest **setki opcji**, które umożliwiają wyszukiwanie **konkretnego pakietu**, jeśli zostanie znalezione coś interesującego, zostanie to tutaj wymienione. Sprawdź [**dokumentację**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html), aby uzyskać więcej informacji!
```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
