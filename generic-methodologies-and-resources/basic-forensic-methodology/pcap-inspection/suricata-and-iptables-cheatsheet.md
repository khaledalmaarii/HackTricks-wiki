# Suricata & Iptables cheatsheet

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Chains

In iptables, i gruppi di regole noti come chains vengono elaborati in sequenza. Tra questi, tre chains primarie sono presenti universalmente, con altre come NAT che possono essere supportate a seconda delle capacità del sistema.

- **Input Chain**: Utilizzata per gestire il comportamento delle connessioni in ingresso.
- **Forward Chain**: Utilizzata per gestire le connessioni in ingresso che non sono destinate al sistema locale. Questo è tipico per i dispositivi che agiscono come router, dove i dati ricevuti devono essere inoltrati verso una destinazione diversa. Questa chain è rilevante principalmente quando il sistema è coinvolto nel routing, NATing o attività simili.
- **Output Chain**: Dedicata alla regolazione delle connessioni in uscita.

Queste chains garantiscono l'elaborazione ordinata del traffico di rete, consentendo la specifica di regole dettagliate che governano il flusso di dati dentro, attraverso e fuori da un sistema.
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

### Installazione e configurazione

Per installare Suricata, eseguire i seguenti passaggi:

1. Aggiornare il sistema operativo:

```shell
sudo apt update
sudo apt upgrade
```

2. Installare Suricata:

```shell
sudo apt install suricata
```

3. Configurare Suricata:

```shell
sudo nano /etc/suricata/suricata.yaml
```

4. Modificare le seguenti opzioni nel file di configurazione:

```yaml
default-log-dir: /var/log/suricata/
default-rule-path: /etc/suricata/rules/
```

5. Salvare e chiudere il file di configurazione.

### Avviare Suricata

Per avviare Suricata, eseguire il seguente comando:

```shell
sudo suricata -c /etc/suricata/suricata.yaml -i <interfaccia_di_rete>
```

Sostituire `<interfaccia_di_rete>` con l'interfaccia di rete su cui si desidera eseguire la scansione.

### Iptables

#### Abilitare il logging di iptables

Per abilitare il logging di iptables, eseguire il seguente comando:

```shell
sudo iptables -A INPUT -j LOG
```

#### Visualizzare i log di iptables

Per visualizzare i log di iptables, eseguire il seguente comando:

```shell
sudo tail -f /var/log/kern.log
```

#### Pulire le regole di iptables

Per pulire tutte le regole di iptables, eseguire il seguente comando:

```shell
sudo iptables -F
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
### Definizioni delle Regole

[Dalla documentazione:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Una regola/firma consiste nei seguenti elementi:

* L'**azione**, determina cosa succede quando la firma viene trovata corrispondente.
* L'**intestazione**, definisce il protocollo, gli indirizzi IP, le porte e la direzione della regola.
* Le **opzioni della regola**, definiscono i dettagli specifici della regola.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Le azioni valide sono**

* alert - genera un avviso
* pass - interrompe ulteriori ispezioni del pacchetto
* **drop** - elimina il pacchetto e genera un avviso
* **reject** - invia un errore RST/ICMP irraggiungibile al mittente del pacchetto corrispondente.
* rejectsrc - uguale a _reject_
* rejectdst - invia un pacchetto di errore RST/ICMP al destinatario del pacchetto corrispondente.
* rejectboth - invia pacchetti di errore RST/ICMP a entrambi i lati della conversazione.

#### **Protocolli**

* tcp (per il traffico tcp)
* udp
* icmp
* ip (ip sta per 'tutti' o 'qualsiasi')
* _protocolli di livello 7_: http, ftp, tls, smb, dns, ssh... (più informazioni nella [**documentazione**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Indirizzi di origine e destinazione

Supporta intervalli di indirizzi IP, negazioni e elenchi di indirizzi:

| Esempio                        | Significato                                  |
| ------------------------------ | -------------------------------------------- |
| ! 1.1.1.1                      | Ogni indirizzo IP tranne 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]           | Ogni indirizzo IP tranne 1.1.1.1 e 1.1.1.2   |
| $HOME\_NET                     | La tua impostazione di HOME\_NET nel file yaml        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET e non HOME\_NET          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 tranne 10.0.0.5          |

#### Porte di origine e destinazione

Supporta intervalli di porte, negazioni ed elenchi di porte

| Esempio         | Significato                                |
| --------------- | ------------------------------------------ |
| any             | qualsiasi porta                            |
| \[80, 81, 82]   | porta 80, 81 e 82                          |
| \[80: 82]       | Intervallo da 80 a 82                       |
| \[1024: ]       | Da 1024 fino al numero di porta più alto    |
| !80             | Ogni porta tranne 80                        |
| \[80:100,!99]   | Intervallo da 80 a 100 escluso 99           |
| \[1:80,!\[2,4]] | Intervallo da 1 a 80, tranne le porte 2 e 4 |

#### Direzione

È possibile indicare la direzione della regola di comunicazione che viene applicata:
```
source -> destination
source <> destination  (both directions)
```
#### Parole chiave

Ci sono **centinaia di opzioni** disponibili in Suricata per cercare il **pacchetto specifico** che stai cercando, qui verrà menzionato se viene trovato qualcosa di interessante. Consulta la [**documentazione**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) per ulteriori informazioni!
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

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Lavori in una **azienda di sicurezza informatica**? Vuoi vedere la tua **azienda pubblicizzata in HackTricks**? o vuoi avere accesso all'**ultima versione di PEASS o scaricare HackTricks in PDF**? Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* **Unisciti al** [**💬**](https://emojipedia.org/speech-balloon/) [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguimi** su **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR al [repo hacktricks](https://github.com/carlospolop/hacktricks) e al [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
