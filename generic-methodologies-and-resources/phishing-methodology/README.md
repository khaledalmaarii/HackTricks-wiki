# Metodologija za ribarenje (Phishing)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Metodologija

1. Izviđanje žrtve
1. Izaberite **domen žrtve**.
2. Izvršite osnovnu web enumeraciju **tražeći login portale** koje koristi žrtva i **odlučite** koji ćete **prevariti**.
3. Koristite neke **OSINT** metode da **pronađete email adrese**.
2. Priprema okruženja
1. **Kupite domen** koji ćete koristiti za ribarenje
2. **Konfigurišite email servis** povezane zapise (SPF, DMARC, DKIM, rDNS)
3. Konfigurišite VPS sa **gophish**-om
3. Priprema kampanje
1. Pripremite **šablon email-a**
2. Pripremite **web stranicu** za krađu podataka za prijavu
4. Pokrenite kampanju!

## Generisanje sličnih domena ili kupovina pouzdanog domena

### Tehnike varijacije imena domena

* **Ključna reč**: Domen sadrži važnu **ključnu reč** originalnog domena (npr. zelster.com-management.com).
* **Poddomen sa crticom**: Zamenite **tačku crticom** u poddomenu (npr. www-zelster.com).
* **Novi TLD**: Ista domena koristeći **novi TLD** (npr. zelster.org)
* **Homograft**: Zamenjuje slovo u imenu domena sa slovima koja izgledaju slično (npr. zelfser.com).
* **Transpozicija**: Zamenjuje dva slova u imenu domena (npr. zelster.com).
* **Jednina/Množina**: Dodaje ili uklanja "s" na kraju imena domena (npr. zeltsers.com).
* **Izostavljanje**: Uklanja jedno slovo iz imena domena (npr. zelser.com).
* **Ponavljanje**: Ponavlja jedno slovo u imenu domena (npr. zeltsser.com).
* **Zamena**: Slično homograftu, ali manje prikriveno. Zamenjuje jedno slovo u imenu domena, možda slovom koje je blizu originalnog slova na tastaturi (npr. zektser.com).
* **Poddomen**: Uvodi **tačku** unutar imena domena (npr. ze.lster.com).
* **Umetanje**: Umeće slovo u ime domena (npr. zerltser.com).
* **Nedostajuća tačka**: Dodaje TLD domenu (npr. zelstercom.com)

**Automatski alati**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Veb stranice**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Postoji **mogućnost da se jedan od nekih bitova koji se čuvaju ili komuniciraju automatski promeni** zbog različitih faktora kao što su solarni bljeskovi, kosmički zraci ili greške hardvera.

Kada se ovaj koncept **primeni na DNS zahteve**, moguće je da **domen koji DNS server prima** nije isti kao domen koji je inicijalno zahtevan.

Na primer, jedna promena bita u domenu "windows.com" može ga promeniti u "windnws.com".

Napadači mogu **iskoristiti ovo tako što registruju više domena sa promenjenim bitovima** koji su slični domenu žrtve. Njihova namera je da preusmere legitimne korisnike na svoju infrastrukturu.

Za više informacija pročitajte [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kupovina pouzdanog domena

Možete pretraživati [https://www.expireddomains.net/](https://www.expireddomains.net) za istekli domen koji biste mogli koristiti.\
Da biste bili sigurni da istekli domen koji ćete kupiti **već ima dobar SEO**, možete proveriti kako je kategorizovan na:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Otkrivanje email adresa

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% besplatno)
* [https://phonebook.cz/](https://phonebook.cz) (100% besplatno)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Da biste **otkrili više** validnih email adresa ili **proverili one** koje ste već otkrili, možete proveriti da li možete izvršiti brute-force napad na smtp servere žrtve. [Saznajte kako da proverite/otkrijete email adresu ovde](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Takođe, ne zaboravite da ako korisnici koriste **bilo koji web portal za pristup svojim email-ovima**, možete proveriti da li je ranjiv na **brute-force napad na korisnička imena**, i iskoristiti ranjivost ako je moguće.

## Konfigurisanje GoPhish-a

### Instalacija

Možete preuzeti sa [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Preuzmite i raspakujte ga unutar `/opt/gophish` i izvršite `/opt/gophish/gophish`\
Biće vam dodeljena lozinka za admin korisnika na portu 3333 u izlazu. Stoga, pristupite tom portu i koristite te podatke za promenu lozinke admin korisnika. Možda ćete morati da usmerite taj port na lokalni:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracija

**Konfiguracija TLS sertifikata**

Pre nego što pređete na ovaj korak, trebali biste **već kupiti domen** koji ćete koristiti i on mora biti **usmeren** na **IP adresu VPS-a** na kojem konfigurišete **gophish**.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Konfiguracija e-pošte**

Započnite instalaciju: `apt-get install postfix`

Zatim dodajte domen u sledeće datoteke:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Takođe promenite vrednosti sledećih promenljivih unutar /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na kraju izmenite datoteke **`/etc/hostname`** i **`/etc/mailname`** na ime vašeg domena i **restartujte vaš VPS.**

Sada kreirajte **DNS A zapis** za `mail.<domain>` koji pokazuje na **IP adresu** VPS-a i **DNS MX zapis** koji pokazuje na `mail.<domain>`

Sada testirajmo slanje e-pošte:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracija Gophish-a**

Zaustavite izvršavanje Gophish-a i konfigurišite ga.\
Izmenite `/opt/gophish/config.json` na sledeći način (obratite pažnju na korišćenje https):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Konfigurisanje gophish servisa**

Da biste kreirali gophish servis koji se može automatski pokretati i upravljati kao servis, možete kreirati datoteku `/etc/init.d/gophish` sa sledećim sadržajem:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Završite konfiguraciju servisa i proverite je tako što ćete uraditi:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Konfiguracija poštanskog servera i domena

### Sačekajte i budite legitimni

Što je stariji domen, manja je verovatnoća da će biti uhvaćen kao spam. Zato biste trebali sačekati što je duže moguće (barem 1 nedelju) pre nego što započnete procenu phishinga. Takođe, ako postavite stranicu o reputacionom sektoru, reputacija koju ćete dobiti će biti bolja.

Imajte na umu da čak i ako morate čekati nedelju dana, možete završiti konfiguraciju svega sada.

### Konfiguracija Reverse DNS (rDNS) zapisa

Postavite rDNS (PTR) zapis koji rešava IP adresu VPS-a u ime domena.

### SPF (Sender Policy Framework) zapis

**Morate konfigurisati SPF zapis za novi domen**. Ako ne znate šta je SPF zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/#spf).

Možete koristiti [https://www.spfwizard.net/](https://www.spfwizard.net) da generišete svoju SPF politiku (koristite IP adresu VPS mašine)

![](<../../.gitbook/assets/image (388).png>)

Ovo je sadržaj koji treba postaviti unutar TXT zapisa u domenu:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### DMARC zapis zasnovan na domenu za autentifikaciju, izveštavanje i usaglašenost (DMARC)

Morate **konfigurisati DMARC zapis za novu domenu**. Ako ne znate šta je DMARC zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Morate kreirati novi DNS TXT zapis koji upućuje na ime hosta `_dmarc.<domena>` sa sledećim sadržajem:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Morate **konfigurisati DKIM za novu domenu**. Ako ne znate šta je DMARC zapis, [**pročitajte ovu stranicu**](../../network-services-pentesting/pentesting-smtp/#dkim).

Ovaj tutorijal se bazira na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Potrebno je da spojite oba B64 vrednosti koje generiše DKIM ključ:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Testirajte ocenu konfiguracije vaše e-pošte

To možete uraditi koristeći [https://www.mail-tester.com/](https://www.mail-tester.com)\
Jednostavno pristupite stranici i pošaljite e-poštu na adresu koju vam daju:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Možete takođe **proveriti konfiguraciju vaše e-pošte** slanjem e-pošte na `check-auth@verifier.port25.com` i **čitanjem odgovora** (za ovo će vam biti potrebno da **otvorite** port **25** i vidite odgovor u datoteci _/var/mail/root_ ako šaljete e-poštu kao root).\
Proverite da prođete sve testove:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Takođe možete poslati **poruku na Gmail koji je pod vašom kontrolom**, i proveriti **zaglavlja emaila** u svom Gmail inboxu, `dkim=pass` treba da bude prisutan u polju zaglavlja `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Uklanjanje sa Spamhouse crne liste

Stranica [www.mail-tester.com](www.mail-tester.com) može vam pokazati da li je vaš domen blokiran od strane Spamhouse-a. Možete zatražiti uklanjanje vašeg domena/IP adrese na: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Uklanjanje sa Microsoft crne liste

Možete zatražiti uklanjanje vašeg domena/IP adrese na [https://sender.office.com/](https://sender.office.com).

## Kreiranje i pokretanje GoPhish kampanje

### Profil za slanje

* Postavite **ime za identifikaciju** profila pošiljaoca
* Odlučite sa kojeg naloga ćete slati phishing emailove. Predlozi: _noreply, support, servicedesk, salesforce..._
* Možete ostaviti prazno korisničko ime i lozinku, ali se pobrinite da proverite opciju Ignore Certificate Errors

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Preporučuje se korišćenje funkcionalnosti "**Send Test Email**" da biste proverili da li sve radi.\
Preporučujem da **test emailove šaljete na adrese 10min mailova** kako biste izbegli da budete blokirani tokom testiranja.
{% endhint %}

### Email šablon

* Postavite **ime za identifikaciju** šablona
* Zatim napišite **naslov** (ništa čudno, samo nešto što biste očekivali da pročitate u regularnom emailu)
* Proverite da li je označena opcija "**Add Tracking Image**"
* Napišite **email šablon** (možete koristiti promenljive kao u sledećem primeru):
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Napomena da biste **povećali kredibilitet e-pošte**, preporučuje se korišćenje nekog potpisa iz e-pošte klijenta. Predlozi:

* Pošaljite e-poštu na **ne postojeću adresu** i proverite da li odgovor ima neki potpis.
* Potražite **javne e-adrese** poput info@ex.com ili press@ex.com ili public@ex.com i pošaljite im e-poštu i sačekajte odgovor.
* Pokušajte da kontaktirate **neku validnu otkrivenu** e-adresu i sačekajte odgovor.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Predložak e-pošte takođe omogućava **prilaganje datoteka za slanje**. Ako želite da ukradete NTLM izazove koristeći posebno napravljene datoteke/dokumente [pročitajte ovu stranicu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Stranica za sletanje

* Napišite **ime**
* **Napišite HTML kod** veb stranice. Imajte na umu da možete **uvoziti** veb stranice.
* Označite **Capture Submitted Data** i **Capture Passwords**
* Postavite **preusmeravanje**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Obično ćete morati da izmenite HTML kod stranice i izvršite neke testove lokalno (možda koristeći neki Apache server) **dok ne budete zadovoljni rezultatima**. Zatim, napišite taj HTML kod u okviru.\
Imajte na umu da ako trebate **koristiti neke statičke resurse** za HTML (možda neke CSS i JS stranice) možete ih sačuvati u _**/opt/gophish/static/endpoint**_ a zatim im pristupiti putem _**/static/\<filename>**_
{% endhint %}

{% hint style="info" %}
Za preusmeravanje možete **preusmeriti korisnike na legitimnu glavnu veb stranicu** žrtve, ili ih preusmeriti na _/static/migration.html_ na primer, staviti neki **okretajući točak** ([**https://loading.io/**](https://loading.io)) na 5 sekundi, a zatim naznačiti da je proces uspešan.
{% endhint %}

### Korisnici i grupe

* Postavite ime
* **Uvezite podatke** (imajte na umu da za upotrebu predloška za primer trebate ime, prezime i e-adresu svakog korisnika)

![](<../../.gitbook/assets/image (395).png>)

### Kampanja

Na kraju, kreirajte kampanju odabirom imena, predloška e-pošte, stranice za sletanje, URL-a, profila slanja i grupe. Imajte na umu da će URL biti veza poslata žrtvama.

Imajte na umu da **Profil slanja omogućava slanje testne e-pošte da biste videli kako će izgledati konačna phishing e-pošta**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Preporučio bih da **testne e-poruke pošaljete na adrese 10min mailova** kako biste izbegli da budete na crnoj listi tokom testiranja.
{% endhint %}

Kada je sve spremno, samo pokrenite kampanju!

## Kloniranje veb stranica

Ako iz nekog razloga želite klonirati veb stranicu, proverite sledeću stranicu:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Dokumenti i datoteke sa zadnjim vratima

U nekim phishing procenama (uglavnom za Crvene timove) želite takođe **poslati datoteke koje sadrže neku vrstu zadnjeg vrata** (možda C2 ili samo nešto što će pokrenuti autentifikaciju).\
Pogledajte sledeću stranicu za neke primere:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Putem Proxy MitM

Prethodni napad je prilično pametan jer lažirate pravu veb stranicu i prikupljate informacije koje je korisnik uneo. Nažalost, ako korisnik nije uneo ispravnu lozinku ili ako je aplikacija koju ste lažirali konfigurisana sa 2FA, **ove informacije vam neće omogućiti da se predstavite kao prevareni korisnik**.

Ovde su korisni alati poput [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Ovaj alat će vam omogućiti generisanje napada poput MitM-a. Osnovno, napad funkcioniše na sledeći način:

1. **Predstavljate** obrazac za **prijava** prave veb stranice.
2. Korisnik **šalje** svoje **poverljive podatke** na vašu lažnu stranicu, a alat ih šalje na pravu veb stranicu, **proveravajući da li podaci za prijavu rade**.
3. Ako je nalog konfigurisan sa **2FA**, MitM stranica će to zatražiti, a kada **korisnik unese** 2FA, alat će ga poslati na pravu veb stranicu.
4. Kada se korisnik autentifikuje, vi (kao napadač) ćete **pokupiti poverljive podatke, 2FA, kolačiće i sve informacije** o svakoj interakciji dok alat izvodi MitM.

### Putem VNC-a

Šta ako umesto **slanja žrtve na zlonamernu stranicu** sa istim izgledom kao originalna stranica, pošaljete je na **VNC sesiju sa pregledačem povezanim sa pravom veb stranicom**? Bićete u mogućnosti da vidite šta radi, ukradete lozinku, korišćeni MFA, kolačiće...\
To možete uraditi sa [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Otkrivanje otkrivanja

Očigledno, jedan od najboljih načina da saznate da li ste uhvaćeni je da **pretražite svoju domenu u crnim listama**. Ako se pojavi na listi, nekako je vaša domena otkrivena kao sumnjiva.\
Jednostavan način da proverite da li se vaša domena pojavljuje na bilo kojoj crnoj listi je da koristite [https://malwareworld.com/](https://malwareworld.com)

Međutim, postoje i drugi načini da saznate da li je žrtva **aktivno u potrazi za sumnjivom phishing aktivnošću na internetu**, kako je objašnjeno u:

{% content-ref url="detecting-phising.md" %}
[detecting-ph
