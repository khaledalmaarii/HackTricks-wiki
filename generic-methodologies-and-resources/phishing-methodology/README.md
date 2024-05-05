# Hengel Metodologie

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hengeltruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Metodologie

1. Verken die slagoffer
1. Kies die **slagoffer-domein**.
2. Voer 'n paar basiese webversameling uit **op soek na aanmeldingsportale** wat deur die slagoffer gebruik word en **besluit** watter een jy sal **impersoneer**.
3. Gebruik 'n bietjie **OSINT** om **e-posse** te **vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy gaan gebruik vir die hengelassessering
2. **Stel die e-posdiens** verwante rekords in (SPF, DMARC, DKIM, rDNS)
3. Stel die VPS op met **gophish**
3. Berei die veldtog voor
1. Berei die **e-pos-sjabloon** voor
2. Berei die **webbladsy** voor om die geloofsbriewe te steel
4. Lanseer die veldtog!

## Genereer soortgelyke domeinname of koop 'n vertroude domein

### Domeinnaamvariasietegnieke

* **Sleutelwoord**: Die domeinnaam **bevat 'n belangrike sleutelwoord** van die oorspronklike domein (bv., zelster.com-bestuur.com).
* **Gedagteken subdomein**: Verander die **punt vir 'n koppelteken** van 'n subdomein (bv., www-zelster.com).
* **Nuwe TLD**: Dieselfde domein met 'n **nuwe TLD** (bv., zelster.org)
* **Homoglyf**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv., zelfser.com).
* **Transposisie:** Dit **ruil twee letters** binne die domeinnaam (bv., zelsetr.com).
* **Enkelvoudiging/Meervoudiging**: Voeg by of verwyder "s" aan die einde van die domeinnaam (bv., zeltsers.com).
* **Weglating**: Dit **verwyder een** van die letters uit die domeinnaam (bv., zelser.com).
* **Herhaling**: Dit **herhaal een** van die letters in die domeinnaam (bv., zeltsser.com).
* **Vervanging**: Soos homoglyf maar minder slu. Dit vervang een van die letters in die domeinnaam, miskien met 'n letter in die nabyheid van die oorspronklike letter op die sleutelbord (bv., zektser.com).
* **Subdomein**: Voer 'n **punt** binne die domeinnaam in (bv., ze.lster.com).
* **Invoeging**: Dit **voeg 'n letter** by die domeinnaam in (bv., zerltser.com).
* **Ontbrekende punt**: Voeg die TLD by die domeinnaam. (bv., zelstercom.com)

**Outomatiese Gereedskap**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webwerwe**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **moontlikheid dat een van 'n paar bits wat gestoor of in kommunikasie is, outomaties omgeswaai kan word** as gevolg van verskeie faktore soos sonvlae, kosmiese strale, of hardewarefoute.

Wanneer hierdie konsep **toegepas word op DNS-versoeke**, is dit moontlik dat die **domein wat deur die DNS-bediener ontvang word**, nie dieselfde is as die aanvanklike aangevraagde domein nie.

Byvoorbeeld, 'n enkele bit-wysiging in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan hiervan **profiteer deur meervoudige bit-omswaai-domeine te registreer** wat soortgelyk is aan die slagoffer se domein. Hulle beoog om regmatige gebruikers na hul eie infrastruktuur te stuur.

Vir meer inligting lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Koop 'n vertroude domein

Jy kan soek op [https://www.expireddomains.net/](https://www.expireddomains.net) vir 'n vervalde domein wat jy kan gebruik.\
Om seker te maak dat die vervalde domein wat jy gaan koop **reeds 'n goeie SEO het** kan jy nagaan hoe dit gekategoriseer is in:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdek E-posse

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
* [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Om meer geldige e-posse te **ontdek** of die een wat jy reeds ontdek het te **verifieer** kan jy kyk of jy hulle smtp-bedieners van die slagoffer kan kragtig. [Leer hoe om e-posadres te verifieer/ontdek hier](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Moenie vergeet dat as die gebruikers enige webportaal gebruik om by hul e-posse te kom nie, kan jy nagaan of dit vatbaar is vir **gebruikersnaam-bruteforce**, en die kwesbaarheid benut indien moontlik.

## Konfigureer GoPhish

### Installasie

Jy kan dit aflaai van [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en dekomprimeer dit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit\
Jy sal 'n wagwoord vir die admin-gebruiker kry op poort 3333 in die uitset. Toegang tot daardie poort en gebruik daardie geloofsbriewe om die admin-wagwoord te verander. Jy mag dalk daardie poort na plaaslik moet tonnel.
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Opset

**TLS sertifikaat opset**

Voor hierdie stap moet jy **reeds die domein gekoop het** wat jy gaan gebruik en dit moet na die **IP van die VPS** wat jy gebruik vir die opset van **gophish**, **verwys**.
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
**Poskonfigurasie**

Begin met installering: `apt-get install postfix`

Voeg dan die domein by tot die volgende lêers:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Verander uiteindelik die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herlaai jou VPS.**

Skep nou 'n **DNS A-rekord** van `mail.<domain>` wat na die **ip-adres** van die VPS wys en 'n **DNS MX-rekord** wat na `mail.<domain>` wys

Laat ons nou toets om 'n e-pos te stuur:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish konfigurasie**

Stop die uitvoering van gophish en laat ons dit konfigureer.\
Wysig `/opt/gophish/config.json` na die volgende (let op die gebruik van https):
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
**Stel gophish-diens in**

Om die gophish-diens te skep sodat dit outomaties gestart en bestuur kan word as 'n diens, kan jy die lêer `/etc/init.d/gophish` skep met die volgende inhoud:
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
Voltooi die konfigurasie van die diens en kontroleer dit deur die volgende te doen:
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
## Instelling van posdiens en domein

### Wag & wees wettig

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam gevang sal word. Jy moet dus so lank as moontlik wag (ten minste 1 week) voor die hengelassessering. Verder, as jy 'n bladsy oor 'n reputasie-sektor plaas, sal die verkrygte reputasie beter wees.

Let daarop dat selfs al moet jy 'n week wag, kan jy nou alles afkonfigureer.

### Konfigureer Omgekeerde DNS (rDNS) rekord

Stel 'n rDNS (PTR) rekord in wat die IP-adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) Rekord

Jy moet **'n SPF-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n SPF-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP van die VPS-masjien)

![](<../../.gitbook/assets/image (1037).png>)

Dit is die inhoud wat binne 'n TXT-rekord binne die domein ingestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domeingebaseerde Berigverifikasie, Verslagdoening & Ooreenstemming (DMARC) Rekord

Jy moet **'n DMARC-rekord konfigureer vir die nuwe domein**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat na die gasnaam `_dmarc.<domein>` wys met die volgende inhoud:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet **'n DKIM vir die nuwe domein instel**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/#dkim).

Hierdie handleiding is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Jy moet beide B64-waardes wat die DKIM-sleutel genereer, saamvoeg:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Toets jou e-poskonfigurasiescore

Jy kan dit doen deur [https://www.mail-tester.com/](https://www.mail-tester.com) te gebruik\
Net toegang tot die bladsy en stuur 'n e-pos na die adres wat hulle aan jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **jou e-poskonfigurasie nagaan** deur 'n e-pos te stuur na `check-auth@verifier.port25.com` en **die antwoord te lees** (hiervoor moet jy poort **25 oopmaak** en die antwoord sien in die lêer _/var/mail/root_ as jy die e-pos as root stuur).\
Kontroleer dat jy slaag vir al die toetse:
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
Jy kan ook 'n **boodskap stuur na 'n Gmail onder jou beheer**, en die **e-pos se koppe** in jou Gmail-inboks nagaan, `dkim=pass` behoort teenwoordig te wees in die `Authentication-Results` kopvel.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Verwydering van Spamhouse Swartlys

Die bladsy [www.mail-tester.com](https://www.mail-tester.com) kan aandui of jou domein deur spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering van Microsoft Swartlys

Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Lanceer GoPhish-veldtog

### Verstuurprofiel

* Stel 'n **naam in om die** afstuurprofiel te identifiseer
* Besluit van watter rekening jy die hengel-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
* Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker om die Ignore Certificate Errors te kies

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

{% hint style="info" %}
Dit word aanbeveel om die "**Stuur Toets E-pos**" funksionaliteit te gebruik om te toets of alles werk.\
Ek sal aanbeveel om die toets e-posse na 10min posadres te stuur om te verhoed dat jy op 'n swartlys beland terwyl jy toetse doen.
{% endhint %}

### E-pos Templaat

* Stel 'n **naam in om die** templaat te identifiseer
* Skryf dan 'n **onderwerp** (niks vreemds nie, net iets wat jy in 'n gewone e-pos sou verwag om te lees)
* Maak seker jy het "**Voeg Spoorbeeld in**" aangevink
* Skryf die **e-pos templaat** (jy kan veranderlikes gebruik soos in die volgende voorbeeld):
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
Merk op dat **om die geloofwaardigheid van die e-pos te verhoog**, dit aanbeveel word om 'n handtekening van 'n e-pos van die klient te gebruik. Voorstelle:

* Stuur 'n e-pos na 'n **nie-bestaande adres** en kyk of die reaksie enige handtekening het.
* Soek na **openbare e-posse** soos info@ex.com of press@ex.com of public@ex.com en stuur hulle 'n e-pos en wag vir die reaksie.
* Probeer om kontak te maak met **'n geldige ontdekte** e-pos en wag vir die reaksie

![](<../../.gitbook/assets/image (80).png>)

{% hint style="info" %}
Die E-pos Templaat maak dit ook moontlik om **lêers aan te heg om te stuur**. As jy ook NTLM-uitdagings wil steel deur van spesiaal vervaardigde lêers/dokumente gebruik te maak, [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Landingsbladsy

* Skryf 'n **naam**
* **Skryf die HTML-kode** van die webbladsy. Merk op dat jy webbladsye kan **importe**.
* Merk **Vasgevangde Ingesaamde Data** en **Vasgevangde Wagwoorde**
* Stel 'n **herleiding** in

![](<../../.gitbook/assets/image (826).png>)

{% hint style="info" %}
Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en toetse in 'n plaaslike omgewing moet uitvoer (miskien deur 'n Apache-bediener te gebruik) **tot jy tevrede is met die resultate.** Skryf dan daardie HTML-kode in die blokkie.\
Merk op dat as jy **sekere statiese hulpbronne** vir die HTML nodig het (miskien sommige CSS- en JS-bladsye) kan jy hulle stoor in _**/opt/gophish/static/endpoint**_ en dan vanaf _**/static/\<lêernaam>**_ daartoe toegang verkry.
{% endhint %}

{% hint style="info" %}
Vir die herleiding kan jy die gebruikers **herlei na die regte hoofwebbladsy** van die slagoffer, of hulle herlei na _/static/migrasie.html_ byvoorbeeld, sit 'n **draaiende wiel (**[**https://loading.io/**](https://loading.io)**) vir 5 sekondes en dui dan aan dat die proses suksesvol was**.
{% endhint %}

### Gebruikers & Groepe

* Stel 'n naam in
* **Importeer die data** (merk op dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die templaat vir die voorbeeld te gebruik)

![](<../../.gitbook/assets/image (163).png>)

### Veldtog

Skep uiteindelik 'n veldtog deur 'n naam, die e-pos templaat, die landingsbladsy, die URL, die stuurprofiel en die groep te kies. Merk op dat die URL die skakel is wat na die slagoffers gestuur sal word

Merk op dat die **Stuurprofiel toelaat om 'n toets-e-pos te stuur om te sien hoe die uiteindelike hengel-e-pos lyk**:

![](<../../.gitbook/assets/image (192).png>)

{% hint style="info" %}
Ek sal aanbeveel om die toets-e-posse na 10min-posadres te stuur om te verhoed dat jy op 'n swartlys beland terwyl jy toetse uitvoer.
{% endhint %}

Sodra alles gereed is, begin net die veldtog!

## Webwerfkloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende bladsy:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Agterdeur Dokumente & Lêers

In sommige hengelassesseringe (hoofsaaklik vir Rooi Spanne) wil jy ook **lêers stuur wat 'n soort agterdeur bevat** (miskien 'n C2 of dalk net iets wat 'n outentifikasie sal inisieer).\
Kyk na die volgende bladsy vir voorbeelde:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Hengel MFA

### Via Proksi MitM

Die vorige aanval is redelik slim omdat jy 'n werklike webwerf namaak en die inligting wat deur die gebruiker ingevoer is, insamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie of as die aansoek wat jy nageboots het, met 2FA gekonfigureer is, **sal hierdie inligting jou nie toelaat om die bedriegde gebruiker te impersoneer nie**.

Dit is waar gereedskap soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie gereedskap sal jou in staat stel om 'n MitM-aanval te genereer. Die aanvalle werk basies so:

1. Jy **impersoneer die aanmeldingsvorm** van die werklike webbladsy.
2. Die gebruiker **stuur** sy **legitimasie** na jou valse bladsy en die gereedskap stuur dit na die werklike webbladsy, **om te kyk of die legitimasie werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-bladsy daarvoor vra en sodra die **gebruiker dit invoer**, sal die gereedskap dit na die werklike webbladsy stuur.
4. Sodra die gebruiker geïdentifiseer is, sal jy (as aanvaller) die legitimasie, die 2FA, die koekie en enige inligting **van elke interaksie wat jy terwyl die gereedskap 'n MitM uitvoer, vasgevang het**.

### Via VNC

Wat as jy in plaas daarvan die slagoffer na 'n skadelike bladsy met dieselfde voorkoms as die oorspronklike een stuur, hom na 'n **VNC-sessie met 'n blaaier wat aan die werklike webbladsy gekoppel is**, stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die gebruikte MFA, die koekies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Die opsporing van die opsporing

Dit is vanselfsprekend een van die beste maniere om te weet of jy betraps is, is om **jou domein binne swartlyste te soek**. As dit gelys word, is jou domein op een of ander manier as verdag geïdentifiseer.\
Een maklike manier om te kontroleer of jou domein op enige swartlys verskyn, is om [https://malwareworld.com/](https://malwareworld.com) te gebruik

Daar is egter ander maniere om te weet of die slagoffer **aktief op soek is na verdagte hengelaktiwiteit in die wildernis** soos verduidelik in:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Jy kan **'n domein met 'n baie soortgelyke naam koop** as die slagoffer se domein **en/of 'n sertifikaat genereer** vir 'n **subdomein** van 'n domein wat deur jou beheer word **wat die sleutelwoord** van die slagoffer se domein bevat. As die **slagoffer** enige soort **DNS- of HTTP-interaksie** daarmee uitvoer, sal jy weet dat **hy aktief op soek is** na verdagte domeine en jy moet baie versigtig wees.

### Evalueer die hengel

Gebruik [**Phishious** ](https://github.com/Rices/Phishious)om te evalueer of jou e-pos in die spamvouer gaan beland of geblokkeer of suksesvol gaan wees.

## Verwysings

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien hoe jou **maatskappy geadverteer word in HackTricks** of **HackTricks in PDF aflaai**, kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hakerstruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
