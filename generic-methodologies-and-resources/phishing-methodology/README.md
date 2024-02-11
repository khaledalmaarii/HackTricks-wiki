# Phishing Metodologie

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Metodologie

1. Verken die slagoffer
1. Kies die **slagoffer-domein**.
2. Voer 'n paar basiese webondersoeke uit deur te soek na aanmeldingsportale wat deur die slagoffer gebruik word en **besluit** watter een jy sal **impersoneer**.
3. Gebruik 'n bietjie **OSINT** om e-posse te **vind**.
2. Berei die omgewing voor
1. **Koop die domein** wat jy gaan gebruik vir die hengel-assessering
2. **Konfigureer die e-posdiens** verwante rekords (SPF, DMARC, DKIM, rDNS)
3. Konfigureer die VPS met **gophish**
3. Berei die veldtog voor
1. Berei die **e-pos-sjabloon** voor
2. Berei die **webbladsy** voor om die geloofsbriewe te steel
4. Begin die veldtog!

## Genereer soortgelyke domeinname of koop 'n betroubare domein

### Tegnieke vir die variasie van domeinname

* **Sleutelwoord**: Die domeinnaam **bevat** 'n belangrike **sleutelwoord** van die oorspronklike domein (bv. zelster.com-management.com).
* **Gehypeniseerde subdomein**: Verander die **punt vir 'n strepie** van 'n subdomein (bv. www-zelster.com).
* **Nuwe TLD**: Dieselfde domein met 'n **nuwe TLD** (bv. zelster.org)
* **Homoglyf**: Dit **vervang** 'n letter in die domeinnaam met **letters wat soortgelyk lyk** (bv. zelfser.com).
* **Omruiling**: Dit **ruil twee letters** binne die domeinnaam om (bv. zelster.com).
* **Enkelvoud/Meervoud**: Voeg of verwyder "s" aan die einde van die domeinnaam (bv. zeltsers.com).
* **Weglating**: Dit **verwyder een** van die letters uit die domeinnaam (bv. zelser.com).
* **Herhaling**: Dit **herhaal een** van die letters in die domeinnaam (bv. zeltsser.com).
* **Vervanging**: Soos homoglyf, maar minder sluipend. Dit vervang een van die letters in die domeinnaam, miskien met 'n letter in die nabyheid van die oorspronklike letter op die sleutelbord (bv. zektser.com).
* **Subdomein**: Voeg 'n **punt** in die domeinnaam in (bv. ze.lster.com).
* **Invoeging**: Dit **voeg 'n letter** by die domeinnaam in (bv. zerltser.com).
* **Ontbrekende punt**: Voeg die TLD by die domeinnaam. (bv. zelstercom.com)

**Outomatiese hulpmiddels**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webwerwe**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Daar is 'n **moontlikheid dat een van die bits wat gestoor of in kommunikasie is, outomaties omgeskakel kan word** as gevolg van verskeie faktore soos sonvlamme, kosmiese strale of hardewarefoute.

Wanneer hierdie konsep **toegepas word op DNS-versoeke**, is dit moontlik dat die **domein wat deur die DNS-bediener ontvang word**, nie dieselfde is as die aanvanklike gevraagde domein nie.

Byvoorbeeld, 'n enkele bit-wysiging in die domein "windows.com" kan dit verander na "windnws.com."

Aanvallers kan hiervan **profiteer deur verskeie bit-flipping-domeine** te registreer wat soortgelyk is aan die slagoffer se domein. Hulle bedoeling is om legitieme gebruikers na hul eie infrastruktuur om te lei.

Vir meer inligting, lees [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Koop 'n betroubare domein

Jy kan soek na 'n vervalde domein wat jy kan gebruik by [https://www.expireddomains.net/](https://www.expireddomains.net).\
Om seker te maak dat die vervalde domein wat jy gaan koop **reeds 'n goeie SEO het**, kan jy nagaan hoe dit gekategoriseer word in:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Ontdek e-posse

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% gratis)
* [https://phonebook.cz/](https://phonebook.cz) (100% gratis)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Om meer geldige e-posse te **ontdek** of die een wat jy reeds ontdek het, te **verifieer**, kan jy kyk of jy hul smtp-bedieners kan brute force. [Leer hoe om e-posadres te verifieer/ontdek hier](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Moenie ook vergeet dat as gebruikers **enige webportaal gebruik om by hul e-posse te kom**, jy kan nagaan of dit vatbaar is vir **gebruikersnaam-brute force**, en die kwesbaarheid uitbuit indien moontlik.

## Konfigurering van GoPhish

### Installasie

Jy kan dit aflaai vanaf [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Laai dit af en dekomprimeer dit binne `/opt/gophish` en voer `/opt/gophish/gophish` uit\
Jy sal 'n wagwoord vir die admin-gebruiker kry op poort 3333 in die uitset. Toegang daardie poort en gebruik daardie geloofsbriewe om die admin-wagwoord te verander. Jy mag dalk daardie poort na plaaslike toe moet skuif:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfigurasie

**TLS-sertifikaatkonfigurasie**

Voordat hierdie stap geneem word, moet jy die domein wat jy gaan gebruik, **reeds gekoop** het en dit moet na die **IP van die VPS** waar jy **gophish** konfigureer, **verwys**.
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

Begin deur te installeer: `apt-get install postfix`

Voeg dan die domein by die volgende lêers:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Verander ook die waardes van die volgende veranderlikes binne /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Verander uiteindelik die lêers **`/etc/hostname`** en **`/etc/mailname`** na jou domeinnaam en **herlaai jou VPS.**

Skep nou 'n **DNS A-rekord** van `mail.<domain>` wat na die **ip-adres** van die VPS wys en 'n **DNS MX-rekord** wat na `mail.<domain>` wys.

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
**Stel gophish-diens op**

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
Voltooi die konfigurasie van die diens en toets dit deur die volgende stappe te volg:
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
## Konfigureer posdiens en domein

### Wag en wees legitiem

Hoe ouer 'n domein is, hoe minder waarskynlik is dit dat dit as spam gevang sal word. Jy moet dus so lank as moontlik wag (ten minste 1 week) voordat jy die phising-assessering doen. Verder sal die reputasie wat verkry word beter wees as jy 'n bladsy oor 'n reputasievolle sektor plaas.

Let daarop dat selfs al moet jy 'n week wag, jy alles nou kan konfigureer.

### Konfigureer omgekeerde DNS (rDNS) rekord

Stel 'n rDNS (PTR) rekord in wat die IP-adres van die VPS na die domeinnaam oplos.

### Sender Policy Framework (SPF) Rekord

Jy moet **'n SPF-rekord vir die nuwe domein konfigureer**. As jy nie weet wat 'n SPF-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/#spf).

Jy kan [https://www.spfwizard.net/](https://www.spfwizard.net) gebruik om jou SPF-beleid te genereer (gebruik die IP van die VPS-masjien)

![](<../../.gitbook/assets/image (388).png>)

Dit is die inhoud wat binne 'n TXT-rekord in die domein ingestel moet word:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domeingebaseerde Berigverifikasie, Rapportering en Nakoming (DMARC) Rekord

Jy moet 'n DMARC-rekord **konfigureer vir die nuwe domein**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Jy moet 'n nuwe DNS TXT-rekord skep wat die gasheernaam `_dmarc.<domein>` na die volgende inhoud verwys:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Jy moet 'n DKIM vir die nuwe domein **konfigureer**. As jy nie weet wat 'n DMARC-rekord is nie, [**lees hierdie bladsy**](../../network-services-pentesting/pentesting-smtp/#dkim).

Hierdie handleiding is gebaseer op: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Jy moet beide B64-waardes wat die DKIM-sleutel genereer, saamvoeg:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Toets jou e-pos konfigurasie telling

Jy kan dit doen deur gebruik te maak van [https://www.mail-tester.com/](https://www.mail-tester.com)\
Net toegang tot die bladsy en stuur 'n e-pos na die adres wat hulle aan jou gee:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Jy kan ook **jou e-pos konfigurasie nagaan** deur 'n e-pos te stuur na `check-auth@verifier.port25.com` en **die antwoord te lees** (hiervoor sal jy die poort **25** moet **oopmaak** en die antwoord in die lêer _/var/mail/root_ sien as jy die e-pos as root stuur).\
Maak seker dat jy slaag vir al die toetse:
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
Jy kan ook 'n **boodskap na 'n Gmail onder jou beheer** stuur en die **e-pos se koppe** in jou Gmail-inboks nagaan, `dkim=pass` moet teenwoordig wees in die `Authentication-Results` kopvel.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Verwydering van Spamhouse Blacklist

Die bladsy [www.mail-tester.com](www.mail-tester.com) kan aandui of jou domein deur Spamhouse geblokkeer word. Jy kan versoek dat jou domein/IP verwyder word by: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Verwydering van Microsoft Blacklist

Jy kan versoek dat jou domein/IP verwyder word by [https://sender.office.com/](https://sender.office.com).

## Skep & Lanseer GoPhish-veldtog

### Verstuurprofiel

* Stel 'n **naam in om** die verstuurprofiel te identifiseer
* Besluit van watter rekening jy die phising-e-posse gaan stuur. Voorstelle: _noreply, support, servicedesk, salesforce..._
* Jy kan die gebruikersnaam en wagwoord leeg laat, maar maak seker om die "Ignore Certificate Errors" te merk

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Dit word aanbeveel om die "**Send Test Email**" funksionaliteit te gebruik om te toets of alles werk.\
Ek sal aanbeveel om die toets-e-posse na 10min-posadressse te stuur om te voorkom dat jy op die swartlys beland terwyl jy toetse doen.
{% endhint %}

### E-pos-sjabloon

* Stel 'n **naam in om** die sjabloon te identifiseer
* Skryf dan 'n **onderwerp** (niks vreemds nie, net iets wat jy in 'n gewone e-pos sou verwag om te lees)
* Maak seker dat jy "**Add Tracking Image**" gemerk het
* Skryf die **e-pos-sjabloon** (jy kan veranderlikes gebruik soos in die volgende voorbeeld):
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
Let daarop dat **om die geloofwaardigheid van die e-pos te verhoog**, dit aanbeveel word om 'n handtekening van 'n e-pos van die kliënt te gebruik. Voorstelle:

* Stuur 'n e-pos na 'n **nie-bestaande adres** en kyk of die reaksie enige handtekening het.
* Soek na **openbare e-posse** soos info@ex.com of press@ex.com of public@ex.com en stuur hulle 'n e-pos en wag vir die reaksie.
* Probeer om **'n geldige ontdekte** e-pos te kontak en wag vir die reaksie.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Die E-pos Templaat maak dit ook moontlik om **lêers aan te heg om te stuur**. As jy ook NTLM-uitdagings wil steel deur van spesiaal vervaardigde lêers/dokumente gebruik te maak, [lees hierdie bladsy](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Landingsbladsy

* Skryf 'n **naam**
* **Skryf die HTML-kode** van die webbladsy. Let daarop dat jy webbladsye kan **importe**.
* Merk **Vasgevang Data** en **Vasgevang Wagwoorde**
* Stel 'n **omleiding** in

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Gewoonlik sal jy die HTML-kode van die bladsy moet wysig en 'n paar toetse plaaslik doen (dalk deur van 'n Apache-bediener gebruik te maak) **tot jy tevrede is met die resultate**. Skryf dan daardie HTML-kode in die blokkie.\
Let daarop dat as jy **van statiese hulpbronne** vir die HTML gebruik (dalk van CSS- en JS-bladsye), jy hulle kan stoor in _**/opt/gophish/static/endpoint**_ en dan daarna toegang daartoe kan verkry vanaf _**/static/\<lêernaam>**_
{% endhint %}

{% hint style="info" %}
Vir die omleiding kan jy die gebruikers **omlei na die regmatige hoofwebbladsy** van die slagoffer, of hulle omlei na _/static/migration.html_ byvoorbeeld, 'n **draaiwiel** ([**https://loading.io/**](https://loading.io)) vir 5 sekondes plaas en dan aandui dat die proses suksesvol was.
{% endhint %}

### Gebruikers & Groepe

* Stel 'n naam in
* **Importeer die data** (let daarop dat jy die voornaam, van en e-posadres van elke gebruiker nodig het om die templaat vir die voorbeeld te gebruik)

![](<../../.gitbook/assets/image (395).png>)

### Veldtog

Skep uiteindelik 'n veldtog deur 'n naam, die e-pos templaat, die landingsbladsy, die URL, die stuurprofiel en die groep te kies. Let daarop dat die URL die skakel is wat na die slagoffers gestuur word.

Let daarop dat die **Stuurprofiel toelaat om 'n toets-e-pos te stuur om te sien hoe die uiteindelike phising-e-pos lyk**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Ek sal aanbeveel om die toets-e-posse na 10min-e-posadresse te stuur om te verhoed dat jy deur toetse op 'n swartlys geplaas word.
{% endhint %}

Sodra alles gereed is, begin die veldtog!

## Webwerfkloning

As jy om enige rede die webwerf wil kloon, kyk na die volgende bladsy:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Terugdeur-dokumente & -lêers

In sommige phising-assesserings (veral vir Rooi Spanne) wil jy ook **lêers stuur wat 'n sekere soort terugdeur bevat** (dalk 'n C2 of dalk net iets wat 'n outentifikasie sal inisieer).\
Kyk na die volgende bladsy vir voorbeelde:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phising MFA

### Via Proxy MitM

Die vorige aanval is redelik slim omdat jy 'n regte webwerf naboots en die inligting wat deur die gebruiker ingevoer is, versamel. Ongelukkig, as die gebruiker nie die korrekte wagwoord ingevoer het nie of as die toepassing wat jy nageboots het, met 2FA gekonfigureer is, **sal hierdie inligting jou nie in staat stel om die bedriegde gebruiker na te boots nie**.

Dit is waar hulpmiddels soos [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) en [**muraena**](https://github.com/muraenateam/muraena) nuttig is. Hierdie hulpmiddel sal jou in staat stel om 'n MitM-soort aanval te genereer. Die aanval werk basies soos volg:

1. Jy **boots die aanmeldingsvorm** van die regte webbladsy na.
2. Die gebruiker **stuur** sy **inskrywings** na jou valse bladsy en die hulpmiddel stuur dit na die regte webbladsy, **deur te kyk of die inligting werk**.
3. As die rekening met **2FA** gekonfigureer is, sal die MitM-bladsy daarvoor vra en sodra die **gebruiker dit invoer**, sal die hulpmiddel dit na die regte webbladsy stuur.
4. Sodra die gebruiker geïdentifiseer is, sal jy (as aanvaller) die **inskrywings, die 2FA, die koekie en enige inligting** van elke interaksie wat jy tydens die MitM-uitvoer van die hulpmiddel uitvoer, **vasgevang het**.

### Via VNC

Wat as jy die slagoffer in plaas daarvan **na 'n skadelike bladsy stuur** met dieselfde voorkoms as die oorspronklike een, hom na 'n **VNC-sessie met 'n blaaier wat aan die regte webbladsy gekoppel is**, stuur? Jy sal kan sien wat hy doen, die wagwoord steel, die gebruikte MFA, die koekies...\
Jy kan dit doen met [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Die opsporing van die opsporing

Dit is vanselfsprekend een van die beste maniere om te weet of jy gevang is, is om jou domein in swartlyste te soek. As dit gelys word, is jou domein op een of ander manier as verdag geïdentifiseer.\
Een maklike manier om te kyk of jou domein op enige swartlys verskyn, is deur [https://malwareworld.com/](https://malwareworld.com) te gebruik

Daar is egter ander maniere om te weet of die slagoffer **aktief op soek is na verdagte phising-aktiwiteit in die wildernis**, soos verduidelik in:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Jy kan 'n domein **koop met 'n baie soortgelyke naam** as die slagoffer se domein **en/of 'n sertifikaat genereer** vir 'n **subdomein** van 'n domein wat deur jou beheer word **wat die sleutelwoord** van die slagoffer
