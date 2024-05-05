# Mbinu za Udukuzi wa Phishing

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Mbinu

1. Fanya uchunguzi wa mwathiriwa
1. Chagua **kikoa cha mwathiriwa**.
2. Fanya uchunguzi wa wavuti wa msingi **ukitafuta malango ya kuingilia** yanayotumiwa na mwathiriwa na **amua** ni lipi utakalolitumia **kujifanya**.
3. Tumia **OSINT** ku **kupata barua pepe**.
2. Andaa mazingira
1. **Nunua kikoa** utakachotumia kwa tathmini ya udukuzi wa phishing
2. **Sanidi rekodi zinazohusiana na huduma ya barua pepe** (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS na **gophish**
3. Andaa kampeni
1. Andaa **templeti ya barua pepe**
2. Andaa **ukurasa wa wavuti** wa kuiba maelezo ya kuingia
4. Anzisha kampeni!

## Jenereta majina ya kikoa yanayofanana au nunua kikoa kilichoaminika

### Mbinu za Kubadilisha Jina la Kikoa

* **Neno muhimu**: Jina la kikoa **lina** neno muhimu **la kikoa cha asili** (k.m., zelster.com-management.com).
* **Subdomain yenye mstari wa kufungua**: Badilisha **dot kwa mstari wa kufungua** wa subdomain (k.m., www-zelster.com).
* **TLD Mpya**: Kikoa sawa kwa kutumia **TLD mpya** (k.m., zelster.org)
* **Homoglyph**: Inabadilisha herufi katika jina la kikoa na **herufi zinazofanana** (k.m., zelfser.com).
* **Kubadilishana**: Inabadilisha **herufi mbili** ndani ya jina la kikoa (k.m., zelsetr.com).
* **Kuongeza/kuondoa neno**: Inaongeza au kuondoa "s" mwishoni mwa jina la kikoa (k.m., zeltsers.com).
* **Ukosefu**: Inaondoa moja ya herufi kutoka kwa jina la kikoa (k.m., zelser.com).
* **Kurudia**: Inarudia moja ya herufi katika jina la kikoa (k.m., zeltsser.com).
* **Badala**: Kama homoglyph lakini si ya siri. Inabadilisha moja ya herufi katika jina la kikoa, labda na herufi karibu na herufi ya asili kwenye kibodi (k.m, zektser.com).
* **Subdomained**: Ingiza **dot** ndani ya jina la kikoa (k.m., ze.lster.com).
* **Kuingiza**: Inaingiza herufi katika jina la kikoa (k.m., zerltser.com).
* **Kupoteza dot**: Ongeza TLD kwa jina la kikoa. (k.m., zelstercom.com)

**Zana za Kiotomatiki**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Tovuti**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna **uwezekano kwamba moja ya baadhi ya bits zilizohifadhiwa au katika mawasiliano inaweza kubadilishwa moja kwa moja** kutokana na sababu mbalimbali kama miale ya jua, miale kutoka angani, au makosa ya vifaa.

Wakati dhana hii inapotumiwa kwa **ombi za DNS**, inawezekana kwamba **kikoa kilichopokelewa na seva ya DNS** sio sawa na kikoa kilichoulizwa awali.

Kwa mfano, mabadiliko ya bit moja katika kikoa "windows.com" yanaweza kubadilika kuwa "windnws.com."

Wadukuzi wanaweza **kutumia hili kwa kusajili vikoa vingi vya bit-flipping** ambavyo ni sawa na kikoa cha mwathiriwa. Nia yao ni kupeleka watumiaji halali kwenye miundombinu yao wenyewe.

Kwa habari zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Nunua kikoa kilichoaminika

Unaweza kutafuta kwenye [https://www.expireddomains.net/](https://www.expireddomains.net) kwa kikoa kilichoisha muda ambacho unaweza kutumia.\
Ili kuhakikisha kwamba kikoa kilichoisha muda ambacho unakwenda kununua **tayari kina SEO nzuri** unaweza kutafuta jinsi kilivyoainishwa katika:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Kugundua Barua pepe

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% bure)
* [https://phonebook.cz/](https://phonebook.cz) (100% bure)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Ili **kugundua barua pepe halali zaidi** au **kuthibitisha zile** ambazo tayari umegundua unaweza kuangalia kama unaweza kuzitumia kwa nguvu za smtp za mwathiriwa. [Jifunze jinsi ya kuthibitisha/kugundua anwani ya barua pepe hapa](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa watumiaji wanatumia **lango la wavuti kufikia barua zao**, unaweza kuangalia ikiwa lina hatari ya kuvunjika kwa **nguvu ya jina la mtumiaji**, na kutumia udhaifu ikiwa inawezekana.

## Kuweka GoPhish

### Usanidi

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na usambaze ndani ya `/opt/gophish` na tekeleza `/opt/gophish/gophish`\
Utapewa nenosiri la mtumiaji wa admin kwenye bandari 3333 kwenye matokeo. Kwa hivyo, fikia bandari hiyo na tumia maelezo hayo kubadilisha nenosiri la admin. Unaweza kuhitaji kufanya pia bandari hiyo iweze kufikika kwa eneo lako:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii unapaswa **tayari kununua kikoa** utakachotumia na lazima kiwe **kinazingatia** kwenye **IP ya VPS** ambapo unasanidi **gophish**.
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
**Usanidi wa Barua pepe**

Anza kwa kufunga: `apt-get install postfix`

Kisha ongeza kikoa kwenye faili zifuatazo:

- **/etc/postfix/virtual\_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual\_regexp**

**Badilisha pia thamani za variables zifuatazo ndani ya /etc/postfix/main.cf**

`myhostname = <kikoa>`\
`mydestination = $myhostname, <kikoa>, localhost.com, localhost`

Hatimaye badilisha faili **`/etc/hostname`** na **`/etc/mailname`** kwa jina lako la kikoa na **anzisha upya VPS yako.**

Sasa, tengeneza **rekodi ya DNS A** ya `mail.<kikoa>` ikionyesha kwa **anwani ya IP** ya VPS na **rekodi ya DNS MX** ikionyesha kwa `mail.<kikoa>`

Sasa jaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Mipangilio ya Gophish**

Acha utekelezaji wa gophish na tuwekeze mazingira yake.\
Badilisha `/opt/gophish/config.json` kuwa yafuatayo (zingatia matumizi ya https):
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
**Sanidi huduma ya gophish**

Ili kuunda huduma ya gophish ili iweze kuanza moja kwa moja na kusimamiwa kama huduma unaweza kuunda faili `/etc/init.d/gophish` na yaliyomo yafuatayo:
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
Maliza kuwezesha huduma na uipime kwa kufanya:
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
## Kuweka mwenyeji wa barua pepe na kikoa

### Subiri & kuwa halali

Kadri kikoa kinavyokuwa cha zamani, ndivyo inavyowezekana kidogo kugunduliwa kama barua taka. Kwa hivyo unapaswa kusubiri muda mrefu iwezekanavyo (angalau wiki 1) kabla ya tathmini ya udukuzi. Zaidi ya hayo, ikiwa unaweka ukurasa kuhusu sekta ya sifa, sifa iliyopatikana itakuwa bora.

Tambua kwamba hata kama unapaswa kusubiri wiki moja, unaweza kumaliza kuweka kila kitu sasa.

### Weka Rekodi ya Reverse DNS (rDNS)

Wekeza rekodi ya rDNS (PTR) ambayo inatatua anwani ya IP ya VPS kwa jina la kikoa.

### Rekodi ya Sera ya Mtumaji (SPF)

Unapaswa **kuweka rekodi ya SPF kwa kikoa kipya**. Ikiwa hujui ni nini rekodi ya SPF [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kuzalisha sera yako ya SPF (tumia anwani ya IP ya mashine ya VPS)

![](<../../.gitbook/assets/image (1037).png>)

Hii ndio yaliyomo yanayopaswa kuwekwa ndani ya rekodi ya TXT ndani ya kikoa:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya Domain-based Message Authentication, Reporting & Conformance (DMARC)

Unapaswa **kuweka rekodi ya DMARC kwa kikoa kipya**. Ikiwa hujui ni nini rekodi ya DMARC [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Unapaswa kuunda rekodi mpya ya DNS TXT ikielekeza jina la mwenyeji `_dmarc.<kikoa>` na yaliyomo yafuatayo:
```bash
v=DMARC1; p=none
```
### Barua pepe Zilizoidhinishwa za DomainKeys (DKIM)

Unapaswa **kuwezesha DKIM kwa kikoa kipya**. Ikiwa hujui ni nini rekodi ya DMARC [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/#dkim).

Mafunzo haya yanategemea: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Unahitaji kuunganisha pamoja thamani zote za B64 ambazo funguo za DKIM zinazalisha:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Jaribu alama yako ya usanidi wa barua pepe

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Tu ufikie ukurasa na tuma barua pepe kwa anwani watakayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kuangalia usanidi wa barua pepe yako** kwa kutuma barua pepe kwenda `check-auth@verifier.port25.com` na **kusoma majibu** (kwa hili utahitaji **kufungua** bandari **25** na kuona majibu kwenye faili _/var/mail/root_ ikiwa utatuma barua pepe kama root).\
Hakikisha unapita vipimo vyote:
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
Unaweza pia kutuma **ujumbe kwa Gmail chini ya udhibiti wako**, na angalia **vichwa vya barua pepe** kwenye sanduku lako la Gmail, `dkim=pass` inapaswa kuwepo katika uga wa kichwa cha barua pepe cha `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Kuondoa kutoka kwenye Orodha ya Spamhouse

Ukurasa [www.mail-tester.com](https://www.mail-tester.com) unaweza kukujulisha ikiwa kikoa chako kimezuiliwa na spamhouse. Unaweza kuomba kikoa/IP chako kuondolewa kwenye: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondoa kutoka kwenye Orodha ya Microsoft

Unaweza kuomba kikoa/IP chako kuondolewa kwenye [https://sender.office.com/](https://sender.office.com).

## Unda na Anzisha Kampeni ya GoPhish

### Profaili ya Kutuma

* Weka **jina la kutambua** profaili ya mtumaji
* Amua kutoka kwenye akaunti gani utatuma barua pepe za udukuzi. Mapendekezo: _noreply, support, servicedesk, salesforce..._
* Unaweza kuacha bila kujaza jina la mtumiaji na nywila, lakini hakikisha kuchagua Ignore Certificate Errors

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

{% hint style="info" %}
Inapendekezwa kutumia "**Tuma Barua pepe ya Majaribio**" kufanya majaribio ya kuhakikisha kuwa kila kitu kinafanya kazi.\
Ningependekeza **kutuma barua pepe za majaribio kwa anwani za barua pepe za 10min** ili kuepuka kuwekwa kwenye orodha nyeusi wakati wa majaribio.
{% endhint %}

### Kiolezo cha Barua pepe

* Weka **jina la kutambua** kwenye kiolezo
* Kisha andika **mada** (siyo kitu cha kushangaza, kitu unachoweza kutarajia kusoma kwenye barua pepe ya kawaida)
* Hakikisha umechagua "**Ongeza Picha ya Kufuatilia**"
* Andika **kiolezo cha barua pepe** (unaweza kutumia mabadiliko kama kwenye mfano ufuatao):
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
Tafadhali kumbuka kwamba **ili kuongeza uaminifu wa barua pepe**, ni vyema kutumia saini fulani kutoka kwa barua pepe ya mteja. Mapendekezo:

* Tuma barua pepe kwa **anwani isiyopo** na angalia kama jibu lina saini yoyote.
* Tafuta **barua pepe za umma** kama info@ex.com au press@ex.com au public@ex.com kisha watume barua pepe na subiri jibu.
* Jaribu kuwasiliana na **baadhi ya barua pepe halali zilizogunduliwa** kisha subiri jibu.

![](<../../.gitbook/assets/image (80).png>)

{% hint style="info" %}
Kiolesura cha Barua pepe pia kuruhusu ku **ambatanisha faili za kutuma**. Ikiwa ungependa kuiba changamoto za NTLM kwa kutumia faili/nyaraka zilizoundwa maalum [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Ukurasa wa Kutua

* Andika **jina**
* **Andika msimbo wa HTML** wa ukurasa wa wavuti. Kumbuka unaweza **kuagiza** kurasa za wavuti.
* Weka alama **Capture Submitted Data** na **Capture Passwords**
* Weka **urejeshaji**

![](<../../.gitbook/assets/image (826).png>)

{% hint style="info" %}
Kawaida utahitaji kurekebisha msimbo wa HTML wa ukurasa na kufanya majaribio kwa eneo la ndani (labda kwa kutumia seva ya Apache) **mpaka upendezwe na matokeo.** Kisha, andika msimbo huo wa HTML kwenye sanduku.\
Kumbuka ikiwa unahitaji **kutumia rasilimali za tuli** kwa HTML (labda kurasa za CSS na JS) unaweza kuziokoa katika _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kutoka _**/static/\<jina la faili>**_
{% endhint %}

{% hint style="info" %}
Kwa urejeshaji unaweza **kuwaongoza watumiaji kwenye ukurasa wa wavuti kuu halali** ya muathiriwa, au kuwaongoza kwenye _/static/migration.html_ kwa mfano, weka **gurudumu linalozunguka (**[**https://loading.io/**](https://loading.io)**) kwa sekunde 5 kisha onyesha kuwa mchakato ulikuwa wa mafanikio**.
{% endhint %}

### Watumiaji & Vikundi

* Weka jina
* **Agiza data** (kumbuka ili kutumia kiolezo kwa mfano unahitaji jina la kwanza, jina la mwisho na anwani ya barua pepe ya kila mtumiaji)

![](<../../.gitbook/assets/image (163).png>)

### Kampeni

Hatimaye, tengeneza kampeni kwa kuchagua jina, kiolezo cha barua pepe, ukurasa wa kutua, URL, wasifu wa kutuma na kikundi. Kumbuka URL itakuwa kiungo kinachotumwa kwa waathiriwa

Kumbuka kwamba **Wasifu wa Kutuma huruhusu kutuma barua pepe ya majaribio kuona jinsi barua pepe ya ujanja ya mwisho itakavyoonekana**:

![](<../../.gitbook/assets/image (192).png>)

{% hint style="info" %}
Ningependekeza **kutuma barua pepe za majaribio kwa anwani za barua pepe za dakika 10** ili kuepuka kuwekwa kwenye orodha nyeusi wakati wa majaribio.
{% endhint %}

Baada ya kila kitu kuwa tayari, zindua kampeni!

## Kujirudia wa Tovuti

Ikiwa kwa sababu yoyote unataka kujirudia tovuti angalia ukurasa ufuatao:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Nyaraka na Faili Zenye Backdoor

Katika tathmini za ujanja (hasa kwa Timu Nyekundu) unaweza pia **kutuma faili zenye backdoor** (labda C2 au kitu kitakachosababisha uwakilishi).\
Angalia ukurasa ufuatao kwa mifano:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Ujanja wa MFA

### Kupitia Proxy MitM

Shambulio lililopita ni la busara kwani unafanya tovuti halisi na kukusanya habari iliyowekwa na mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hajaweka nenosiri sahihi au ikiwa programu uliyoiga imeundwa na 2FA, **habari hii haitakuruhusu kujifanya kuwa mtumiaji aliyechezwa**.

Hapo ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinavyofaa. Zana hizi zitaruhusu kuzalisha shambulio kama MitM. Kimsingi, mashambulio hufanya kazi kama ifuatavyo:

1. Wewe **unajifanya kuwa fomu ya kuingia** kwenye wavuti halisi.
2. Mtumiaji **anatuma** maelezo yake ya **kitambulisho** kwenye ukurasa wako bandia na zana hiyo inayatuma kwenye wavuti halisi, **ikiangalia ikiwa kitambulisho kinafanya kazi**.
3. Ikiwa akaunti imeundwa na **2FA**, ukurasa wa MitM utauliza hilo na mara tu **mtumiaji atakapoingiza** litatuma kwenye wavuti halisi.
4. Mara tu mtumiaji amethibitishwa wewe (kama mshambuliaji) utakuwa umekamata **kitambulisho, 2FA, kuki na habari yoyote** ya kila mwingiliano wako wakati zana inatekeleza MitM.

### Kupitia VNC

Kipi kama badala ya **kutuma mhanga kwenye ukurasa mbaya** unaofanana na wa awali, unampeleka kwenye **kikao cha VNC na kivinjari kilichounganishwa na wavuti halisi**? Utaweza kuona anachofanya, kuiba nenosiri, MFA iliyotumiwa, vidakuzi...\
Unaweza kufanya hivi na [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Kugundua Uchunguzi

Kwa dhahiri moja ya njia bora ya kujua ikiwa umegunduliwa ni **kutafuta kikoa chako kwenye orodha nyeusi**. Ikiwa inaonekana kwenye orodha, kwa njia fulani kikoa chako kiligunduliwa kuwa shuki.\
Njia rahisi ya kuangalia ikiwa kikoa chako kinaonekana kwenye orodha yoyote nyeusi ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Hata hivyo, kuna njia nyingine za kujua ikiwa muathiriwa **anaangalia kwa uangalifu shughuli za ujanja wa shaka** kama ilivyoelezwa katika:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Unaweza **kununua kikoa chenye jina linalofanana sana** na kikoa cha muathiriwa **na/au kuzalisha cheti** kwa **subdomain** ya kikoa kinachodhibitiwa na wewe **kikiwa na** neno muhimu la kikoa cha muathiriwa. Ikiwa **muathiriwa** atafanya aina yoyote ya **mwingiliano wa DNS au HTTP** nao, utajua kuwa **anaangalia** kwa makini vikoa vya shaka na utahitaji kuwa na siri sana.

### Tathmini Ujanja

Tumia [**Phishious** ](https://github.com/Rices/Phishious)kutathmini ikiwa barua pepe yako itamalizikia kwenye folda ya taka au ikiwa itazuiliwa au itafanikiwa.

## Marejeo

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
