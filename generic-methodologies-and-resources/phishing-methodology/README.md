# Njia za Udukuzi wa Phishing

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Njia

1. Recon mnyama
1. Chagua **kikoa cha mnyama**.
2. Fanya uchunguzi wa wavuti wa msingi **ukitafuta portali za kuingia** zinazotumiwa na mnyama na **amua** ni ipi uta **jitambulisha**.
3. Tumia **OSINT** ku **pata barua pepe**.
2. Andaa mazingira
1. **Nunua kikoa** utakachotumia kwa tathmini ya udukuzi wa phishing
2. **Sanidi huduma ya barua pepe** inayohusiana (SPF, DMARC, DKIM, rDNS)
3. Sanidi VPS na **gophish**
3. Andaa kampeni
1. Andaa **templeti ya barua pepe**
2. Andaa **ukurasa wa wavuti** wa kuiba vitambulisho
4. Anzisha kampeni!

## Jenga majina ya kikoa yanayofanana au nunua kikoa kilichoaminika

### Mbinu za Kubadilisha Jina la Kikoa

* **Neno kuu**: Jina la kikoa **lina** neno muhimu **la kikoa cha asili** (kwa mfano, zelster.com-management.com).
* **Subdomain yenye mstari**: Badilisha **dot kwa mstari** wa subdomain (kwa mfano, www-zelster.com).
* **TLD Mpya**: Kikoa kimoja kwa kutumia **TLD mpya** (kwa mfano, zelster.org)
* **Homoglyph**: Inabadilisha herufi katika jina la kikoa na herufi zinazoonekana kufanana (kwa mfano, zelfser.com).
* **Kubadilishana**: Inabadilisha herufi mbili ndani ya jina la kikoa (kwa mfano, zelster.com).
* **Umbizo wa Wingi/Umbizo wa Kipekee**: Inaongeza au kuondoa "s" mwishoni mwa jina la kikoa (kwa mfano, zeltsers.com).
* **Ukosefu**: Inaondoa moja ya herufi kutoka kwa jina la kikoa (kwa mfano, zelser.com).
* **Kurudia**: Inarudia moja ya herufi katika jina la kikoa (kwa mfano, zeltsser.com).
* **Badala**: Kama homoglyph lakini haifichiki sana. Inabadilisha moja ya herufi katika jina la kikoa, labda na herufi karibu na herufi ya asili kwenye kibodi (kwa mfano, zektser.com).
* **Subdomained**: Ingiza **dot** ndani ya jina la kikoa (kwa mfano, ze.lster.com).
* **Kuingizwa**: Inaingiza herufi katika jina la kikoa (kwa mfano, zerltser.com).
* **Dot iliyokosekana**: Ongeza TLD kwa jina la kikoa. (kwa mfano, zelstercom.com)

**Zana za Kiotomatiki**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Tovuti**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Kuna **uwezekano kwamba moja ya baadhi ya bits zilizohifadhiwa au katika mawasiliano zinaweza kubadilishwa moja kwa moja** kutokana na sababu mbalimbali kama miale ya jua, miale ya cosmic, au makosa ya vifaa.

Wakati dhana hii inapotumiwa kwa **ombi za DNS**, inawezekana kwamba **kikoa kinachopokelewa na seva ya DNS** sio sawa na kikoa kilichotakiwa awali.

Kwa mfano, mabadiliko ya bit moja katika kikoa "windows.com" yanaweza kubadilisha kuwa "windnws.com."

Wahalifu wanaweza **kutumia hii kwa kusajili vikoa vingi vya bit-flipping** ambavyo ni sawa na kikoa cha mwathirika. Nia yao ni kupelekeza watumiaji halali kwenye miundombinu yao wenyewe.

Kwa habari zaidi soma [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Nunua kikoa kilichoaminika

Unaweza kutafuta [https://www.expireddomains.net/](https://www.expireddomains.net) kwa kikoa kilichoisha ambacho unaweza kutumia.\
Ili kuhakikisha kuwa kikoa kilichoisha ambacho unakwenda kununua **tayari kina SEO nzuri** unaweza kuangalia jinsi kilivyopangwa katika:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Kugundua Barua pepe

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% bure)
* [https://phonebook.cz/](https://phonebook.cz) (100% bure)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Ili **kugundua zaidi** anwani halali za barua pepe au **uthibitishe zile** ambazo tayari umegundua, unaweza kuangalia ikiwa unaweza kuzishambulia seva za smtp za mwathirika kwa nguvu. [Jifunze jinsi ya kuthibitisha/kugundua anwani ya barua pepe hapa](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Zaidi ya hayo, usisahau kwamba ikiwa watumiaji wanatumia **kituo chochote cha wavuti kufikia barua zao**, unaweza kuangalia ikiwa kina hatari ya **kushambuliwa kwa nguvu ya jina la mtumiaji**, na kutumia udhaifu ikiwa inawezekana.

## Kuweka GoPhish

### Usanidi

Unaweza kuipakua kutoka [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pakua na kuchanganua ndani ya `/opt/gophish` na tekeleza `/opt/gophish/gophish`\
Utapewa nenosiri kwa mtumiaji wa admin kwenye bandari 3333 kwenye matokeo. Kwa hivyo, fikia bandari hiyo na tumia sifa hizo kubadilisha nenosiri la admin. Unaweza kuhitaji kufanya mchimbuko wa bandari hiyo kwa local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Usanidi

**Usanidi wa cheti cha TLS**

Kabla ya hatua hii, unapaswa **tayari kununua kikoa** utakachotumia na lazima kiwe **kinawaelekeza** kwenye **IP ya VPS** ambapo unasanidi **gophish**.
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

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Badilisha pia thamani za variables zifuatazo ndani ya /etc/postfix/main.cf**

`myhostname = <kikoa>`\
`mydestination = $myhostname, <kikoa>, localhost.com, localhost`

Hatimaye, badilisha faili za **`/etc/hostname`** na **`/etc/mailname`** kwa jina lako la kikoa na **zima upya VPS yako.**

Sasa, tengeneza **DNS A record** ya `mail.<kikoa>` ikielekeza kwenye **anwani ya IP** ya VPS na **DNS MX** record ikielekeza kwenye `mail.<kikoa>`

Sasa jaribu kutuma barua pepe:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Mazingira ya Gophish**

Acha utekelezaji wa gophish na tufanye mazingira yake.\
Badilisha `/opt/gophish/config.json` kwa yafuatayo (zingatia matumizi ya https):
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

Ili kuunda huduma ya gophish ili iweze kuanza kiotomatiki na kusimamiwa kama huduma, unaweza kuunda faili `/etc/init.d/gophish` na yaliyomo yafuatayo:
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
Maliza kuwezesha huduma na ukague kwa kufanya yafuatayo:
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
## Kuweka mazingira ya seva ya barua pepe na kikoa

### Subiri na kuwa halali

Kadri kikoa kinavyokuwa cha zamani, ndivyo inavyowezekana kidogo kikatambuliwa kama barua taka. Kwa hiyo, unapaswa kusubiri kwa muda mrefu iwezekanavyo (angalau wiki 1) kabla ya tathmini ya udukuzi. Aidha, ikiwa unaweka ukurasa kuhusu sekta yenye sifa nzuri, sifa iliyopatikana itakuwa bora zaidi.

Tambua kwamba hata ikiwa unapaswa kusubiri wiki moja, unaweza kumaliza kuweka kila kitu sasa.

### Weka rekodi ya Reverse DNS (rDNS)

Weka rekodi ya rDNS (PTR) ambayo inatatua anwani ya IP ya VPS kwa jina la kikoa.

### Rekodi ya Sender Policy Framework (SPF)

Unapaswa **kuweka rekodi ya SPF kwa kikoa kipya**. Ikiwa haujui ni nini rekodi ya SPF [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/#spf).

Unaweza kutumia [https://www.spfwizard.net/](https://www.spfwizard.net) kuunda sera yako ya SPF (tumia anwani ya IP ya kifaa cha VPS)

![](<../../.gitbook/assets/image (388).png>)

Hii ndiyo maudhui yanayopaswa kuwekwa ndani ya rekodi ya TXT ndani ya kikoa:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekodi ya Domain-based Message Authentication, Reporting & Conformance (DMARC)

Unapaswa **kuweka rekodi ya DMARC kwa kikoa kipya**. Ikiwa hujui ni nini rekodi ya DMARC [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Unapaswa kuunda rekodi mpya ya DNS TXT inayoelekeza jina la mwenyeji `_dmarc.<kikoa>` na yaliyomo yafuatayo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Unapaswa **kuwezesha DKIM kwa kikoa kipya**. Ikiwa hujui ni nini rekodi ya DMARC [**soma ukurasa huu**](../../network-services-pentesting/pentesting-smtp/#dkim).

Mafunzo haya yanategemea: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Unahitaji kuunganisha pamoja thamani zote mbili za B64 ambazo funguo za DKIM zinazozalisha:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Jaribu alama ya usanidi wa barua pepe yako

Unaweza kufanya hivyo kwa kutumia [https://www.mail-tester.com/](https://www.mail-tester.com)\
Tu ufikie ukurasa na tuma barua pepe kwa anwani wanayokupa:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Unaweza pia **kuchunguza usanidi wa barua pepe yako** kwa kutuma barua pepe kwa `check-auth@verifier.port25.com` na **kusoma majibu** (kwa hili utahitaji **kufungua** bandari **25** na kuona majibu katika faili _/var/mail/root_ ikiwa unatuma barua pepe kama root).\
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
Unaweza pia kutuma **ujumbe kwa Gmail chini ya udhibiti wako**, na angalia **vichwa vya barua pepe** kwenye kisanduku chako cha Gmail, `dkim=pass` inapaswa kuwepo katika uga wa kichwa cha barua pepe ya `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Kuondoa kutoka kwenye Orodha ya Spamhouse

Ukurasa [www.mail-tester.com](www.mail-tester.com) unaweza kukujulisha ikiwa kikoa chako kimezuiliwa na spamhouse. Unaweza kuomba kikoa/IP chako kuondolewa kwenye: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Kuondoa kutoka kwenye Orodha ya Microsoft

Unaweza kuomba kikoa/IP chako kuondolewa kwenye [https://sender.office.com/](https://sender.office.com).

## Kuunda na Kuzindua Kampeni ya GoPhish

### Wasifu wa Kutuma

* Weka **jina la kutambua** wasifu wa mtumaji
* Chagua akaunti gani utatumia kutuma barua pepe za udukuzi. Mapendekezo: _noreply, support, servicedesk, salesforce..._
* Unaweza kuacha jina la mtumiaji na nenosiri tupu, lakini hakikisha kuangalia "Ignore Certificate Errors"

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Inapendekezwa kutumia kazi ya "**Send Test Email**" kuthibitisha kuwa kila kitu kinavyofanya kazi.\
Ningependekeza **kutuma barua pepe za majaribio kwa anwani za barua pepe za dakika 10** ili kuepuka kuwekwa kwenye orodha nyeusi wakati wa majaribio.
{% endhint %}

### Kigezo cha Barua pepe

* Weka **jina la kutambua** kigezo
* Kisha andika **mada** (kitu cha kawaida unachoweza kutarajia kusoma kwenye barua pepe ya kawaida)
* Hakikisha umeweka tiki kwenye "**Ongeza Picha ya Kufuatilia**"
* Andika **kigezo cha barua pepe** (unaweza kutumia pembejeo kama ilivyo kwenye mfano ufuatao):
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
Tafadhali kumbuka kwamba **ili kuongeza uaminifu wa barua pepe**, inashauriwa kutumia saini fulani kutoka kwa barua pepe ya mteja. Mapendekezo:

* Tuma barua pepe kwa **anwani isiyokuwepo** na angalia ikiwa jibu lina saini yoyote.
* Tafuta barua pepe **za umma** kama info@ex.com au press@ex.com au public@ex.com na watume barua pepe na kusubiri jibu.
* Jaribu kuwasiliana na **barua pepe halali iliyogunduliwa** na kusubiri jibu.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Kigezo cha Barua pepe pia kinaruhusu **kuambatanisha faili za kutuma**. Ikiwa ungependa pia kuiba changamoto za NTLM kwa kutumia faili/nyaraka zilizoundwa kwa umakini [soma ukurasa huu](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Ukurasa wa Kutua

* Andika **jina**
* **Andika nambari ya HTML** ya ukurasa wa wavuti. Kumbuka kuwa unaweza **kuagiza** kurasa za wavuti.
* Weka alama kwenye **Kukamata Data Iliyowasilishwa** na **Kukamata Nywila**
* Weka **urejeshaji**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Kawaida utahitaji kurekebisha nambari ya HTML ya ukurasa na kufanya majaribio fulani kwa eneo la ndani (labda kwa kutumia seva ya Apache) **hadi uweze kufurahia matokeo**. Kisha, andika nambari hiyo ya HTML kwenye sanduku.\
Kumbuka kuwa ikiwa unahitaji **kutumia rasilimali za tuli** kwa HTML (labda baadhi ya kurasa za CSS na JS) unaweza kuziokoa katika _**/opt/gophish/static/endpoint**_ na kisha kuzifikia kutoka _**/static/\<filename>**_
{% endhint %}

{% hint style="info" %}
Kwa urejeshaji unaweza **kuwaongoza watumiaji kwenye ukurasa wa wavuti kuu halali** wa mwathirika, au kuwaongoza kwenye _/static/migration.html_ kwa mfano, weka **gurudumu linalozunguka** ([**https://loading.io/**](https://loading.io)**) kwa sekunde 5 na kisha onyesha kuwa mchakato ulikuwa na mafanikio**.
{% endhint %}

### Watumiaji & Vikundi

* Weka jina
* **Ingiza data** (kumbuka kuwa ili kutumia kigezo kwa mfano unahitaji jina la kwanza, jina la mwisho na anwani ya barua pepe ya kila mtumiaji)

![](<../../.gitbook/assets/image (395).png>)

### Kampeni

Hatimaye, tengeneza kampeni kwa kuchagua jina, kigezo cha barua pepe, ukurasa wa kutua, URL, wasifu wa kutuma na kikundi. Kumbuka kuwa URL itakuwa kiunga kinachotumwa kwa waathirika

Kumbuka kuwa **Wasifu wa Kutuma** huruhusu kutuma barua pepe ya majaribio kuona jinsi barua pepe ya udukuzi ya mwisho itakavyoonekana:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Ningependekeza **kutuma barua pepe za majaribio kwa anwani za barua pepe za dakika 10** ili kuepuka kupigwa marufuku wakati wa majaribio.
{% endhint %}

Marafiki kila kitu tayari, zindua kampeni!

## Kujifanya Kuwa Tovuti

Ikiwa kwa sababu yoyote unataka kuiga tovuti angalia ukurasa ufuatao:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Nyaraka na Faili Zenye Mlango wa Nyuma

Katika tathmini fulani za udukuzi (hasa kwa Timu Nyekundu) unataka pia **kutuma faili zinazohusisha aina fulani ya mlango wa nyuma** (labda C2 au kitu ambacho kitazindua uwakiki).\
Angalia ukurasa ufuatao kwa mifano fulani:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Udukuzi wa MFA

### Kupitia Proxy MitM

Shambulio lililopita ni la busara kwani unajifanya kuwa wavuti halisi na kukusanya habari zilizowekwa na mtumiaji. Kwa bahati mbaya, ikiwa mtumiaji hakuingiza nenosiri sahihi au ikiwa programu uliyodanganya imeundwa na MFA, **habari hii haitakuruhusu kujifanya kuwa mtumiaji aliyedanganywa**.

Hapo ndipo zana kama [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) na [**muraena**](https://github.com/muraenateam/muraena) zinavyofaa. Zana hizi zitaruhusu kuzalisha shambulio kama MitM. Kimsingi, shambulio linafanya kazi kama ifuatavyo:

1. Unajifanya kuwa **fomu ya kuingia** ya wavuti halisi.
2. Mtumiaji **anatuma** **vyeti** vyake kwenye ukurasa wako bandia na zana inayatuma kwenye wavuti halisi, **ikiangalia ikiwa vyeti vinafanya kazi**.
3. Ikiwa akaunti imeundwa na **MFA**, ukurasa wa MitM utauliza kwa hilo na mara tu **mtumiaji anapoingiza**, zana itaituma kwenye wavuti halisi.
4. Mara tu mtumiaji anapothibitishwa, wewe (kama mshambuliaji) utakuwa umekamata **vyeti, MFA, kuki na habari yoyote** ya kila mwingiliano wako wakati zana inafanya MitM.

### Kupitia VNC

Je! Ikiwa badala ya **kumtuma mwathirika kwenye ukurasa mbaya** na muonekano sawa na wa asili, unamtuma kwenye **kikao cha VNC na kivinjari kilichounganishwa na wavuti halisi**? Utaweza kuona anachofanya, kuiba nenosiri, MFA iliyotumiwa, kuki...\
Unaweza kufanya hivi na [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Kugundua Udukuzi

Kwa dhahiri njia moja bora ya kujua ikiwa umegunduliwa ni **kutafuta kikoa chako kwenye orodha nyeusi**. Ikiwa inaonekana kwenye orodha, kwa njia fulani kikoa chako kiligunduliwa kuwa shaka.\
Njia rahisi ya kuangalia ikiwa kikoa chako kinaonekana kwenye orodha nyeusi ni kutumia [https://malwareworld.com/](https://malwareworld.com)

Walakini, kuna njia zingine za kujua ikiwa mwathirika anatafuta **shughuli za udukuzi za kushuku** kwenye mtandao k
