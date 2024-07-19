# Active Directory Methodology

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

## Basic overview

**Active Directory** inatumika kama teknolojia ya msingi, ikiwasaidia **wasimamizi wa mtandao** kuunda na kusimamia kwa ufanisi **domeni**, **watumiaji**, na **vitu** ndani ya mtandao. Imeundwa ili kuweza kupanuka, ikirahisisha kupanga idadi kubwa ya watumiaji katika **makundi** na **subgroups** yanayoweza kudhibitiwa, huku ikidhibiti **haki za ufikiaji** katika ngazi mbalimbali.

Muundo wa **Active Directory** unajumuisha tabaka tatu kuu: **domeni**, **miti**, na **misitu**. **Domeni** inajumuisha mkusanyiko wa vitu, kama vile **watumiaji** au **vifaa**, vinavyoshiriki hifadhidata ya pamoja. **Miti** ni makundi ya hizi domeni zilizounganishwa na muundo wa pamoja, na **msitu** unawakilisha mkusanyiko wa miti kadhaa, zilizounganishwa kupitia **uhusiano wa kuaminiana**, zikiforma tabaka la juu zaidi la muundo wa shirika. Haki maalum za **ufikiaji** na **mawasiliano** zinaweza kutolewa katika kila moja ya ngazi hizi.

Mifano muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Inahifadhi taarifa zote zinazohusiana na vitu vya Active Directory.
2. **Object** – Inamaanisha viumbe ndani ya directory, ikiwa ni pamoja na **watumiaji**, **makundi**, au **folda zilizoshirikiwa**.
3. **Domain** – Inatumika kama chombo cha vitu vya directory, ikiwa na uwezo wa domeni nyingi kuishi pamoja ndani ya **msitu**, kila moja ikihifadhi mkusanyiko wake wa vitu.
4. **Tree** – Kundi la domeni zinazoshiriki domain ya mzizi wa pamoja.
5. **Forest** – Kilele cha muundo wa shirika katika Active Directory, kinachojumuisha miti kadhaa zikiwa na **uaminifu** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi wa kati na mawasiliano ndani ya mtandao. Huduma hizi zinajumuisha:

1. **Domain Services** – Inakusanya uhifadhi wa data na kusimamia mwingiliano kati ya **watumiaji** na **domeni**, ikiwa ni pamoja na **uthibitishaji** na **utafutaji**.
2. **Certificate Services** – Inasimamia uundaji, usambazaji, na usimamizi wa **vyeti vya dijitali** salama.
3. **Lightweight Directory Services** – Inasaidia programu zinazotumia directory kupitia **protokali ya LDAP**.
4. **Directory Federation Services** – Inatoa uwezo wa **kuingia mara moja** kuthibitisha watumiaji katika programu nyingi za wavuti katika kikao kimoja.
5. **Rights Management** – Inasaidia kulinda mali ya hakimiliki kwa kudhibiti usambazaji na matumizi yake bila idhini.
6. **DNS Service** – Muhimu kwa kutatua **majina ya domeni**.

Kwa maelezo zaidi, angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active\_directory)

### **Kerberos Authentication**

Ili kujifunza jinsi ya **kushambulia AD** unahitaji **kuelewa** vizuri mchakato wa **uthibitishaji wa Kerberos**.\
[**Soma ukurasa huu ikiwa bado hujui jinsi inavyofanya kazi.**](kerberos-authentication.md)

## Cheat Sheet

Unaweza kutembelea [https://wadcoms.github.io/](https://wadcoms.github.io) kupata muonekano wa haraka wa amri ambazo unaweza kukimbia ili kuhesabu/kutumia AD.

## Recon Active Directory (No creds/sessions)

Ikiwa una ufikiaji tu wa mazingira ya AD lakini huna akreditif/nikundi unaweza:

* **Pentest mtandao:**
* Fanya skana ya mtandao, pata mashine na bandari wazi na jaribu **kutumia udhaifu** au **kuchota akreditif** kutoka kwao (kwa mfano, [printa zinaweza kuwa malengo ya kuvutia sana](ad-information-in-printers.md).
* Kuangalia DNS kunaweza kutoa taarifa kuhusu seva muhimu katika domeni kama wavuti, printa, sehemu, vpn, media, nk.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Angalia [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) kupata maelezo zaidi kuhusu jinsi ya kufanya hivi.
* **Angalia ufikiaji wa null na Guest kwenye huduma za smb** (hii haitafanya kazi kwenye toleo la kisasa la Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Mwongozo wa kina zaidi juu ya jinsi ya kuhesabu seva ya SMB unaweza kupatikana hapa:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Hesabu Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Mwongozo wa kina zaidi juu ya jinsi ya kuhesabu LDAP unaweza kupatikana hapa (zingatia **ufikiaji wa siri**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Poison mtandao**
* Kusanya akreditif [**ukijifanya huduma na Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Fikia mwenyeji kwa [**kudhulumu shambulio la relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Kusanya akreditif **ukifichua** [**huduma za UPnP za uongo na evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Toa majina ya watumiaji/majina kutoka kwa nyaraka za ndani, mitandao ya kijamii, huduma (hasa wavuti) ndani ya mazingira ya domeni na pia kutoka kwa yaliyopo hadharani.
* Ikiwa unapata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu kanuni tofauti za **majina ya mtumiaji wa AD** ([**soma hii**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Kanuni maarufu zaidi ni: _NameSurname_, _Name.Surname_, _NamSur_ (herufi 3 za kila moja), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, herufi 3 _za nasibu na nambari 3 za nasibu_ (abc123).
* Zana:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

* **Anonymous SMB/LDAP enum:** Angalia [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) kurasa.
* **Kerbrute enum**: Wakati **jina la mtumiaji lisilo sahihi linapohitajika** seva itajibu kwa kutumia **nambari ya kosa la Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, ikituruhusu kubaini kwamba jina la mtumiaji halikuwa sahihi. **Majina ya watumiaji sahihi** yatatoa ama **TGT katika jibu la AS-REP** au kosa _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, ikionyesha kwamba mtumiaji anahitajika kufanya uthibitishaji wa awali.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) Server**

Ikiwa umepata moja ya seva hizi katika mtandao unaweza pia kufanya **user enumeration dhidi yake**. Kwa mfano, unaweza kutumia chombo [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
Unaweza kupata orodha za majina ya watumiaji katika [**hii github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* na hii nyingine ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Hata hivyo, unapaswa kuwa na **jina la watu wanaofanya kazi katika kampuni** kutoka hatua ya recon ambayo unapaswa kuwa umefanya kabla ya hii. Kwa jina na jina la ukoo unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuunda majina ya watumiaji halali yanayoweza kuwa.
{% endhint %}

### Kujua jina moja au kadhaa za watumiaji

Sawa, hivyo unajua tayari una jina halali la mtumiaji lakini hakuna nywila... Kisha jaribu:

* [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hana** sifa _DONT\_REQ\_PREAUTH_ unaweza **kuomba ujumbe wa AS\_REP** kwa mtumiaji huyo ambao utakuwa na data fulani iliyosimbwa kwa derivation ya nywila ya mtumiaji.
* [**Password Spraying**](password-spraying.md): Jaribu nywila **za kawaida zaidi** na kila mmoja wa watumiaji waliogunduliwa, labda mtumiaji fulani anatumia nywila mbaya (kumbuka sera ya nywila!).
* Kumbuka kwamba unaweza pia **spray OWA servers** kujaribu kupata ufikiaji wa seva za barua za watumiaji.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Poisoning

Unaweza kuwa na uwezo wa **kupata** baadhi ya changamoto **hashes** ili kufungua **kuharibu** baadhi ya protokali za **mtandao**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Ikiwa umeweza kuorodhesha active directory utakuwa na **barua pepe zaidi na ufahamu bora wa mtandao**. Unaweza kuwa na uwezo wa kulazimisha NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* kupata ufikiaji wa mazingira ya AD.

### Kuiba NTLM Creds

Ikiwa unaweza **kufikia kompyuta nyingine au sehemu** na **mtumiaji wa null au mgeni** unaweza **kweka faili** (kama faili la SCF) ambayo ikiwa kwa namna fulani itafikiwa itasababisha **uthibitishaji wa NTML dhidi yako** ili uweze **kuiba** **NTLM challenge** ili kuifungua:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Kuorodhesha Active Directory KWA nywila/sessio

Kwa hatua hii unahitaji kuwa **umevunjika nywila au sessio ya akaunti halali ya domain.** Ikiwa una nywila halali au shell kama mtumiaji wa domain, **unapaswa kukumbuka kwamba chaguzi zilizotolewa hapo awali bado ni chaguzi za kuvunja watumiaji wengine**.

Kabla ya kuanza kuorodhesha kwa uthibitisho unapaswa kujua ni nini **shida ya Kerberos double hop.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Kuorodhesha

Kuwa na akaunti iliyovunjika ni **hatua kubwa ya kuanza kuvunja domain nzima**, kwa sababu utaweza kuanza **Kuorodhesha Active Directory:**

Kuhusu [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila mtumiaji anayeweza kuwa hatarini, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu nywila ya akaunti iliyovunjika, nywila tupu na nywila mpya zinazowezekana.

* Unaweza kutumia [**CMD kufanya recon ya msingi**](../basic-cmd-for-pentesters.md#domain-info)
* Unaweza pia kutumia [**powershell kwa recon**](../basic-powershell-for-pentesters/) ambayo itakuwa ya siri zaidi
* Unaweza pia [**kutumia powerview**](../basic-powershell-for-pentesters/powerview.md) kutoa taarifa za kina zaidi
* Zana nyingine nzuri kwa ajili ya recon katika active directory ni [**BloodHound**](bloodhound.md). Si **ya siri sana** (kulingana na mbinu za ukusanyaji unazotumia), lakini **ikiwa hujali** kuhusu hilo, unapaswa kujaribu kabisa. Pata mahali ambapo watumiaji wanaweza RDP, pata njia za makundi mengine, nk.
* **Zana nyingine za kuorodhesha AD za kiotomatiki ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Rekodi za DNS za AD**](ad-dns-records.md) kwani zinaweza kuwa na taarifa za kuvutia.
* **Zana yenye GUI** ambayo unaweza kutumia kuorodhesha directory ni **AdExplorer.exe** kutoka **SysInternal** Suite.
* Unaweza pia kutafuta katika database ya LDAP kwa **ldapsearch** kutafuta nywila katika maeneo _userPassword_ & _unixUserPassword_, au hata kwa _Description_. cf. [Nywila katika AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa mbinu nyingine.
* Ikiwa unatumia **Linux**, unaweza pia kuorodhesha domain kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
* Unaweza pia kujaribu zana za kiotomatiki kama:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Kutoa majina yote ya watumiaji wa domain**

Ni rahisi sana kupata majina yote ya watumiaji wa domain kutoka Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Kuorodhesha inaonekana ndogo hii ndiyo sehemu muhimu zaidi ya yote. Fikia viungo (hasa ile ya cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuorodhesha domain na fanya mazoezi hadi ujisikie vizuri. Wakati wa tathmini, hii itakuwa wakati muhimu wa kupata njia yako hadi DA au kuamua kwamba hakuna kinachoweza kufanywa.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumiwa na huduma zinazohusiana na akaunti za watumiaji na kufungua usimbaji wao—ambao unategemea nywila za watumiaji—**nje ya mtandao**.

Zaidi kuhusu hii katika:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Muunganisho wa mbali (RDP, SSH, FTP, Win-RM, nk)

Mara tu unapokuwa umepata nywila fulani unaweza kuangalia ikiwa una ufikiaji wa **kompyuta** yoyote. Kwa jambo hilo, unaweza kutumia **CrackMapExec** kujaribu kuungana kwenye seva kadhaa kwa kutumia protokali tofauti, kulingana na skana zako za port.

### Kuinua Privilege za Mitaa

Ikiwa umevunjika nywila au sessio kama mtumiaji wa kawaida wa domain na una **ufikiaji** na mtumiaji huyu kwa **kompyuta yoyote katika domain** unapaswa kujaribu kupata njia yako ya **kuinua mamlaka kwa ndani na kutafuta nywila**. Hii ni kwa sababu ni tu kwa mamlaka ya msimamizi wa ndani utaweza **dump hashes za watumiaji wengine** katika kumbukumbu (LSASS) na kwa ndani (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**kuinua mamlaka ya ndani katika Windows**](../windows-local-privilege-escalation/) na [**orodha ya ukaguzi**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tiketi za Sessio za Sasa

Ni **ngumu sana** kwamba utapata **tiketi** katika mtumiaji wa sasa **zinazokupa ruhusa ya kufikia** rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Ikiwa umeweza kuorodhesha active directory utakuwa na **barua pepe zaidi na ufahamu bora wa mtandao**. Unaweza kuwa na uwezo wa kulazimisha NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Angalia Creds katika Computer Shares**

Sasa kwamba una baadhi ya akidi za msingi unapaswa kuangalia kama unaweza **kupata** **faili za kuvutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo kwa mikono lakini ni kazi ya kuchosha na ya kurudiwa (na zaidi ikiwa unapata mamia ya hati unahitaji kuangalia).

[**Fuata kiungo hiki kujifunza kuhusu zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Steal NTLM Creds

Ikiwa unaweza **kufikia PCs nyingine au shares** unaweza **kweka faili** (kama faili la SCF) ambayo ikiwa kwa namna fulani itafikiwa it **sababisha uthibitisho wa NTML dhidi yako** ili uweze **kuiba** **changamoto ya NTLM** ili kuifungua:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Uthibitisho huu uliruhusu mtumiaji yeyote aliyeidhinishwa **kudhoofisha kidhibiti cha eneo**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Kwa mbinu zifuatazo mtumiaji wa kawaida wa eneo si wa kutosha, unahitaji baadhi ya haki/akidi maalum ili kutekeleza mashambulizi haya.**

### Hash extraction

Tuna matumaini umeweza **kudhoofisha akaunti ya msimamizi wa ndani** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) ikiwa ni pamoja na relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [kuinua haki za ndani](../windows-local-privilege-escalation/).\
Basi, ni wakati wa kutupa hash zote kwenye kumbukumbu na ndani.\
[**Soma ukurasa huu kuhusu njia tofauti za kupata hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Mara tu unapo kuwa na hash ya mtumiaji**, unaweza kuitumia **kujifanya** kuwa yeye.\
Unahitaji kutumia **chombo** ambacho kitafanya **uthibitisho wa NTLM kwa kutumia** hiyo **hash**, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** hiyo **hash** ndani ya **LSASS**, hivyo wakati uthibitisho wowote wa **NTLM unafanywa**, hiyo **hash itatumika.** Chaguo la mwisho ndilo ambalo mimikatz hufanya.\
[**Soma ukurasa huu kwa maelezo zaidi.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Shambulizi hili linakusudia **kutumia hash ya mtumiaji wa NTLM kuomba tiketi za Kerberos**, kama mbadala wa kawaida wa Pass The Hash juu ya itifaki ya NTLM. Hivyo, hii inaweza kuwa hasa **faida katika mitandao ambapo itifaki ya NTLM imezimwa** na tu **Kerberos inaruhusiwa** kama itifaki ya uthibitisho.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Katika mbinu ya shambulizi ya **Pass The Ticket (PTT)**, washambuliaji **wanaiba tiketi ya uthibitisho wa mtumiaji** badala ya nenosiri lao au thamani za hash. Tiketi hii iliyibwa inatumika kisha **kujifanya kuwa mtumiaji**, ikipata ufikiaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Credentials Reuse

Ikiwa una **hash** au **nenosiri** la **msimamizi wa ndani** unapaswa kujaribu **kuingia ndani** kwenye **PC nyingine** kwa kutumia hiyo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Kumbuka kwamba hii ni **kelele** na **LAPS** itapunguza.
{% endhint %}

### MSSQL Dhuluma & Viungo Vilivyoaminika

Ikiwa mtumiaji ana mamlaka ya **kufikia mifano ya MSSQL**, anaweza kuwa na uwezo wa kuitumia **kutekeleza amri** kwenye mwenyeji wa MSSQL (ikiwa inafanya kazi kama SA), **kuchukua** NetNTLM **hash** au hata kufanya **shambulio la relay**.\
Pia, ikiwa mfano wa MSSQL unakubaliwa (kiungo cha database) na mfano mwingine wa MSSQL. Ikiwa mtumiaji ana mamlaka juu ya database iliyoaminika, atakuwa na uwezo wa **kutumia uhusiano wa kuaminiana kutekeleza maswali pia kwenye mfano mwingine**. Hizi kuaminiana zinaweza kuunganishwa na kwa wakati fulani mtumiaji anaweza kuwa na uwezo wa kupata database iliyo na makosa ambapo anaweza kutekeleza amri.\
**Viungo kati ya databases vinafanya kazi hata kati ya kuaminiana kwa misitu.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Uwakilishi Usio na Mipaka

Ikiwa unapata kitu chochote cha Kompyuta chenye sifa [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) na una mamlaka ya kikoa kwenye kompyuta, utaweza kutoa TGTs kutoka kwenye kumbukumbu ya kila mtumiaji anayeingia kwenye kompyuta.\
Hivyo, ikiwa **Msimamizi wa Kikoa anaingia kwenye kompyuta**, utaweza kutoa TGT yake na kumwakilisha kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Shukrani kwa uwakilishi ulio na mipaka unaweza hata **kudhoofisha Server ya Print** (tunatumai itakuwa DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Uwakilishi Ulio na Mipaka

Ikiwa mtumiaji au kompyuta inaruhusiwa kwa "Uwakilishi Ulio na Mipaka" itakuwa na uwezo wa **kumwakilisha mtumiaji yeyote ili kufikia huduma fulani kwenye kompyuta**.\
Kisha, ikiwa **utadhuru hash** ya mtumiaji/hii kompyuta utaweza **kumwakilisha mtumiaji yeyote** (hata wasimamizi wa kikoa) ili kufikia huduma fulani.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Uwakilishi wa Mipango ya Rasilimali

Kuwa na mamlaka ya **KANDARASI** kwenye kitu cha Active Directory cha kompyuta ya mbali kunaruhusu kupata utekelezaji wa msimbo wenye **mamlaka ya juu**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Dhuluma ya ACLs

Mtumiaji aliyeathiriwa anaweza kuwa na **mamlaka ya kuvutia juu ya baadhi ya vitu vya kikoa** ambavyo vinaweza kukuruhusu **kuhamasisha** kwa upande/**kuinua** mamlaka.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Dhuluma ya huduma ya Printer Spooler

Kugundua **huduma ya Spool inayosikiliza** ndani ya kikoa inaweza **kudhulumiwa** ili **kupata akidi mpya** na **kuinua mamlaka**.

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Dhuluma ya vikao vya wahusika wengine

Ikiwa **watumiaji wengine** **wanapata** mashine **iliyoathiriwa**, inawezekana **kukusanya akidi kutoka kwenye kumbukumbu** na hata **kuingiza beacons kwenye michakato yao** ili kuwawakilisha.\
Kawaida watumiaji wataingia kwenye mfumo kupitia RDP, hivyo hapa kuna jinsi ya kufanya mashambulizi kadhaa juu ya vikao vya RDP vya wahusika wengine:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** inatoa mfumo wa kusimamia **neno la siri la Msimamizi wa ndani** kwenye kompyuta zilizounganishwa na kikoa, kuhakikisha kuwa ni **ya nasibu**, ya kipekee, na mara kwa mara **inabadilishwa**. Maneno haya ya siri yanahifadhiwa kwenye Active Directory na ufikiaji unadhibitiwa kupitia ACLs kwa watumiaji walioidhinishwa tu. Kwa ruhusa ya kutosha ya kufikia maneno haya ya siri, kuhamasisha kwenye kompyuta nyingine kunakuwa na uwezekano.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Wizi wa Vyeti

**Kukusanya vyeti** kutoka kwenye mashine iliyeathiriwa inaweza kuwa njia ya kuinua mamlaka ndani ya mazingira:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Dhuluma ya Mipango ya Vyeti

Ikiwa **mipango dhaifu** imewekwa inawezekana kudhulumu ili kuinua mamlaka:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Baada ya Utekelezaji na akaunti ya mamlaka ya juu

### Kutupa Akidi za Kikoa

Mara tu unapopata **Msimamizi wa Kikoa** au hata bora **Msimamizi wa Biashara**, unaweza **kutupa** **database ya kikoa**: _ntds.dit_.

[**Taarifa zaidi kuhusu shambulio la DCSync inaweza kupatikana hapa**](dcsync.md).

[**Taarifa zaidi kuhusu jinsi ya kuiba NTDS.dit inaweza kupatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kama Uendelevu

Baadhi ya mbinu zilizozungumziwa hapo awali zinaweza kutumika kwa uendelevu.\
Kwa mfano unaweza:

*   Kuwaweka watumiaji katika hatari ya [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Kuwaweka watumiaji katika hatari ya [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   Kutoa [**DCSync**](./#dcsync) mamlaka kwa mtumiaji

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Tiketi ya Fedha

**Shambulio la Tiketi ya Fedha** linaunda **tiketi halali ya Huduma ya Kutoa Tiketi (TGS)** kwa huduma maalum kwa kutumia **hash ya NTLM** (kwa mfano, **hash ya akaunti ya PC**). Njia hii inatumika ili **kufikia mamlaka ya huduma**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Tiketi ya Dhahabu

**Shambulio la Tiketi ya Dhahabu** linahusisha mshambuliaji kupata ufikiaji wa **hash ya NTLM ya akaunti ya krbtgt** katika mazingira ya Active Directory (AD). Akaunti hii ni maalum kwa sababu inatumika kusaini **Tiketi za Kutoa Tiketi (TGTs)**, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mara mshambuliaji anapopata hash hii, anaweza kuunda **TGTs** kwa akaunti yoyote anayotaka (shambulio la tiketi ya fedha).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Tiketi ya Almasi

Hizi ni kama tiketi za dhahabu zilizoforgiwa kwa njia ambayo **inasababisha kupita mifumo ya kawaida ya kugundua tiketi za dhahabu.**

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Uendelevu wa Akaunti za Vyeti**

**Kuwa na vyeti vya akaunti au kuwa na uwezo wa kuviomba** ni njia nzuri ya kuwa na uwezo wa kuendelea katika akaunti za watumiaji (hata kama anabadilisha nenosiri):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Uendelevu wa Vyeti vya Kikoa**

**Kutumia vyeti pia kunawezekana kuendelea na mamlaka ya juu ndani ya kikoa:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Kundi la AdminSDHolder

Kitu cha **AdminSDHolder** katika Active Directory kinahakikisha usalama wa **vikundi vyenye mamlaka** (kama Wasimamizi wa Kikoa na Wasimamizi wa Biashara) kwa kutumia **Orodha ya Udhibiti wa Ufikiaji (ACL)** ya kawaida kati ya vikundi hivi ili kuzuia mabadiliko yasiyoidhinishwa. Hata hivyo, kipengele hiki kinaweza kudhulumiwa; ikiwa mshambuliaji atabadilisha ACL ya AdminSDHolder ili kutoa ufikiaji kamili kwa mtumiaji wa kawaida, mtumiaji huyo anapata udhibiti mkubwa juu ya vikundi vyote vyenye mamlaka. Kipimo hiki cha usalama, kilichokusudiwa kulinda, kinaweza hivyo kurudi nyuma, kuruhusu ufikiaji usio na haki isipokuwa ufuatiliwe kwa karibu.

[**Taarifa zaidi kuhusu Kundi la AdminDSHolder hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Akidi za DSRM

Ndani ya kila **Msimamizi wa Kikoa (DC)**, kuna akaunti ya **msimamizi wa ndani**. Kwa kupata haki za usimamizi kwenye mashine kama hiyo, hash ya Msimamizi wa ndani inaweza kutolewa kwa kutumia **mimikatz**. Baada ya hii, mabadiliko ya rejista yanahitajika ili **kuwezesha matumizi ya nenosiri hili**, kuruhusu ufikiaji wa mbali kwa akaunti ya Msimamizi wa ndani.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Uendelevu wa ACL

Unaweza **kutoa** baadhi ya **mamlaka maalum** kwa **mtumiaji** juu ya baadhi ya vitu maalum vya kikoa ambavyo vitamruhusu mtumiaji **kuinua mamlaka katika siku zijazo**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Maelezo ya Usalama

**Maelezo ya usalama** yanatumika **kuhifadhi** **mamlaka** ambayo **kitu** kina **juu ya** **kitu**. Ikiwa unaweza tu **kufanya** **mabadiliko madogo** katika **maelezo ya usalama** ya kitu, unaweza kupata mamlaka ya kuvutia juu ya kitu hicho bila kuhitaji kuwa mwanachama wa kundi lenye mamlaka.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Funguo la Skeleton

Badilisha **LSASS** katika kumbukumbu ili kuanzisha **neno la siri la ulimwengu**, linalotoa ufikiaji kwa akaunti zote za kikoa.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP ya Kijadi

[Jifunze ni nini SSP (Mtoa Msaada wa Usalama) hapa.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kukamata** kwa **maandishi wazi** **akidi** zinazotumika kufikia mashine.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Inasajili **Msimamizi Mpya wa Kikoa** katika AD na inaitumia **kushinikiza sifa** (SIDHistory, SPNs...) kwenye vitu vilivyotajwa **bila** kuacha **kumbukumbu** kuhusu **mabadiliko**. Unahitaji ruhusa za DA na uwe ndani ya **kikoa cha mzizi**.\
Kumbuka kwamba ikiwa utatumia data mbaya, kumbukumbu mbaya sana zitaonekana.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Uendelevu wa LAPS

Kabla tulijadili jinsi ya kuinua mamlaka ikiwa una **ruhusa ya kutosha kusoma maneno ya siri ya LAPS**. Hata hivyo, maneno haya ya siri yanaweza pia kutumika **kuendeleza uendelevu**.\
Angalia:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Kuinua Mamlaka ya Misitu - Kuaminiana kwa Kikoa

Microsoft inaona **Misitu** kama mpaka wa usalama. Hii inamaanisha kwamba **kuathiri kikoa kimoja kunaweza kusababisha misitu yote kuathiriwa**.

### Taarifa za Msingi

[**kuaminiana kwa kikoa**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) ni mekanizma ya usalama inayowezesha mtumiaji kutoka kwenye **kikoa** moja kufikia rasilimali katika **kikoa** kingine. Kimsingi inaunda uhusiano kati ya mifumo ya uthibitishaji ya vikundi viwili, ikiruhusu uthibitishaji kuhamasika bila shida. Wakati vikundi vinapoweka uhusiano wa kuaminiana, wanabadilishana na kuhifadhi funguo maalum ndani ya **Msimamizi wao wa Kikoa (DCs)**, ambazo ni muhimu kwa uaminifu wa uhusiano huo.

Katika hali ya kawaida, ikiwa mtumiaji anataka kufikia huduma katika **kikoa kilichoaminika**, lazima kwanza aombe tiketi maalum inayojulikana kama **TGT ya kati** kutoka kwa DC ya kikoa chake mwenyewe. TGT hii inashikiliwa kwa funguo ya pamoja **ambayo vikundi vyote viwili vimekubaliana.** Mtumiaji kisha anawasilisha TGT hii kwa **DC ya kikoa kilichoaminika** ili kupata tiketi ya huduma (**TGS**). Baada ya uthibitishaji wa mafanikio wa TGT ya kati na DC ya kikoa kilichoaminika, inatoa TGS, ikimpa mtumiaji ufikiaji wa huduma.

**Hatua**:

1. Kompyuta **mteja** katika **Kikoa 1** inaanza mchakato kwa kutumia **hash ya NTLM** kuomba **Tiketi ya Kutoa Tiketi (TGT)** kutoka kwa **Msimamizi wake wa Kikoa (DC1)**.
2. DC1 inatoa TGT mpya ikiwa mteja amethibitishwa kwa mafanikio.
3. Mteja kisha anaomba **TGT ya kati** kutoka DC1, ambayo inahitajika kufikia rasilimali katika **Kikoa 2**.
4. TGT ya kati inashikiliwa kwa **funguo ya kuaminiana** iliyoshirikiwa kati ya DC1 na DC2 kama sehemu ya uhusiano wa kuaminiana wa pande mbili.
5. Mteja anachukua TGT ya kati kwa **Msimamizi wa Kikoa 2 (DC2)**.
6. DC2 inathibitisha TGT ya kati kwa kutumia funguo yake ya kuaminiana iliyoshirikiwa na, ikiwa ni halali, inatoa **Huduma ya Kutoa Tiketi (TGS)** kwa seva katika Kikoa 2 ambayo mteja anataka kufikia.
7. Hatimaye, mteja anawasilisha TGS hii kwa seva, ambayo inashikiliwa kwa hash ya akaunti ya seva, ili kupata ufikiaji wa huduma katika Kikoa 2.

### Kuaminiana tofauti

Ni muhimu kutambua kwamba **kuaminiana kunaweza kuwa njia 1 au njia 2**. Katika chaguo la njia 2, vikundi vyote viwili vitakuwa na uaminifu kwa kila mmoja, lakini katika uhusiano wa **njia 1** moja ya vikundi itakuwa **imeaminika** na nyingine itakuwa **inayoaminika**. Katika kesi ya mwisho, **utaweza tu kufikia rasilimali ndani ya kikoa kinachoaminika kutoka kwenye kikoa kilichoaminika**.

Ikiwa Kikoa A kinakuaminisha Kikoa B, A ni kikoa kinachoaminika na B ni kikoa kilichoaminika. Zaidi ya hayo, katika **Kikoa A**, hii itakuwa **kuaminiana kwa nje**; na katika **Kikoa B**, hii itakuwa **kuaminiana kwa ndani**.

**Uhusiano tofauti wa kuaminiana**

* **Kuaminiana kwa Mzazi-Mwana**: Hii ni mipangilio ya kawaida ndani ya misitu hiyo hiyo, ambapo kikoa cha mtoto kwa otomatiki kina uhusiano wa kuaminiana wa pande mbili na kikoa chake cha mzazi. Kimsingi, hii inamaanisha kwamba maombi ya uthibitishaji yanaweza kuhamasika bila shida kati ya mzazi na mtoto.
* **Kuaminiana kwa Msalaba**: Inajulikana kama "kuaminiana kwa mkato," hizi zimeanzishwa kati ya vikundi vya watoto ili kuharakisha michakato ya rufaa. Katika misitu ngumu, rufaa za uthibitishaji kawaida zinahitaji kusafiri hadi mzizi wa msitu na kisha kushuka hadi kikoa lengwa. Kwa kuunda viungo vya msalaba, safari inakuwa fupi, ambayo ni faida hasa katika mazingira yaliyosambazwa kijiografia.
* **Kuaminiana kwa Nje**: Hizi zimeanzishwa kati ya vikundi tofauti, visivyo na uhusiano na ni zisizo za kupita. Kulingana na [nyaraka za Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), kuaminiana kwa nje ni muhimu kwa kufikia rasilimali katika kikoa kilicho nje ya msitu wa sasa ambacho hakijashikamana na uhusiano wa msitu. Usalama unaboreshwa kupitia kuchuja SID na kuaminiana kwa nje.
* **Kuaminiana kwa Mzizi wa Mti**: Hizi kuaminiana zinaanzishwa moja kwa moja kati ya kikoa cha mzizi wa msitu na mzizi mpya wa mti ulioongezwa. Ingawa hazikutana mara kwa mara, kuaminiana kwa mzizi wa mti ni muhimu kwa kuongeza miti mipya ya kikoa kwenye msitu, ikiruhusu kudumisha jina la kipekee la kikoa na kuhakikisha kupita kwa pande mbili. Taarifa zaidi zinaweza kupatikana katika [mwongozo wa Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Kuaminiana kwa Misitu**: Aina hii ya kuaminiana ni kuaminiana kwa pande mbili kati ya vikundi viwili vya mzizi wa msitu, pia ikilazimisha kuchuja SID ili kuboresha hatua za usalama.
* **Kuaminiana kwa MIT**: Hizi kuaminiana zinaanzishwa na vikundi vya Kerberos vinavyokubaliana na [RFC4120](https://tools.ietf.org/html/rfc4120) visivyo vya Windows. Kuaminiana kwa MIT ni maalum zaidi na inahudumia mazingira yanayohitaji ushirikiano na mifumo ya Kerberos nje ya mfumo wa Windows.

#### Tofauti nyingine katika **uhusiano wa kuaminiana**

* Uhusiano wa kuaminiana unaweza pia kuwa **wa kupita** (A inakuaminisha B, B inakuaminisha C, kisha A inakuaminisha C) au **usio wa kupita**.
* Uhusiano wa kuaminiana unaweza kuwekwa kama **kuaminiana kwa pande mbili** (kila mmoja anakuaminisha mwingine) au kama **kuaminiana kwa njia moja** (moja tu kati yao inakuaminisha mwingine).

### Njia ya Shambulio

1. **Tathmini** uhusiano wa kuaminiana
2. Angalia ikiwa **kiongozi wa usalama** (mtumiaji/kundi/kompyuta) ana **ufikiaji** wa rasilimali za **kikoa kingine**, labda kupitia entries za ACE au kwa kuwa katika vikundi vya kikoa kingine. Angalia **uhusiano kati ya vikundi** (kuaminiana kulianzishwa kwa hili labda).
1. kerberoast katika kesi hii inaweza kuwa chaguo lingine.
3. **Dhulumu** **akaunti** ambazo zinaweza **kuhamasisha** kupitia vikundi.

Wavamizi wanaweza kufikia rasilimali katika kikoa kingine kupitia mitambo mitatu kuu:

* **Uanachama wa Kundi la Mitaa**: Viongozi wanaweza kuongezwa kwenye vikundi vya ndani kwenye mashine, kama vile kundi la "Wasimamizi" kwenye seva, wakitoa udhibiti mkubwa juu ya mashine hiyo.
* **Uanachama wa Kundi la Kikoa la Kigeni**: Viongozi pia wanaweza kuwa wanachama wa vikundi ndani ya kikoa cha kigeni. Hata hivyo, ufanisi wa njia hii unategemea asili ya uhusiano wa kuaminiana na upeo wa kundi.
* **Orodha za Udhibiti wa Ufikiaji (ACLs)**: Viongozi wanaweza kutajwa katika **ACL**, hasa kama viumbe katika **ACEs** ndani ya **DACL**, wakitoa ufikiaji kwa rasilimali maalum. Kwa wale wanaotaka kuingia kwa undani zaidi katika mitambo ya ACLs, DACLs, na ACEs, karatasi ya nyeupe iliyoitwa “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)” ni rasilimali muhimu.

### Kuinua mamlaka ya Misitu kutoka Mtoto hadi Mzazi
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
Kuna **funguo 2 za kuaminika**, moja kwa _Mtoto --> Mzazi_ na nyingine kwa _Mzazi_ --> _Mtoto_.\
Unaweza kutumia ile inayotumika na eneo la sasa kwa:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

Pandisha kama msimamizi wa Enterprise kwa kutumia uaminifu na SID-History injection:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Exploit writeable Configuration NC

Kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumika ni muhimu. Configuration NC inatumika kama hazina kuu ya data za usanidi katika msitu wa Active Directory (AD). Data hii inakopwa kwa kila Domain Controller (DC) ndani ya msitu, huku DC zenye uwezo wa kuandika zikihifadhi nakala inayoweza kuandikwa ya Configuration NC. Ili kutumia hili, mtu lazima awe na **privileges za SYSTEM kwenye DC**, bora iwe DC ya mtoto.

**Link GPO to root DC site**

Konteina ya Sites ya Configuration NC inajumuisha taarifa kuhusu tovuti za kompyuta zote zilizounganishwa na domain ndani ya msitu wa AD. Kwa kufanya kazi na privileges za SYSTEM kwenye DC yoyote, washambuliaji wanaweza kuunganisha GPOs kwenye tovuti za root DC. Kitendo hiki kinaweza kuathiri domain ya mzazi kwa kubadilisha sera zinazotumika kwenye tovuti hizi.

Kwa taarifa za kina, mtu anaweza kuchunguza utafiti kuhusu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Njia ya shambulio inahusisha kulenga gMSAs zenye mamlaka ndani ya domain. Funguo ya KDS Root, muhimu kwa kuhesabu nywila za gMSAs, inahifadhiwa ndani ya Configuration NC. Kwa kuwa na privileges za SYSTEM kwenye DC yoyote, inawezekana kufikia funguo ya KDS Root na kuhesabu nywila za gMSA yoyote ndani ya msitu.

Uchambuzi wa kina unaweza kupatikana katika majadiliano kuhusu [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Njia hii inahitaji uvumilivu, ikisubiri kuundwa kwa vitu vipya vya AD vyenye mamlaka. Kwa kuwa na privileges za SYSTEM, mshambuliaji anaweza kubadilisha Schema ya AD ili kumpa mtumiaji yeyote udhibiti kamili juu ya makundi yote. Hii inaweza kusababisha ufikiaji usioidhinishwa na udhibiti wa vitu vipya vya AD vilivyoundwa.

Kusoma zaidi kunaweza kupatikana kwenye [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Ukatili wa ADCS ESC5 unalenga udhibiti wa vitu vya Public Key Infrastructure (PKI) ili kuunda kiolezo cha cheti kinachowezesha uthibitisho kama mtumiaji yeyote ndani ya msitu. Kwa kuwa vitu vya PKI vinapatikana katika Configuration NC, kuathiri DC ya mtoto inayoweza kuandikwa kunaruhusu utekelezaji wa shambulio la ESC5.

Maelezo zaidi kuhusu hili yanaweza kusomwa katika [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika hali ambazo hazina ADCS, mshambuliaji ana uwezo wa kuanzisha vipengele muhimu, kama ilivyojadiliwa katika [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Katika hali hii **domeni yako inatambuliwa** na nyingine ya nje ikikupa **idhini zisizojulikana** juu yake. Utahitaji kutafuta **ni wakuu gani wa domeni yako wana ufikiaji gani juu ya domeni ya nje** na kisha jaribu kuifanyia kazi:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Domeni ya Msitu wa Nje - Njia Moja (Nje)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Katika hali hii **domeni yako** in **aminika** baadhi ya **mamlaka** kwa kiongozi kutoka **domeni tofauti**.

Hata hivyo, wakati **domeni inayoaminika** na domeni inayoweka imani, domeni inayowekwa imani **inaunda mtumiaji** mwenye **jina linaloweza kutabiriwa** ambalo linatumia kama **nenosiri nenosiri lililoaminika**. Hii ina maana kwamba inawezekana **kufikia mtumiaji kutoka kwenye domeni inayoweka imani ili kuingia kwenye ile inayowekwa imani** ili kuhesabu na kujaribu kupandisha mamlaka zaidi:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Njia nyingine ya kuathiri domeni inayowekwa imani ni kutafuta [**kiungo cha SQL kilichoaminika**](abusing-ad-mssql.md#mssql-trusted-links) kilichoundwa katika **mwelekeo kinyume** cha imani ya domeni (ambayo si ya kawaida sana).

Njia nyingine ya kuathiri domeni inayowekwa imani ni kusubiri kwenye mashine ambapo **mtumiaji kutoka kwenye domeni inayowekwa imani anaweza kufikia** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza msimbo katika mchakato wa kikao cha RDP na **kufikia domeni ya asili ya mwathirika** kutoka pale.\
Zaidi ya hayo, ikiwa **mwathirika ameunganisha diski yake ngumu**, kutoka kwenye mchakato wa **kikao cha RDP** mshambuliaji anaweza kuhifadhi **backdoors** kwenye **folda ya kuanzisha ya diski ngumu**. Mbinu hii inaitwa **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Kupunguza matumizi mabaya ya imani ya domeni

### **SID Filtering:**

* Hatari ya mashambulizi yanayotumia sifa ya historia ya SID katika imani za msitu inapunguziliwa mbali na SID Filtering, ambayo imewezeshwa kwa chaguo-msingi kwenye imani zote za msitu. Hii inategemea dhana kwamba imani za ndani ya msitu ni salama, ikizingatia msitu, badala ya domeni, kama mpaka wa usalama kulingana na msimamo wa Microsoft.
* Hata hivyo, kuna tatizo: SID filtering inaweza kuathiri programu na ufikiaji wa watumiaji, na kusababisha kuondolewa kwake mara kwa mara.

### **Uthibitishaji wa Chaguo:**

* Kwa imani za kati ya msitu, kutumia Uthibitishaji wa Chaguo kunahakikisha kwamba watumiaji kutoka kwenye msitu mbili hawathibitishwi kiotomatiki. Badala yake, ruhusa wazi zinahitajika kwa watumiaji kufikia domeni na seva ndani ya domeni au msitu unaoweka imani.
* Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya matumizi mabaya ya Muktadha wa Jina la Configuration (NC) unaoweza kuandikwa au mashambulizi kwenye akaunti ya imani.

[**Taarifa zaidi kuhusu imani za domeni katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Ulinzi wa Jumla

[**Jifunze zaidi kuhusu jinsi ya kulinda hati hapa.**](../stealing-credentials/credentials-protections.md)\\

### **Hatua za Kijamii za Ulinzi wa Hati**

* **Vikwazo vya Wasimamizi wa Domeni**: Inapendekezwa kwamba Wasimamizi wa Domeni wanapaswa kuruhusiwa kuingia tu kwenye Wasimamizi wa Domeni, wakiepuka matumizi yao kwenye mwenyeji wengine.
* **Mamlaka ya Akaunti ya Huduma**: Huduma hazipaswi kuendeshwa kwa mamlaka ya Wasimamizi wa Domeni (DA) ili kudumisha usalama.
* **Kikomo cha Muda wa Mamlaka**: Kwa kazi zinazohitaji mamlaka ya DA, muda wao unapaswa kuwa mdogo. Hii inaweza kufanywa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Kutekeleza Mbinu za Udanganyifu**

* Kutekeleza udanganyifu kunahusisha kuweka mitego, kama vile watumiaji wa udanganyifu au kompyuta, zikiwa na sifa kama vile nenosiri ambazo hazitaisha au zimewekwa kama Zinazoaminika kwa Delegation. Njia ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza kwenye vikundi vya mamlaka ya juu.
* Mfano wa vitendo unahusisha kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Zaidi kuhusu kutekeleza mbinu za udanganyifu yanaweza kupatikana kwenye [Deploy-Deception kwenye GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Udanganyifu**

* **Kwa Vitu vya Mtumiaji**: Viashiria vya kutatanisha ni pamoja na ObjectSID isiyo ya kawaida, kuingia mara chache, tarehe za uundaji, na idadi ndogo ya nenosiri mbaya.
* **Viashiria vya Jumla**: Kulinganisha sifa za vitu vya udanganyifu vinavyowezekana na zile za halali kunaweza kufichua kutokuelewana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) zinaweza kusaidia katika kutambua udanganyifu kama huu.

### **Kupita Mfumo wa Ugunduzi**

* **Kupita Ugunduzi wa Microsoft ATA**:
* **Uhesabuji wa Watumiaji**: Kuepuka uhesabuji wa kikao kwenye Wasimamizi wa Domeni ili kuzuia ugunduzi wa ATA.
* **Uigaji wa Tiketi**: Kutumia funguo za **aes** kwa ajili ya uundaji wa tiketi husaidia kuepuka ugunduzi kwa kutokudharau hadi NTLM.
* **Mashambulizi ya DCSync**: Kutekeleza kutoka kwa Wasimamizi wa Domeni sio pendekezo, kwani kutekeleza moja kwa moja kutoka kwa Wasimamizi wa Domeni kutasababisha alerts.

## Marejeleo

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{% hint style="success" %}
Jifunze & fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze & fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
