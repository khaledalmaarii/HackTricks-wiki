# Mbinu za Active Directory

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Muhtasari wa Msingi

**Active Directory** inatumika kama teknolojia ya msingi, ikiruhusu **watawala wa mtandao** kuunda na kusimamia kwa ufanisi **domains**, **watumiaji**, na **vitu** ndani ya mtandao. Imeundwa ili kuwezesha ukuaji, kurahisisha utaratibu wa kuweka idadi kubwa ya watumiaji katika **makundi** na **makundi ya chini**, wakati wa kudhibiti **haki za ufikiaji** kwa viwango mbalimbali.

Muundo wa **Active Directory** unajumuisha safu tatu kuu: **domains**, **miti**, na **misitu**. **Domain** inajumuisha mkusanyiko wa vitu, kama vile **watumiaji** au **vifaa**, vinavyoshiriki kwenye database moja. **Miti** ni makundi ya domains haya yanayounganishwa na muundo unaoshirikiwa, na **msitu** unawakilisha mkusanyiko wa miti kadhaa, zilizounganishwa kupitia **uaminifu**, na kuunda safu ya juu kabisa ya muundo wa shirika. **Haki maalum** za ufikiaji na mawasiliano zinaweza kutengwa kwa kila kiwango hiki.

Mawazo muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** - Inahifadhi habari zote zinazohusiana na vitu vya Active Directory.
2. **Kitu** - Inaonyesha vitu ndani ya directory, ikiwa ni pamoja na **watumiaji**, **makundi**, au **folda zilizoshirikiwa**.
3. **Domain** - Inatumika kama chombo cha kuhifadhi vitu vya directory, na uwezo wa kuwepo kwa domains nyingi ndani ya **msitu**, kila moja ikisimamia mkusanyiko wake wa vitu.
4. **Mti** - Kikundi cha domains kinachoshiriki kikoa cha mizizi kinachofanana.
5. **Msitu** - Kilele cha muundo wa shirika katika Active Directory, kilichojumuisha miti kadhaa na **uaminifu** kati yao.

**Active Directory Domain Services (AD DS)** inajumuisha huduma mbalimbali muhimu kwa usimamizi na mawasiliano ya kati katika mtandao. Huduma hizi ni pamoja na:

1. **Huduma za Domain** - Inahifadhi data na kusimamia mwingiliano kati ya **watumiaji** na **domains**, ikiwa ni pamoja na utambulisho na utafutaji.
2. **Huduma za Cheti** - Inasimamia uundaji, usambazaji, na usimamizi wa **vyeti vya dijiti** salama.
3. **Huduma Ndogo za Directory** - Inasaidia programu zinazoruhusu matumizi ya **itifaki ya LDAP**.
4. **Huduma za Ushirikiano wa Directory** - Inatoa uwezo wa **kuingia kwa mara moja** ili kuthibitisha watumiaji kwenye programu za wavuti nyingi katika kikao kimoja.
5. **Usimamizi wa Haki** - Inasaidia kulinda hakimiliki kwa kudhibiti usambazaji na matumizi yake yasiyoruhusiwa.
6. **Huduma ya DNS** - Muhimu kwa ufumbuzi wa **majina ya kikoa**.

Kwa maelezo zaidi angalia: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)


### **Uthibitisho wa Kerberos**

Ili kujifunza jinsi ya **kuhujumu AD** unahitaji **kuelewa vizuri** mchakato wa **uthibitisho wa Kerberos**.\
[**Soma ukurasa huu ikiwa bado haujui jinsi inavyofanya kazi.**](kerberos-authentication.md)

## Orodha ya Udanganyifu

Unaweza kwenda [https://wadcoms.github.io/](https://wadcoms.github.io) ili kuona haraka amri gani unaweza kutumia kwa ajili ya kuchunguza/kutumia AD.

## Uchunguzi wa Active Directory (Bila sifa/vikao)

Ikiwa una ufikiaji tu kwenye mazingira ya AD lakini huna sifa/vikao yoyote unaweza:

* **Pentest mtandao:**
* Tafuta mtandao, tafuta mashine na fanya bandari zifunguke na jaribu **kutumia udhaifu** au **kupata sifa** kutoka kwao (kwa mfano, [printers inaweza kuwa malengo muhimu sana](ad-information-in-printers.md).
* Kuchunguza DNS kunaweza kutoa habari kuhusu seva muhimu katika kikoa kama vile wavuti, printers, hisa, vpn, media, nk.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Angalia [**Mbinu ya Msingi ya Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) kupata habari zaidi kuhusu jinsi ya kufanya hivi.
* **Angalia upatikanaji wa null na Guest kwenye huduma za smb** (hii haitafanya kazi kwenye toleo za kisasa za Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Mwongozo wa kina zaidi juu ya jinsi ya kuchunguza seva ya SMB unaweza kupatikana hapa:

{% content-ref url="../../network-services-pentesting/pentesting-smb.md" %}
[pentesting-smb.md](../../network-services-pentesting/pentesting-smb.md)
{% endcontent-ref %}

* **Chunguza Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Mwongozo wa kina zaidi juu ya jinsi ya kuchunguza LDAP unaweza kupatikana hapa (angalia **upatikanaji wa bila jina**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md
### Uchambuzi wa Watumiaji

* **Uchambuzi wa SMB/LDAP wa Anonimasi:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb.md) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Uchambuzi wa Kerbrute**: Wakati jina la mtumiaji **lisilo sahihi linahitajika**, seva itajibu kwa kutumia kificho cha **Kerberos error** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, kuruhusu sisi kubaini kuwa jina la mtumiaji halikuwa sahihi. **Majina sahihi ya mtumiaji** yataleta majibu ya **TGT katika jibu la AS-REP** au kosa _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, ikionyesha kuwa mtumiaji anahitajika kufanya uthibitishaji kabla ya mawasiliano.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Seva ya OWA (Outlook Web Access)**

Ikiwa umepata moja ya seva hizi kwenye mtandao, unaweza pia kufanya **utambuzi wa watumiaji dhidi yake**. Kwa mfano, unaweza kutumia chombo cha [**MailSniper**](https://github.com/dafthack/MailSniper):
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
Unaweza kupata orodha ya majina ya watumiaji katika [**repo hii ya github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* na hii ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Hata hivyo, unapaswa kuwa na **jina la watu wanaofanya kazi katika kampuni** kutoka hatua ya uchunguzi ambayo unapaswa kufanya kabla ya hii. Kwa kutumia jina na jina la mwisho unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuunda majina ya watumiaji yanayowezekana.
{% endhint %}

### Kujua jina moja au majina kadhaa ya watumiaji

Sawa, basi unajua tayari una jina la mtumiaji halali lakini hakuna nywila... Basi jaribu:

* [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **hawana** sifa ya _DONT\_REQ\_PREAUTH_ unaweza **kuomba ujumbe wa AS\_REP** kwa mtumiaji huyo ambao utaleta data iliyosimbwa na maelekezo ya nywila ya mtumiaji.
* [**Password Spraying**](password-spraying.md): Jaribu nywila **za kawaida** zaidi kwa kila mtumiaji uliyegundua, labda kuna mtumiaji anatumia nywila mbaya (zingatia sera ya nywila!).
* Tambua pia unaweza **kupuliza seva za OWA** ili kujaribu kupata ufikiaji wa seva za barua pepe za watumiaji.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Sumu ya LLMNR/NBT-NS

Unaweza kuwa na uwezo wa **kupata** baadhi ya changamoto **hashes** za kuvunja **sumu** baadhi ya itifaki za **mtandao**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Ikiwa umefanikiwa kuorodhesha active directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza kuwa na uwezo wa kufanya mashambulizi ya [**relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* ya NTML ili kupata ufikiaji wa mazingira ya AD.

### Kuiba NTML Creds

Ikiwa unaweza **kufikia PC au kushirikiana** na mtumiaji wa **null au mgeni** unaweza **kuweka faili** (kama faili ya SCF) ambayo ikiwa itafikiwa kwa njia fulani ita**chochea uthibitisho wa NTML dhidi yako** ili uweze **kuiba** changamoto ya **NTML** ili kuvunja:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Kuhesabu Active Directory NA sifa/kikao

Kwa hatua hii unahitaji **kuvunja sifa au kikao cha akaunti halali ya kikoa.** Ikiwa una sifa halali au kikao kama mtumiaji wa kikoa, **unapaswa kukumbuka kuwa chaguo zilizotolewa hapo awali bado ni chaguo za kuvunja watumiaji wengine**.

Kabla ya kuanza uhesabu uliothibitishwa unapaswa kujua ni nini **tatizo la Kerberos double hop.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Uhesabu

Kuwa na akaunti iliyovunjwa ni **hatua kubwa ya kuanza kuvunja kikoa kizima**, kwa sababu utaweza kuanza **Uhesabu wa Active Directory:**

Kuhusu [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila mtumiaji anayeweza kuwa na udhaifu, na kuhusu [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya majina yote ya watumiaji** na kujaribu nywila ya akaunti iliyovunjwa, nywila tupu na nywila mpya yenye ahadi.

* Unaweza kutumia [**CMD kufanya uchunguzi wa msingi**](../basic-cmd-for-pentesters.md#domain-info)
* Unaweza pia kutumia [**powershell kwa uchunguzi**](../basic-powershell-for-pentesters/) ambao utakuwa wa siri zaidi
* Unaweza pia [**tumia powerview**](../basic-powershell-for-pentesters/powerview.md) ili kutoa habari zaidi za kina
* Zana nyingine nzuri kwa uchunguzi katika active directory ni [**BloodHound**](bloodhound.md). Haifichi sana (kulingana na njia za ukusanyaji unazotumia), lakini **ikiwa hujali** kuhusu hilo, unapaswa kujaribu kabisa. Tafuta mahali ambapo watumiaji wanaweza kufanya RDP, tafuta njia ya vikundi vingine, nk.
* **Zana zingine za uhesabu wa AD zilizotumika ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Rekodi za DNS za AD**](ad-dns-records.md) kwani zinaweza kuwa na habari muhimu.
* Zana **yenye GUI** unayoweza kutumia kuhesabu saraka ni **AdExplorer.exe** kutoka **SysInternal** Suite.
* Unaweza pia kutafuta katika database ya LDAP na **ldapsearch** kutafuta siri katika uga _userPassword_ & _unixUserPassword_, au hata _Description_. angalia [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa njia nyingine.
* Ikiwa unatumia **Linux**, unaweza pia kuhesabu kikoa kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
* Unaweza pia kujaribu zana za otomatiki kama:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Kuchimbua watumiaji wote wa kikoa**

Ni rahisi sana kupata majina yote ya watumiaji wa kikoa kutoka kwa Windows (`net user /domain` ,`Get-DomainUser` au `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Uhesabu inaonekana ndogo hii ndio sehemu muhimu zaidi ya yote. Fikia viungo (hasa kwa cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuhesabu kikoa na jifunze hadi ujisikie vizuri. Wakati wa tathmini, hii itakuwa wakati muhimu wa kupata njia yako ya DA au kuamua kwamba hakuna kitu kinachoweza kufanywa.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumiwa na huduma zinazohusiana na akaunti za watumiaji na kuvunja usimbaji wao—ambao unategemea nywila za watumiaji—**nje ya mtandao**.

Zaidi kuhusu hii katika:

{% content-ref url="kerberoast.md" %}
### Uhusiano wa mbali (RDP, SSH, FTP, Win-RM, nk)

Baada ya kupata baadhi ya siri za kuingia, unaweza kuangalia ikiwa una ufikiaji wa **mashine** yoyote. Kwa hilo, unaweza kutumia **CrackMapExec** kujaribu kuunganisha kwenye seva kadhaa kwa itifaki tofauti, kulingana na uchunguzi wako wa bandari.

### Kuinua Hadhi ya Mamlaka ya Ndani

Ikiwa una siri zilizodukuliwa au kikao kama mtumiaji wa kawaida wa kikoa na una **ufikiaji** na mtumiaji huyu kwenye **mashine yoyote katika kikoa**, unapaswa jaribu kupata njia ya **kuinua hadhi ya mamlaka kwa kiwango cha ndani na kuiba siri**. Hii ni kwa sababu tu na hadhi ya msimamizi wa ndani utaweza **kudumpisha hash za watumiaji wengine** kwenye kumbukumbu (LSASS) na kwa kiwango cha ndani (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**kuinua hadhi ya mamlaka ya ndani katika Windows**](../windows-local-privilege-escalation/) na [**orodha ya ukaguzi**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tiketi za Kikao cha Sasa

Ni **hatari sana** kupata **tiketi** katika mtumiaji wa sasa **zilizokupa ruhusa ya kufikia** rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Ikiwa umefanikiwa kuchunguza kikamilifu active directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Huenda ukaweza kufanya mashambulizi ya NTML [**relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Tafuta Vitambulisho kwenye Sehemu za Kompyuta**

Sasa unapokuwa na vitambulisho vya msingi, unapaswa kuangalia ikiwa unaweza **kupata** faili **zinazovutia zinazoshirikiwa ndani ya AD**. Unaweza kufanya hivyo kwa mkono lakini ni kazi ya kuchosha na inarudia mara kwa mara (na zaidi ikiwa unapata mamia ya hati ambazo unahitaji kuzikagua).

[**Fuata kiungo hiki ili kujifunza juu ya zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Pora Vitambulisho vya NTLM

Ikiwa unaweza **kupata upatikanaji wa PC au sehemu zingine**, unaweza **kuweka faili** (kama faili ya SCF) ambayo ikiwa itafikiwa kwa njia fulani itasababisha **uthibitishaji wa NTML dhidi yako** ili uweze **kuiba** **changamoto ya NTLM** ili kuivunja:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Udhaifu huu uliruhusu mtumiaji yeyote aliye na **uthibitisho uliothibitishwa** kuweza **kudhoofisha kudhibiti kikoa**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Kuinua Uthibitisho wa Haki kwenye Active Directory NA vitambulisho/kikao cha haki

**Kwa mbinu zifuatazo, mtumiaji wa kawaida wa kikoa haitoshi, unahitaji baadhi ya haki/uthibitisho maalum ili kufanya mashambulizi haya.**

### Uchimbaji wa Hash

Kwa matumaini umeweza **kudhoofisha akaunti ya msimamizi wa ndani** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) pamoja na kusambaza, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [kuinua haki za ndani](../windows-local-privilege-escalation/).\
Kwa hivyo, ni wakati wa kudondosha hash zote kwenye kumbukumbu na kwa kifaa.\
[**Soma ukurasa huu kuhusu njia tofauti za kupata hash.**](broken-reference/)

### Pita Hash

**Marafiki unapokuwa na hash ya mtumiaji**, unaweza kuitumia kuwa **mtu mwingine**.\
Unahitaji kutumia **zana** fulani ambayo itafanya **uthibitisho wa NTLM** kwa kutumia **hash** hiyo, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** hash hiyo ndani ya **LSASS**, kwa hivyo wakati wowote **uthibitisho wa NTLM unafanywa**, hash hiyo itatumika. Chaguo la mwisho ndilo linalofanywa na mimikatz.\
[**Soma ukurasa huu kwa habari zaidi.**](../ntlm/#pass-the-hash)

### Pita Hash/Chaguo la Pita

Shambulio hili linalenga **kutumia hash ya NTLM ya mtumiaji kuomba tiketi za Kerberos**, kama mbadala wa shambulio la kawaida la Pass The Hash kwa njia ya itifaki ya NTLM. Kwa hivyo, hii inaweza kuwa hasa **nafuu katika mitandao ambapo itifaki ya NTLM imelemazwa** na tu **Kerberos inaruhusiwa** kama itifaki ya uthibitisho.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pita Tiketi

Katika njia ya **Pass The Ticket (PTT)** ya shambulio, wahalifu **wanateka tiketi ya uthibitisho ya mtumiaji** badala ya nywila au thamani za hash. Tiketi hii iliyoibiwa kisha hutumiwa kuwa **mtumiaji mwingine**, kupata ufikiaji usiohalali kwa rasilimali na huduma ndani ya mtandao.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Matumizi ya Upya wa Vitambulisho

Ikiwa una **hash** au **nywila** ya **msimamizi wa ndani**, unapaswa kujaribu kuingia **kwa njia ya ndani** kwenye **PCs** nyingine nayo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Tafadhali kumbuka kuwa hii ni **kelele** na **LAPS** itapunguza hilo.
{% endhint %}

### MSSQL Uvunjaji wa Usalama & Viungo Vilivyothibitishwa

Ikiwa mtumiaji ana mamlaka ya **kupata kwenye mifano ya MSSQL**, anaweza kutumia hiyo kutekeleza amri kwenye mwenyeji wa MSSQL (ikiwa inaendeshwa kama SA), **kuiba** hash ya NetNTLM au hata kufanya **shambulio la kuhamisha**. Pia, ikiwa mifano ya MSSQL inaaminika (kiungo cha hifadhidata) na mifano mingine ya MSSQL. Ikiwa mtumiaji ana mamlaka juu ya hifadhidata iliyoaminika, ataweza **kutumia uhusiano wa uaminifu kutekeleza maswali pia kwenye mfano mwingine**. Uaminifu huu unaweza kuunganishwa na kwa wakati fulani mtumiaji anaweza kupata hifadhidata iliyopangwa vibaya ambapo anaweza kutekeleza amri. **Viungo kati ya hifadhidata hufanya kazi hata kwenye uaminifu wa misitu.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Utekelezaji Usiozuiliwa

Ikiwa utapata kitu chochote cha Kompyuta na sifa ya [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) na una mamlaka ya kikoa kwenye kompyuta, utaweza kudump TGT kutoka kwenye kumbukumbu ya kila mtumiaji anayeingia kwenye kompyuta. Kwa hivyo, ikiwa **Msimamizi wa Kikoa anajiingiza kwenye kompyuta**, utaweza kudump TGT yake na kujifanya kuwa yeye kwa kutumia [Pass the Ticket](pass-the-ticket.md). Kwa msaada wa uhusiano uliozuiliwa, unaweza hata **kudhoofisha moja kwa moja Seva ya Uchapishaji** (kwa matumaini itakuwa DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Utekelezaji Uliozuiwa

Ikiwa mtumiaji au kompyuta inaruhusiwa kwa "Utekelezaji Uliozuiwa" itaweza **kujifanya kuwa mtumiaji yeyote ili kupata huduma fulani kwenye kompyuta**. Kisha, ikiwa utadhoofisha hash ya mtumiaji/kompyuta huyu utaweza **kujifanya kuwa mtumiaji yeyote** (hata wasimamizi wa kikoa) ili kupata huduma fulani.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Utekelezaji wa Kizuizi cha Rasilimali

Kuwa na **ruhusa ya KUANDIKA** kwenye kitu cha Active Directory cha kompyuta ya mbali kunawezesha kupata utekelezaji wa nambari na **mamlaka yaliyoinuliwa**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Uvunjaji wa Usalama wa ACLs

Mtumiaji aliyeathiriwa anaweza kuwa na **ruhusa za kuvutia juu ya vitu vya kikoa** ambavyo vinaweza kukuruhusu **kuhamia** kwa upande/**kuinua** mamlaka.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Uvunjaji wa Huduma ya Printer Spooler

Kugundua **huduma ya Spool inayosikiliza** ndani ya kikoa kunaweza **kutumiwa vibaya** kupata **vitambulisho vipya** na **kuinua mamlaka**.

{% content-ref url="acl-persistence-abuse/" %}
[printers-spooler-service-abuse](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Uvunjaji wa Vipindi vya Tatu

Ikiwa **watumiaji wengine wanapata** kompyuta **iliyovamiwa**, inawezekana **kukusanya vitambulisho kutoka kwenye kumbukumbu** na hata **kuingiza beacons kwenye michakato yao** ili kujifanya kuwa wao. Kawaida watumiaji watatumia mfumo kupitia RDP, kwa hivyo hapa una jinsi ya kufanya mashambulizi kadhaa kwenye vipindi vya tatu vya RDP:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** hutoa mfumo wa kusimamia nenosiri la **Msimamizi wa Mitaa** kwenye kompyuta zilizojiunga na kikoa, ikihakikisha kuwa ni **randomized**, ya kipekee, na mara kwa mara **inabadilishwa**. Nenosiri hizi zimehifadhiwa kwenye Active Directory na ufikiaji unadhibitiwa kupitia ACLs kwa watumiaji walioruhusiwa tu. Kwa idhini ya kutosha ya kupata nenosiri hizi, kugeuza kwa kompyuta zingine kunawezekana.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Wizi wa Vyeti

**Kukusanya vyeti** kutoka kwenye kompyuta iliyoathiriwa inaweza kuwa njia ya kuinua mamlaka ndani ya mazingira:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Uvunjaji wa Matumizi ya Vyeti

Ikiwa **vigezo hatarishi** vimeboreshwa inawezekana kuvitumia kuinua mamlaka:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Baada ya Uvamizi na Akaunti yenye Mamlaka Kubwa

### Kudumpa Vitambulisho vya Kikoa

Marafiki unapata mamlaka ya **Msimamizi wa Kikoa** au hata bora **Msimamizi wa Kampuni**, unaweza **kudump** hifadhidata ya kikoa: _ntds.dit_.

[**Maelezo zaidi kuhusu shambulio la DCSync yanaweza kupatikana hapa**](dcsync.md).

[**Maelezo zaidi kuhusu jinsi ya kuiba NTDS.dit yanaweza kupatikana hapa**](broken-reference/)

### Privesc kama Uthabiti

Baadhi ya mbinu zilizojadiliwa hapo awali zinaweza kutumika kwa uthabiti. Kwa mfano unaweza:

*   Kufanya watumiaji kuwa hatarini kwa [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <jina la mtumiaji> -Set @{serviceprincipalname="bandia/HAKUNA"}r
```
*   Kufanya watumiaji kuwa hatarini kwa [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <jina la mtumiaji> -XOR @{UserAccountControl=4194304}
```
*   Kutoa ruhusa za [**DCSync**](./#dcsync) kwa mtumiaji

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Tiketi ya Fedha

Shambulio la **Tiketi ya Fedha** linajenga **tiketi halali ya Huduma ya Kutoa Tiketi (TGS)** kwa huduma maalum kwa kutumia hash ya NTLM (kwa mfano, hash ya akaunti ya PC). Njia hii hutumiwa kufikia **mamlaka ya huduma**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Tiketi ya Dhahabu

Shambulio la **Tiketi ya Dhahabu** linahusisha mshambuliaji kupata **hash ya NTLM ya akaunti ya krbtgt** katika mazingira ya Active Directory (AD). Akaunti hii ni maalum kwa sababu
### **Uthibitisho wa Kudumu wa Kikoa kwa Kutumia Vyeti**

**Kwa kutumia vyeti, ni pia inawezekana kudumu na mamlaka kubwa ndani ya kikoa:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Kikundi cha AdminSDHolder

Kipengele cha **AdminSDHolder** katika Active Directory kinahakikisha usalama wa **vikundi vyenye mamlaka** (kama Domain Admins na Enterprise Admins) kwa kutumia **Orodha ya Udhibiti wa Upatikanaji (ACL)** kwenye vikundi hivi ili kuzuia mabadiliko yasiyoruhusiwa. Walakini, kipengele hiki kinaweza kutumiwa vibaya; ikiwa mshambuliaji anabadilisha ACL ya AdminSDHolder ili kumpa mtumiaji wa kawaida ufikiaji kamili, mtumiaji huyo anapata udhibiti mkubwa juu ya vikundi vyote vyenye mamlaka. Hatua hii ya usalama, iliyokusudiwa kulinda, inaweza kusababisha ufikiaji usiohitajika isipokuwa ikifuatiliwa kwa karibu.

[**Maelezo zaidi kuhusu Kikundi cha AdminSDHolder hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Domain Controller (DC)**, akaunti ya **msimamizi wa ndani** ipo. Kwa kupata haki za msimamizi kwenye kifaa kama hicho, hash ya Msimamizi wa ndani inaweza kuchukuliwa kwa kutumia **mimikatz**. Baada ya hapo, marekebisho ya usajili yanahitajika kuwezesha matumizi ya nenosiri hili, kuruhusu ufikiaji wa kijijini kwenye akaunti ya Msimamizi wa ndani.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Uthibitisho wa ACL

Unaweza **kumpa** mtumiaji **mamlaka maalum** juu ya vitu fulani maalum vya kikoa ambavyo vitamruhusu mtumiaji **kuongeza mamlaka baadaye**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descriptors za Usalama

Descriptors za usalama hutumiwa kuhifadhi **mamlaka** ambayo **kitu** ina **juu** ya **kitu kingine**. Ikiwa unaweza **kufanya** mabadiliko **kidogo** kwenye maelezo ya usalama ya kitu, unaweza kupata mamlaka muhimu sana juu ya kitu hicho bila kuwa mwanachama wa kikundi cha mamlaka.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

Badilisha **LSASS** kwenye kumbukumbu ili kuweka **nenosiri la jumla**, kuruhusu ufikiaji wa akaunti zote za kikoa.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP ya Kibinafsi

[Jifunze ni nini SSP (Mtoa Msaada wa Usalama) hapa.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kukamata** kwa **maandishi wazi** **vyeti** vinavyotumiwa kupata ufikiaji kwenye kifaa.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Inasajili **Domain Controller mpya** katika AD na kuitumia kuweka sifa (SIDHistory, SPNs...) kwenye vitu vilivyotajwa **bila** kuacha **kumbukumbu** yoyote kuhusu **mabadiliko**. Unahitaji mamlaka ya DA na kuwa ndani ya **kikoa cha msingi**.\
Tafadhali kumbuka kuwa ikiwa utatumia data isiyo sahihi, kumbukumbu mbaya sana zitaonekana.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Uthibitisho wa LAPS

Tulijadili hapo awali jinsi ya kuongeza mamlaka ikiwa una **ruhusa ya kutosha kusoma nywila za LAPS**. Walakini, nywila hizi pia zinaweza kutumika kudumisha uthibitisho wa kudumu.\
Angalia:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Kuongeza Mamlaka ya Kuvuka Kikoa - Uthibitisho wa Kikoa

Microsoft inaona **Msitu** kama mpaka wa usalama. Hii inamaanisha kwamba **kudukua kikoa kimoja kunaweza kusababisha kudukuliwa kwa Msitu mzima**.

### Taarifa Msingi

[**Uthibitisho wa kikoa**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) ni mbinu ya usalama inayowezesha mtumiaji kutoka **kikoa** kimoja kupata rasilimali katika **kikoa** kingine. Kimsingi, inajenga uhusiano kati ya mifumo ya uthibitisho ya vikoa viwili, kuruhusu uthibitisho kufanyika kwa urahisi. Wakati vikoa vinapoweka uaminifu, hubadilishana na kuhifadhi **funguo maalum** ndani ya **Domain Controllers (DCs)**, ambayo ni muhimu kwa uadilifu wa uaminifu huo.

Katika hali ya kawaida, ikiwa mtumiaji anataka kupata huduma katika **kikoa kilichouaminika**, lazima kwanza aombe tiketi maalum inayojulikana kama **inter-realm TGT** kutoka kwa DC ya kikoa chake. TGT hii imefichwa kwa kutumia **funguo maalum** ambayo vikoa vyote vimekubaliana. Mtumiaji kisha huwasilisha TGT hii kwa **DC ya kikoa kilichouaminika** ili kupata tiketi ya huduma (**TGS**). Baada ya kuthibitisha TGT ya kati-kikoa kwa DC ya kikoa kilichouaminika, inatoa TGS, ikimruhusu mtumiaji kupata huduma.

**Hatua**:

1. **Kompyuta mteja** katika **Kikoa 1** inaanza mchakato kwa kutumia **hash ya NTLM** kuomba **Tiketi ya Kutoa Tiketi (TGT)** kutoka kwa **Domain Controller (DC1)** yake.
2. DC1 inatoa TGT mpya ikiwa mteja anathibitishwa kwa mafanikio.
3. Mteja kisha anaripoti **inter-realm TGT** kutoka kwa DC1, ambayo inahitajika kupata rasilimali katika **Kikoa 2**.
4. Inter-realm TGT imefichwa kwa kutumia **funguo cha uaminifu** kinachoshirikiwa kati ya DC1 na DC2 kama sehemu ya uaminifu wa pande mbili wa vikoa.
5. Mteja anachukua inter-realm TGT kwa **Domain Controller (DC2)** ya Kikoa 2.
6. DC2 inathibitisha inter-realm TGT kwa kutumia funguo la uaminifu lililoshirikiwa na, ikiwa ni halali, inatoa **Tiketi ya Huduma ya Kutoa Tiketi (TGS)** kwa seva katika Kikoa 2 ambayo mteja anataka kupata.
7. Hatimaye, mteja anawasilisha TGS hii kwa seva, ambayo imefichwa kwa kutum
#### Tofauti nyingine katika **uaminifu wa uhusiano**

* Uhusiano wa uaminifu unaweza pia kuwa **wa kusambazana** (A anamwamini B, B anamwamini C, basi A anamwamini C) au **usiokuwa wa kusambazana**.
* Uhusiano wa uaminifu unaweza kuwekwa kama **uaminifu wa pande mbili** (wote wanamwamini mwingine) au kama **uaminifu wa upande mmoja** (mmoja wao tu anamwamini mwingine).

### Njia ya Shambulio

1. **Tambua** uhusiano wa uaminifu
2. Angalia ikiwa **mada za usalama** (mtumiaji/kikundi/kompyuta) zina **upatikanaji** wa rasilimali za **kikoa kingine**, labda kupitia kuingia kwa ACE au kwa kuwa katika vikundi vya kikoa kingine. Tafuta **uhusiano kati ya vikoa** (uaminifu ulianzishwa kwa hili labda).
1. katika kesi hii, kerberoast inaweza kuwa chaguo lingine.
3. **Dhoofisha** akaunti ambazo zinaweza **kupitia** kupitia vikoa.

Wahalifu wenye ufikiaji wa rasilimali katika kikoa kingine wanaweza kutumia njia tatu kuu:

- **Uanachama wa Kikundi cha Ndani**: Mada zinaweza kuongezwa kwenye vikundi vya ndani kwenye mashine, kama vile kikundi cha "Wasimamizi" kwenye seva, ambayo inawapa udhibiti mkubwa juu ya mashine hiyo.
- **Uanachama wa Kikundi cha Kikoa cha Kigeni**: Mada pia inaweza kuwa mwanachama wa vikundi ndani ya kikoa cha kigeni. Walakini, ufanisi wa njia hii unategemea asili ya uaminifu na wigo wa kikundi.
- **Orodha za Kudhibiti Upatikanaji (ACL)**: Mada inaweza kutajwa katika **ACL**, haswa kama vitengo katika **ACEs** ndani ya **DACL**, ikitoa upatikanaji wao kwa rasilimali maalum. Kwa wale wanaotaka kujifunza zaidi juu ya uhandisi wa ACLs, DACLs, na ACEs, karatasi nyeupe iliyoitwa "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)" ni rasilimali muhimu.

### Kuongeza haki za kufikia kikoa cha mtoto kwa mzazi
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
Unaweza kupata ile inayotumiwa na kikoa cha sasa kwa kutumia:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Uingizaji wa SID-History

Kuongeza hadhi kama Msimamizi wa Kampuni kwa kudanganya uaminifu na uingizaji wa SID-History kwa kikoa cha mtoto/cha mzazi:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Kutumia Configuration NC inayoweza kuandikwa

Kuelewa jinsi Configuration Naming Context (NC) inavyoweza kutumiwa ni muhimu. Configuration NC inatumika kama hazina kuu ya data ya usanidi katika mazingira ya Active Directory (AD) ya msitu. Data hii inarekebishwa kwa kila Domain Controller (DC) ndani ya msitu, na DC zinazoweza kuandikwa zinahifadhi nakala inayoweza kuandikwa ya Configuration NC. Ili kutumia hii, mtu lazima awe na **mamlaka ya SYSTEM kwenye DC**, kwa upendeleo DC ya mtoto.

**Weka kiungo cha GPO kwenye tovuti ya DC ya mzizi**

Chombo cha Configuration NC's Sites kina habari kuhusu tovuti za kompyuta zote zilizounganishwa na kikoa ndani ya msitu wa AD. Kwa kufanya kazi na mamlaka ya SYSTEM kwenye DC yoyote, wadukuzi wanaweza kuweka viungo vya GPO kwenye tovuti za DC za mzizi. Hatua hii inaweza kuhatarisha kikoa cha mzizi kwa kubadilisha sera zilizotekelezwa kwenye tovuti hizi.

Kwa habari zaidi, mtu anaweza kuchunguza utafiti juu ya [Kuvuka Kizuizi cha SID](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Dhoofisha gMSA yoyote katika msitu**

Mbinu ya shambulio inahusisha kulenga gMSA zenye mamlaka ndani ya kikoa. Kifungu cha KDS Root, muhimu kwa kuhesabu nywila za gMSA, kimehifadhiwa ndani ya Configuration NC. Kwa mamlaka ya SYSTEM kwenye DC yoyote, ni rahisi kupata KDS Root na kuhesabu nywila za gMSA kote msitu.

Uchambuzi wa kina unaweza kupatikana katika mjadala juu ya [Shambulio la Imani ya Golden gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Shambulio la mabadiliko ya Schema**

Mbinu hii inahitaji subira, kusubiri kwa uundaji wa vitu vipya vya AD vyenye mamlaka. Kwa mamlaka ya SYSTEM, mshambuliaji anaweza kubadilisha Schema ya AD ili kumpa mtumiaji yeyote udhibiti kamili juu ya madarasa yote. Hii inaweza kusababisha ufikiaji usiohalali na udhibiti juu ya vitu vya AD vilivyoundwa hivi karibuni.

Kusoma zaidi kunapatikana kwenye [Shambulio la Imani ya Mabadiliko ya Schema](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Kutoka DA hadi EA na ADCS ESC5**

Udhaifu wa ADCS ESC5 unalenga udhibiti juu ya vitu vya Miundombinu ya Umma ya Ufunguo (PKI) ili kuunda templeti ya cheti inayowezesha uwakilishi kama mtumiaji yeyote ndani ya msitu. Kwa kuwa vitu vya PKI viko ndani ya Configuration NC, kudhoofisha DC ya mtoto inayoweza kuandikwa kunawezesha utekelezaji wa mashambulio ya ESC5.

Maelezo zaidi juu ya hii yanaweza kusomwa katika [Kutoka DA hadi EA na ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika mazingira ambayo hayana ADCS, mshambuliaji ana uwezo wa kuweka sehemu muhimu, kama ilivyozungumziwa katika [Kuongeza Hadhi kutoka kwa Wasimamizi wa Kikoa cha Mtoto hadi Wasimamizi wa Kampuni](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Kikoa cha Msitu wa Nje - Moja-Kwa-Moja (Kuingia) au bidirectional
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
Katika hali hii **kikoa chako kinaaminika** na kimoja cha nje kinachokupa **ruhusa zisizojulikana** juu yake. Utahitaji kupata **wakuu gani wa kikoa chako wana ufikiaji gani juu ya kikoa cha nje** na kisha jaribu kuitumia:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Kikoa cha Msitu cha Nje - Moja-Njia (Kutoka)
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
Katika kesi hii **kikoa chako** kinaweka **imani** fulani kwa mkuu kutoka **vikoa tofauti**.

Hata hivyo, wakati **kikoa kinaweka imani** kwa kikoa kinachoiamini, kikoa kilichoaminiwa **hujenga mtumiaji** na **jina linaloweza kutabirika** ambalo linatumia **nenosiri lililoaminiwa**. Hii inamaanisha kwamba ni **rahisi kufikia mtumiaji kutoka kikoa kinachoiamini ili kuingia kwenye kikoa kilichoaminiwa** ili kulitambua na kujaribu kuongeza mamlaka zaidi:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Njia nyingine ya kudhoofisha kikoa kilichoaminiwa ni kupata [**kiunga cha kuaminika cha SQL**](abusing-ad-mssql.md#mssql-trusted-links) kilichoundwa katika **mwelekeo tofauti** na uaminifu wa kikoa (ambao sio wa kawaida).

Njia nyingine ya kudhoofisha kikoa kilichoaminiwa ni kusubiri kwenye kifaa ambapo **mtumiaji kutoka kikoa kilichoaminiwa anaweza kupata** kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza nambari katika mchakato wa kikao cha RDP na **kufikia kikoa cha asili cha muathirika** kutoka hapo.\
Zaidi ya hayo, ikiwa **muathirika amefunga diski yake ngumu**, kutoka kwenye mchakato wa kikao cha RDP, mshambuliaji anaweza kuhifadhi **nyuma-mlango** kwenye **folda ya kuanza ya diski ngumu**. Mbinu hii inaitwa **RDPInception**.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Kupunguza Ukiukaji wa Imani ya Kikoa

### **SID Filtering:**

- Hatari ya mashambulizi yanayotumia sifa ya historia ya SID kwenye uaminifu wa misitu inapunguzwa na SID Filtering, ambayo imeamilishwa kwa chaguo-msingi kwenye uaminifu wa misitu yote kati ya misitu. Hii inategemea dhana kwamba uaminifu wa ndani wa misitu ni salama, ikizingatiwa misitu badala ya vikoa kama mpaka wa usalama kulingana na msimamo wa Microsoft.
- Walakini, kuna tatizo: SID filtering inaweza kuvuruga programu na ufikiaji wa mtumiaji, na hivyo kusababisha deactivation yake mara kwa mara.

### **Uthibitishaji wa Kuchagua:**

- Kwa uaminifu wa misitu, kutumia Uthibitishaji wa Kuchagua kunahakikisha kuwa watumiaji kutoka misitu miwili hawathibitishwi moja kwa moja. Badala yake, idhini wazi inahitajika kwa watumiaji kupata vikoa na seva ndani ya kikoa au misitu inayoiamini.
- Ni muhimu kutambua kuwa hatua hizi hazilindi dhidi ya udanganyifu wa Writable Configuration Naming Context (NC) au mashambulizi kwenye akaunti ya uaminifu.

[**Maelezo zaidi kuhusu imani za kikoa katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Ulinzi Mkuu

[**Jifunze zaidi kuhusu jinsi ya kulinda vibali hapa.**](../stealing-credentials/credentials-protections.md)\

### **Hatua za Ulinzi kwa Kulinda Vibali**

- **Vikwazo vya Wasimamizi wa Kikoa**: Inapendekezwa kuwa Wasimamizi wa Kikoa wanapaswa kuruhusiwa kuingia tu kwenye Wadhibiti wa Kikoa, kuepuka matumizi yao kwenye mwenyeji mwingine.
- **Vipengele vya Akaunti ya Huduma**: Huduma hazipaswi kuendeshwa na mamlaka ya Wasimamizi wa Kikoa (DA) ili kudumisha usalama.
- **Upeo wa Muda wa Mamlaka**: Kwa kazi zinazohitaji mamlaka ya DA, muda wao unapaswa kuwa mdogo. Hii inaweza kufanikiwa kwa: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Kutekeleza Mbinu za Udanganyifu**

- Kutekeleza udanganyifu kunahusisha kuweka mitego, kama watumiaji au kompyuta bandia, na vipengele kama nywila ambazo hazitamalizika au zimeorodheshwa kama Zilizoaminika kwa Uteuzi. Mbinu ya kina ni pamoja na kuunda watumiaji wenye haki maalum au kuwaongeza kwenye vikundi vya mamlaka ya juu.
- Mfano wa vitendo ni kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Zaidi juu ya kutekeleza mbinu za udanganyifu inaweza kupatikana kwenye [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Udanganyifu**

- **Kwa Vitu vya Mtumiaji**: Viashiria vya shaka ni pamoja na ObjectSID isiyokuwa ya kawaida, kuingia mara chache, tarehe za uundaji, na idadi ndogo ya nywila mbaya.
- **Viashiria vya Jumla**: Kulinganisha sifa za vitu vya udanganyifu inayowezekana na zile za vitu halisi kunaweza kufunua kutofautiana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) inaweza kusaidia kutambua udanganyifu kama huo.

### **Kuepuka Mifumo ya Uchunguzi**

- **Kuepuka Uchunguzi wa Microsoft ATA**:
- **Uchunguzi wa Watumiaji**: Kuepuka uchunguzi wa kikao kwenye Wadhibiti wa Kikoa ili kuzuia uchunguzi wa ATA.
- **Uigaji wa Tiketi**: Kutumia funguo za **aes** kwa uundaji wa tiketi husaidia kuepuka uchunguzi kwa kutofanya kushuka hadi NTLM.
- **Mashambulizi ya DCSync**: Kutekeleza kutoka kwa seva isiyo ya Wadhibiti wa Kikoa ili kuepuka uchunguzi wa ATA inashauriwa, kwani utekelezaji moja kwa moja kutoka kwa Wadhibiti wa Kikoa utasababisha tahadhari.

## Marejeo

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge
