# Mbinu ya Active Directory

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJISAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Muhtasari wa Msingi

**Active Directory** inatumika kama teknolojia ya msingi, ikiruhusu **waandamizi wa mtandao** kuunda na kusimamia kwa ufanisi **domains**, **watumiaji**, na **vitu** ndani ya mtandao. Imeundwa kwa ajili ya kupanuka, ikirahisisha utaratibu wa kuandaa idadi kubwa ya watumiaji katika **makundi** na **makundi ya pili**, huku ikidhibiti **haki za ufikiaji** kwa viwango mbalimbali.

Muundo wa **Active Directory** unajumuisha safu tatu kuu: **domains**, **miti**, na **misitu**. **Domain** inajumuisha mkusanyiko wa vitu, kama vile **watumiaji** au **vifaa**, vinavyoshiriki database moja. **Miti** ni makundi ya domains haya yanayounganishwa na muundo unaoshirikiwa, na **msitu** unawakilisha mkusanyiko wa miti kadhaa, zilizounganishwa kupitia **mahusiano ya uaminifu**, ikifomu safu ya juu kabisa ya muundo wa shirika. **Haki maalum** za ufikiaji na mawasiliano zinaweza kutengwa kwa kila kiwango hiki.

Mawazo muhimu ndani ya **Active Directory** ni pamoja na:

1. **Directory** – Inahifadhi habari zote kuhusu vitu vya Active Directory.
2. **Object** – Inaashiria vitengo ndani ya directory, ikiwa ni pamoja na **watumiaji**, **makundi**, au **folda zilizoshirikiwa**.
3. **Domain** – Inatumika kama chombo cha kuhifadhi vitu vya directory, na uwezo wa domains nyingi kuwepo ndani ya **msitu**, kila moja ikihifadhi mkusanyiko wake wa vitu.
4. **Tree** – Kikundi cha domains kinachoshiriki domain kuu.
5. **Forest** – Kilele cha muundo wa shirika katika Active Directory, kilichoundwa na miti kadhaa yenye **mahusiano ya uaminifu** kati yao.

**Huduma za Domain za Active Directory (AD DS)** zinajumuisha aina mbalimbali za huduma muhimu kwa usimamizi wa kati na mawasiliano ndani ya mtandao. Huduma hizi ni pamoja na:

1. **Huduma za Domain** – Inahifadhi data na kusimamia mwingiliano kati ya **watumiaji** na **domains**, ikiwa ni pamoja na **uthibitishaji** na **utafutaji**.
2. **Huduma za Cheti** – Inasimamia uundaji, usambazaji, na usimamizi wa **vyeti vya kidijitali** salama.
3. **Huduma za Directory Ndogo** – Inasaidia programu zinazoruhusu directory kupitia **itifaki ya LDAP**.
4. **Huduma za Ufederesheni wa Directory** – Hutoa uwezo wa **kuingia mara moja** ili kuthibitisha watumiaji kwenye programu za wavuti kadhaa katika kikao kimoja.
5. **Usimamizi wa Haki** – Husaidia kulinda vifaa vya hakimiliki kwa kudhibiti usambazaji na matumizi yake yasiyoruhusiwa.
6. **Huduma za DNS** – Muhimu kwa kutatua **majina ya domain**.

Kwa maelezo zaidi angalia: [**TechTerms - Ufafanuzi wa Active Directory**](https://techterms.com/definition/active\_directory)

### **Uthibitishaji wa Kerberos**

Ili kujifunza jinsi ya **kudukua AD** unahitaji **kuelewa** vizuri mchakato wa **uthibitishaji wa Kerberos**.\
[**Soma ukurasa huu ikiwa bado haujui jinsi inavyofanya kazi.**](kerberos-authentication.md)

## Orodha ya Udanganyifu

Unaweza kwenda [https://wadcoms.github.io/](https://wadcoms.github.io) kuona haraka amri zipi unaweza kutumia kwa kuchunguza/kudukua AD.

## Uchunguzi wa Active Directory (Bila sifa/vikao)

Ikiwa una ufikiaji kwenye mazingira ya AD lakini huna sifa/vikao unaweza:

* **Pentest mtandao:**
* Tafuta mtandao, pata mashine na milango iliyofunguliwa na jaribu **kudukua udhaifu** au **kupata sifa** kutoka kwao (kwa mfano, [printers zinaweza kuwa malengo mazuri sana](ad-information-in-printers.md).
* Kuchunguza DNS kunaweza kutoa habari kuhusu seva muhimu katika uwanja kama vile wavuti, printers, hisa, vpn, media, nk.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Angalia [**Mbinu ya Kudukua ya Jumla**](../../generic-methodologies-and-resources/pentesting-methodology.md) kupata maelezo zaidi kuhusu jinsi ya kufanya hivi.
* **Angalia upatikanaji wa null na Guest kwenye huduma za smb** (hii haitafanya kazi kwenye toleo za kisasa za Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Mwongozo wa kina zaidi kuhusu jinsi ya kuchunguza seva ya SMB unaweza kupatikana hapa:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Chunguza Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Mwongozo wa kina zaidi kuhusu jinsi ya kuchunguza LDAP unaweza kupatikana hapa (angalia **upatikanaji wa anonimasi**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Ghilibu mtandao**
* Kusanya sifa [**kujifanya kuwa huduma na Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Fikia mwenyeji kwa [**kutumia shambulio la kuhamisha**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Kusanya sifa **kwa kuweka wazi** [**huduma deep UPnP na evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Chukua majina ya watumiaji/majina kutoka kwa nyaraka za ndani, mitandao ya kijamii, huduma (hasa wavuti) ndani ya mazingira ya uwanja na pia kutoka kwa zinazopatikana hadharani.
* Ikiwa unapata majina kamili ya wafanyakazi wa kampuni, unaweza kujaribu **mikataba ya majina ya watumiaji wa AD (**[**soma hii**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Mikataba ya kawaida ni: _JinaJinaLaMwisho_, _Jina.Pembejeo_, _NamSur_ (herufi 3 za kila moja), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameJina_, _Surname.Jina_, _SurnameN_, _Surname.N_, herufi 3 _za kubahatisha na nambari 3 za kubahatisha_ (abc123).
* Zana:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)
### Uchambuzi wa Watumiaji

* **Uchambuzi wa SMB/LDAP wa Anonimasi:** Angalia kurasa za [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) na [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Uchambuzi wa Kerbrute**: Wakati **jina lisilo sahihi la mtumiaji linapotakiwa**, server itajibu kwa kutumia **kificho cha hitilafu cha Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, kuruhusu kutambua kuwa jina la mtumiaji lilikuwa lisilo sahihi. **Majina sahihi ya mtumiaji** yataleta jibu la **TGT katika majibu ya AS-REP** au hitilafu _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, ikionyesha kuwa mtumiaji anahitajika kufanya uthibitishaji wa awali.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Seva ya OWA (Outlook Web Access)**

Ikiwa umepata moja ya seva hizi kwenye mtandao unaweza pia kufanya **utambuzi wa mtumiaji dhidi yake**. Kwa mfano, unaweza kutumia zana [**MailSniper**](https://github.com/dafthack/MailSniper):
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
Unaweza kupata orodha ya majina ya watumiaji katika [**repo hii ya github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) na hii nyingine ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Hata hivyo, unapaswa kuwa na **jina la watu wanaofanya kazi katika kampuni** kutoka hatua ya uchunguzi ambayo unapaswa kufanya kabla ya hii. Kwa kutumia jina na jina la mwisho unaweza kutumia script [**namemash.py**](https://gist.github.com/superkojiman/11076951) kuunda majina ya watumiaji yanayowezekana.
{% endhint %}

### Kujua jina moja au majina kadhaa ya watumiaji

Sawa, basi unajua tayari una jina la mtumiaji halali lakini hakuna nywila... Kisha jaribu:

* [**ASREPRoast**](asreproast.md): Ikiwa mtumiaji **haina** sifa ya _DONT\_REQ\_PREAUTH_ unaweza **kuomba ujumbe wa AS\_REP** kwa mtumiaji huyo ambao utaleta baadhi ya data iliyofichwa kwa kutumia mabadiliko ya nywila ya mtumiaji.
* [**Password Spraying**](password-spraying.md): Hebu jaribu **nywila za kawaida** na kila mmoja wa watumiaji uliowagundua, labda baadhi ya watumiaji wanatumia nywila mbaya (kumbuka sera ya nywila!).
* Tafadhali kumbuka unaweza pia **kupuliza seva za OWA** kujaribu kupata ufikivu wa seva za barua pepe za watumiaji.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Poisoning

Unaweza kuweza **kupata** baadhi ya changamoto **hashes** za kuvunja **sumu** za baadhi ya itifaki za **mtandao**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Ikiwa umefanikiwa kuchambua kikamilifu saraka ya active directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza kuweza kufanya mashambulizi ya [**relay ya NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) **kupata ufikivu wa mazingira ya AD**.

### Kuiba NTLM Creds

Ikiwa unaweza **kufikia PC nyingine au kushirikiana** na mtumiaji **wa null au mgeni** unaweza **kuweka faili** (kama faili ya SCF) ambayo ikiwa itafikiwa kwa njia fulani ita**chochea uthibitisho wa NTML dhidi yako** ili uweze **kuiba** **changamoto ya NTLM** kuvunja:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Kuchambua Active Directory NA vibali/session

Kwa hatua hii unahitaji **kuvunja vibali au kikao cha akaunti halali ya kikoa.** Ikiwa una vibali halali au shell kama mtumiaji wa kikoa, **kumbuka kuwa chaguzi zilizotolewa hapo awali bado ni chaguzi za kuvunja watumiaji wengine**.

Kabla ya kuanza uchambuzi uliothibitishwa unapaswa kujua ni nini **tatizo la mara mbili la hop la Kerberos.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Uchambuzi

Kwa kuvunja akaunti ni **hatua kubwa ya kuanza kuvunja kikoa nzima**, kwa sababu utaweza kuanza **Uchambuzi wa Active Directory:**

Kuhusiana na [**ASREPRoast**](asreproast.md) sasa unaweza kupata kila mtumiaji anayeweza kuathirika, na kuhusiana na [**Password Spraying**](password-spraying.md) unaweza kupata **orodha ya majina ya watumiaji wote** na kujaribu nywila ya akaunti iliyovunjwa, nywila zisizo na nywila na nywila mpya za kutia moyo.

* Unaweza kutumia [**CMD kufanya uchunguzi wa msingi**](../basic-cmd-for-pentesters.md#domain-info)
* Unaweza pia kutumia [**powershell kwa uchunguzi**](../basic-powershell-for-pentesters/) ambao utakuwa wa siri zaidi
* Unaweza pia [**tumia powerview**](../basic-powershell-for-pentesters/powerview.md) kutoa maelezo zaidi
* Zana nyingine nzuri kwa uchunguzi katika active directory ni [**BloodHound**](bloodhound.md). Sio **siri sana** (kulingana na njia za ukusanyaji unazotumia), lakini **ikiwa hujali** kuhusu hilo, unapaswa kujaribu kabisa. Pata mahali watumiaji wanaweza kufanya RDP, pata njia kwa vikundi vingine, n.k.
* **Zana zingine za uchambuzi wa AD zilizotumika ni:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Rekodi za DNS za AD**](ad-dns-records.md) kwani zinaweza kuwa na habari muhimu.
* Zana **yenye GUI** unayoweza kutumia kuchambua saraka ni **AdExplorer.exe** kutoka **SysInternal** Suite.
* Unaweza pia kutafuta katika database ya LDAP na **ldapsearch** kutafuta vibali katika uga wa _userPassword_ & _unixUserPassword_, au hata kwa _Description_. angalia [Password katika Maoni ya Mtumiaji wa AD kwenye PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) kwa njia nyingine.
* Ikiwa unatumia **Linux**, unaweza pia kuchambua kikoa kwa kutumia [**pywerview**](https://github.com/the-useless-one/pywerview).
* Unaweza pia kujaribu zana za otomatiki kama:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Kuchimbua watumiaji wote wa kikoa**

Ni rahisi sana kupata majina yote ya watumiaji wa kikoa kutoka Windows (`net user /domain`, `Get-DomainUser` au `wmic useraccount get name,sid`). Katika Linux, unaweza kutumia: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` au `enum4linux -a -u "user" -p "password" <DC IP>`

> Hata kama sehemu hii ya Uchambuzi inaonekana ndogo hii ndio sehemu muhimu zaidi. Fikia viungo (hasa ule wa cmd, powershell, powerview na BloodHound), jifunze jinsi ya kuchambua kikoa na jifunze hadi ujisikie vizuri. Wakati wa tathmini, hii itakuwa wakati muhimu sana wa kupata njia yako kwa DA au kuamua kwamba hakuna kitu kinaweza kufanywa.

### Kerberoast

Kerberoasting inahusisha kupata **TGS tickets** zinazotumiwa na huduma zilizounganishwa na akaunti za watumiaji na kuvunja encryption yao—ambayo inategemea nywila za watumiaji—**nje ya mtandao**.

Zaidi kuhusu hii katika:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}
### Uunganisho wa mbali (RDP, SSH, FTP, Win-RM, nk)

Maranyi ya kupata baadhi ya siri unaweza kuangalia kama una **upatikanaji wa** **mashine** yoyote. Kwa hili, unaweza kutumia **CrackMapExec** kujaribu kuunganisha kwenye seva kadhaa kwa itifaki tofauti, kulingana na uchunguzi wako wa bandari.

### Kupandisha Hadhi ya Mamlaka ya Kienyeji

Ikiwa umepata siri au kikao kama mtumiaji wa kawaida wa kikoa na una **upatikanaji** na mtumiaji huyu kwa **mashine yoyote kwenye kikoa** unapaswa kujaribu kupata njia yako ya **kupandisha hadhi kienyeji na kuiba siri**. Hii ni kwa sababu tu na mamlaka ya msimamizi wa kienyeji utaweza **kudumpisha hash za watumiaji wengine** kwenye kumbukumbu (LSASS) na kienyeji (SAM).

Kuna ukurasa kamili katika kitabu hiki kuhusu [**kupandisha hadhi ya kienyeji kwenye Windows**](../windows-local-privilege-escalation/) na [**orodha ya ukaguzi**](../checklist-windows-privilege-escalation.md). Pia, usisahau kutumia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tiketi za Kikao cha Sasa

Ni **isivyowezekana sana** kupata **tiketi** katika mtumiaji wa sasa **kukupatia ruhusa ya kupata** rasilimali zisizotarajiwa, lakini unaweza kuangalia:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Ikiwa umefanikiwa kuchambua kikamilifu active directory utakuwa na **barua pepe zaidi na uelewa bora wa mtandao**. Unaweza kuweza kufanya mashambulizi ya **relay ya NTML**.

### **Tafuta Creds katika Hisa za Kompyuta**

Sasa ukiwa na sifa za msingi unapaswa kuangalia kama unaweza **kupata** faili **zenye kuvutia zinazoshirikishwa ndani ya AD**. Unaweza kufanya hivyo kwa mkono lakini ni kazi ya kuchosha na inarudia mara kwa mara (na zaidi ikiwa utapata mamia ya nyaraka unahitaji kuchunguza).

[**Fuata kiungo hiki kujifunza kuhusu zana unazoweza kutumia.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Pora NTLM Creds

Ikiwa unaweza **kupata PCs au hisa zingine** unaweza **kuweka faili** (kama faili ya SCF) ambayo ikiwa itafikiwa kwa njia fulani ita**chochea uthibitisho wa NTML dhidi yako** ili uweze **kuiba** **changamoto ya NTLM** ili kuibuka:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Udhaifu huu uliruhusu mtumiaji yeyote aliye na **uthibitisho kuingilia kati kwenye kudhibiti kikoa**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Kupandisha Mamlaka kwenye Active Directory NA sifa/kipindi cha mamlaka

**Kwa mbinu zifuatazo, mtumiaji wa kawaida wa kikoa haitoshi, unahitaji baadhi ya mamlaka/nyeti za sifa kutekeleza mashambulizi haya.**

### Uchimbaji wa Hash

Kwa matumaini umefanikiwa **kudhoofisha akaunti ya msimamizi wa ndani** kwa kutumia [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) pamoja na kurejelea, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [kupandisha mamlaka kwa ndani](../windows-local-privilege-escalation/).\
Kisha, ni wakati wa kudondosha hash zote kwenye kumbukumbu na kwa ndani.\
[**Soma ukurasa huu kuhusu njia tofauti za kupata hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pita Hash

**Marafiki unapokuwa na hash ya mtumiaji**, unaweza kutumia ku**iga**.\
Unahitaji kutumia **zana** ambayo itafanya **uthibitisho wa NTLM kwa kutumia** hash hiyo, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** hash hiyo ndani ya **LSASS**, hivyo wakati wowote **uthibitisho wa NTLM unafanywa**, hash hiyo itatumika. Chaguo la mwisho ndilo linalofanywa na mimikatz.\
[**Soma ukurasa huu kwa maelezo zaidi.**](../ntlm/#pass-the-hash)

### Pita Hash Zaidi/Pita Ufunguo

Shambulio hili linalenga **kutumia hash ya NTLM ya mtumiaji kuomba tiketi za Kerberos**, kama mbadala kwa Pass The Hash ya kawaida juu ya itifaki ya NTLM. Kwa hivyo, hii inaweza kuwa hasa **yenye manufaa katika mitandao ambapo itifaki ya NTLM imelemazwa** na tu **Kerberos inaruhusiwa** kama itifaki ya uthibitisho.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pita Tiketi

Katika njia ya shambulio ya **Pass The Ticket (PTT)**, wadukuzi **huiba tiketi ya uthibitisho wa mtumiaji** badala ya nywila au hash. Tiketi hii iliyoibiwa kisha hutumiwa **kuiga mtumiaji**, kupata ufikivu usioruhusiwa kwenye rasilimali na huduma ndani ya mtandao.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Matumizi ya Upya ya Sifa

Ikiwa una **hash** au **nywila** ya **msimamizi wa ndani** unapaswa kujaribu **kuingia kwa ndani** kwenye **PCs** zingine nayo.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Tafadhali kumbuka kuwa hii ni **kelele** na **LAPS** itasaidia **kupunguza** hilo.
{% endhint %}

### MSSQL Uvunjaji & Viungo Vilivyothibitishwa

Ikiwa mtumiaji ana **ruhusa ya kufikia mifano ya MSSQL**, anaweza kutumia hiyo kutekeleza amri kwenye mwenyeji wa MSSQL (ikiwa inaendeshwa kama SA), **kuiba** hash ya NetNTLM au hata kufanya **shambulio la kupeleka**.\
Pia, ikiwa mifano ya MSSQL inaaminika (kiungo cha database) na mifano mingine ya MSSQL. Ikiwa mtumiaji ana ruhusa juu ya database iliyothibitishwa, ataweza **kutumia uhusiano wa kuaminika kutekeleza maswali pia kwenye mfano mwingine**. Viungo hivi vinaweza kuunganishwa na kufikia wakati fulani mtumiaji anaweza kupata database iliyo na usanidi mbaya ambapo anaweza kutekeleza amri.\
**Viungo kati ya databases hufanya kazi hata kati ya uaminifu wa misitu.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Utekelezaji Usiozuiliwa

Ikiwa unapata kitu chochote cha Kompyuta chenye sifa ya [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) na una ruhusa ya kikoa kwenye kompyuta, utaweza kudump TGTs kutoka kumbukumbu ya kila mtumiaji anayeingia kwenye kompyuta.\
Kwa hivyo, ikiwa **Msimamizi wa Kikoa anaingia kwenye kompyuta**, utaweza kudump TGT yake na kujifanya kuwa yeye kwa kutumia [Pass the Ticket](pass-the-ticket.md).\
Kutokana na upelekaji uliozuiliwa unaweza hata **kudhoofisha kiotomatiki Seva ya Kuchapisha** (kwa matumaini itakuwa DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Upelekaji Uliozuiliwa

Ikiwa mtumiaji au kompyuta inaruhusiwa kwa "Upelekaji Uliozuiliwa" itaweza **kujifanya kuwa mtumiaji yeyote kufikia baadhi ya huduma kwenye kompyuta**.\
Kisha, ikiwa **unadhoofisha hash** ya mtumiaji/kompyuta huyu utaweza **kujifanya kuwa mtumiaji yeyote** (hata wasimamizi wa kikoa) kufikia baadhi ya huduma.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Upelekaji Uliozuiliwa kwa Msingi wa Rasilimali

Kuwa na **ruhusa ya KUANDIKA** kwenye kitu cha Active Directory cha kompyuta ya mbali kunawezesha kupata utekelezaji wa nambari na **ruhusa zilizoongezeka**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Uvunjaji wa ACLs

Mtumiaji aliyeathiriwa anaweza kuwa na **ruhusa za kuvutia juu ya vitu vya kikoa** ambavyo vinaweza kukuruhusu **kutembea** kwa upande/**kupandisha** viwango vya ruhusa.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Uvunjaji wa Huduma ya Kuchapisha

Kugundua **huduma ya Spool inayosikiliza** ndani ya kikoa kunaweza **kuvunjiwa** kutumika kupata **vitambulisho vipya** na **kupandisha viwango vya ruhusa**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Uvunjaji wa Vipindi vya Tatu

Ikiwa **watumiaji wengine** **wanapata** kompyuta iliyovamiwa, inawezekana **kukusanya vitambulisho kutoka kumbukumbu** na hata **kuingiza beacons katika michakato yao** ili kujifanya wao.\
Kawaida watumiaji watatumia mfumo kupitia RDP, hapa ndio jinsi ya kufanya mashambulizi kadhaa juu ya vikao vya RDP vya tatu:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** hutoa mfumo wa kusimamia **nenosiri la Msimamizi wa Mitaa** kwenye kompyuta zilizounganishwa na kikoa, ikisimamia kuwa **imechanganyikiwa**, ya kipekee, na mara kwa mara **kubadilishwa**. Nenosiri hizi hufutwa kwenye Active Directory na ufikiaji unadhibitiwa kupitia ACLs kwa watumiaji walioruhusiwa tu. Kwa ruhusa za kutosha kufikia nenosiri hizi, kugeuka kwa kompyuta nyingine kunawezekana.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Wizi wa Cheti

**Kukusanya vyeti** kutoka kwenye kompyuta iliyovamiwa inaweza kuwa njia ya kupandisha viwango vya ruhusa ndani ya mazingira:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Uvunjaji wa Templeti za Cheti

Ikiwa **templeti zinazoweza kudhurika** zimeboreshwa inawezekana kuzitumia kudhuru viwango vya ruhusa:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Baada ya Uvamizi na akaunti yenye ruhusa kubwa

### Kudumpisha Vitambulisho vya Kikoa

Maranyingi unapopata **Msimamizi wa Kikoa** au hata bora **Msimamizi wa Kampuni**, unaweza **kudumpisha** **database ya kikoa**: _ntds.dit_.

[**Maelezo zaidi kuhusu shambulio la DCSync yanaweza kupatikana hapa**](dcsync.md).

[**Maelezo zaidi kuhusu jinsi ya kuiba NTDS.dit yanaweza kupatikana hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc kama Uthabiti

Baadhi ya mbinu zilizojadiliwa hapo awali zinaweza kutumika kwa uthabiti.\
Kwa mfano unaweza:

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

Shambulio la **Tiketi ya Fedha** hujenga **tiketi halali ya Huduma ya Kutoa Tiketi (TGS)** kwa huduma maalum kwa kutumia **hash ya NTLM** (kwa mfano, **hash ya akaunti ya PC**). Njia hii hutumiwa kufikia **ruhusa za huduma**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Tiketi ya Dhahabu

Shambulio la **Tiketi ya Dhahabu** linahusisha mshambuliaji kupata **hash ya NTLM ya akaunti ya krbtgt** katika mazingira ya Active Directory (AD). Akaunti hii ni maalum kwa sababu hutumiwa kusaini **Tiketi za Kutoa Tiketi (TGTs)**, ambazo ni muhimu kwa uthibitishaji ndani ya mtandao wa AD.

Mara mshambuliaji anapopata hash hii, wanaweza kuunda **TGTs** kwa akaunti yoyote watakayo (shambulio la tiketi ya fedha).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Tiketi ya Almasi

Hizi ni kama tiketi za dhahabu zilizofanywa kwa njia ambayo **inapita njia za kawaida za kugundua tiketi za dhahabu.**

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}
### **Uthabiti wa Akaunti za Vyeti**

**Kuwa na vyeti vya akaunti au kuweza kuvitaka** ni njia nzuri sana ya kuweza kudumu katika akaunti za watumiaji (hata kama anabadilisha nenosiri):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Uthabiti wa Kikoa cha Vyeti**

**Kutumia vyeti pia ni njia ya kudumu na mamlaka kubwa ndani ya kikoa:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Kikundi cha AdminSDHolder

Kipengele cha **AdminSDHolder** katika Active Directory hutoa usalama wa **vikundi vya mamlaka** (kama Domain Admins na Enterprise Admins) kwa kutumia **Orodha ya Kudhibiti Upatikanaji (ACL)** ya kawaida kuzuia mabadiliko yasiyoruhusiwa. Hata hivyo, kipengele hiki kinaweza kutumiwa vibaya; ikiwa mshambuliaji anabadilisha ACL ya AdminSDHolder kumpa mtumiaji wa kawaida upatikanaji kamili, mtumiaji huyo anapata udhibiti mkubwa juu ya vikundi vyote vya mamlaka. Hatua hii ya usalama, iliyolenga kulinda, inaweza kugeuka na kuruhusu upatikanaji usiohitajika isipokuwa ikifuatiliwa kwa karibu.

[**Taarifa zaidi kuhusu Kikundi cha AdminDSHolder hapa.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Ndani ya kila **Domain Controller (DC)**, akaunti ya **msimamizi wa ndani** ipo. Kwa kupata haki za msimamizi kwenye kompyuta kama hiyo, hash ya Msimamizi wa ndani inaweza kuchimbuliwa kwa kutumia **mimikatz**. Baada ya hapo, marekebisho ya usajili yanahitajika kuwezesha matumizi ya nenosiri hili, kuruhusu upatikanaji wa mbali kwenye akaunti ya Msimamizi wa ndani.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Uthabiti wa ACL

Unaweza **kumpa** mtumiaji **ruhusa maalum** juu ya vitu vya kikoa maalum ambavyo vitamruhusu mtumiaji **kupandisha viwango vya mamlaka baadaye**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Descriptors za Usalama

**Descriptors za usalama** hutumiwa kuhifadhi **ruhusa** ambazo **kitu** kina **juu** ya **kitu** kingine. Ikiwa unaweza **kufanya** mabadiliko **kidogo** kwenye **descriptor ya usalama** ya kitu, unaweza kupata mamlaka muhimu sana juu ya kitu hicho bila kuwa mwanachama wa kikundi cha mamlaka.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

Badilisha **LSASS** kwenye kumbukumbu ili kuweka **nenosiri la kipekee**, kuruhusu upatikanaji wa akaunti zote za kikoa.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### SSP ya Kibinafsi

[Jifunze ni nini SSP (Mtoa Msaada wa Usalama) hapa.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Unaweza kuunda **SSP yako mwenyewe** ili **kukamata** kwa **maandishi wazi** **vyeti** vinavyotumiwa kupata upatikanaji wa kompyuta.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Inasajili **Domain Controller mpya** katika AD na kutumia kusukuma sifa (SIDHistory, SPNs...) kwenye vitu vilivyowekwa **bila** kuacha **kumbukumbu** kuhusu **mabadiliko**. Unahitaji **mamlaka ya DA** na kuwa ndani ya **kikoa cha msingi**.\
Tafadhali kumbuka kuwa ikiwa utatumia data isiyo sahihi, kumbukumbu zenye machafu zitaonekana.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Uthabiti wa LAPS

Tulijadili jinsi ya kupandisha viwango vya mamlaka ikiwa una **ruhusa za kutosha kusoma nywila za LAPS**. Hata hivyo, nywila hizi pia zinaweza kutumika kwa **kudumisha uthabiti**.\
Angalia:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Kupandisha Viwango vya Mamlaka kwenye Msitu - Uaminifu wa Kikoa

Microsoft inaona **Msitu** kama mpaka wa usalama. Hii inamaanisha kwamba **kudukua kikoa kimoja kunaweza kusababisha msitu mzima kudukuliwa**.

### Taarifa Msingi

[**Uaminifu wa kikoa**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) ni mbinu ya usalama inayowezesha mtumiaji kutoka **kikoa kimoja** kupata rasilimali katika **kikoa kingine**. Kimsingi, hii inajenga uhusiano kati ya mifumo ya uthibitishaji ya kikoa mbili, kuruhusu uthibitishaji kufanyika kwa urahisi. Wakati vikoa vinapoweka uaminifu, hubadilishana na kuhifadhi **funguo maalum** ndani ya **Wadhibiti wa Kikoa (DCs)** yao, ambayo ni muhimu kwa uadilifu wa uaminifu.

Kwa kawaida, ikiwa mtumiaji anataka kupata huduma katika **kikoa kilichoaminika**, lazima kwanza aombe tiketi maalum inayoitwa **TGT ya kati-milki** kutoka kwa DC ya kikoa chake. TGT hii inafichwa kwa **funguo la pamoja** ambalo vikoa vyote vimekubaliana. Mtumiaji kisha huleta TGT hii kwa **DC ya kikoa kilichoaminika** kupata tiketi ya huduma (**TGS**). Baada ya uthibitishaji wa mafanikio wa TGT ya kati-milki na DC ya kikoa kilichoaminika, DC hutoa TGS, ikimruhusu mtumiaji kupata huduma.

**Hatua**:

1. **Kompyuta ya mteja** katika **Kikoa 1** huanza mchakato kwa kutumia **hashi ya NTLM** yake kuomba **Tiketi ya Kutoa Tiketi (TGT)** kutoka kwa **Wadhibiti wa Kikoa (DC1)** yake.
2. DC1 inatoa TGT mpya ikiwa mteja amethibitishwa kwa mafanikio.
3. Mteja kisha anaomba **TGT ya kati-milki** kutoka kwa DC1, ambayo inahitajika kupata rasilimali katika **Kikoa 2**.
4. TGT ya kati-milki inafichwa kwa **funguo la uaminifu** lililoshirikiwa kati ya DC1 na DC2 kama sehemu ya uaminifu wa pande mbili wa kikoa.
5. Mteja huleta TGT ya kati-milki kwa **Wadhibiti wa Kikoa cha Kikoa 2 (DC2)**.
6. DC2 inathibitisha TGT ya kati-milki kwa kutumia funguo la uaminifu lililoshirikiwa, na ikiwa ni halali, inatoa **Tiketi ya Huduma ya Kutoa Tiketi (TGS)** kwa seva katika Kikoa 2 ambayo mteja anataka kupata.
7. Hatimaye, mteja huleta TGS hii kwa seva, ambayo inafichwa na hashi ya akaunti ya seva, kupata huduma katika Kikoa 2.

### Uaminifu Tofauti

Ni muhimu kuzingatia kwamba **uaminifu unaweza kuwa wa njia moja au njia mbili**. Katika chaguo la njia mbili, vikoa vyote vitaiminiana, lakini katika uhusiano wa uaminifu wa **njia moja** moja ya vikoa itakuwa kikoa cha **kuaminika** na kingine kikoa cha **kuaminia**. Katika kesi ya mwisho, **utaweza tu kupata rasilimali ndani ya kikoa cha kuaminia kutoka kikoa cha kuaminika**.

Ikiwa Kikoa A inaamini Kikoa B, A ni kikoa cha kuaminia na B ni kikoa cha kuaminika. Zaidi ya hayo, katika **Kikoa A**, hii itakuwa **uaminifu wa kutoka**; na katika **Kikoa B**, hii itakuwa **uaminifu wa kuingia**.

**Mahusiano tofauti ya kuaminia**

* **Uaminifu wa Wazazi-Watoto**: Hii ni usanidi wa kawaida ndani ya msitu mmoja, ambapo kikoa cha mtoto kina uaminifu wa njia mbili na kikoa cha mzazi. Kimsingi, hii inamaanisha kwamba maombi ya uthibitishaji yanaweza kufanyika kwa urahisi kati ya mzazi na mtoto.
* **Uaminifu wa Msalaba**: Unajulikana kama "uaminifu wa njia ya mkato," hizi huanzishwa kati ya vikoa vya watoto kuharakisha mchakato wa rufaa. Katika misitu yenye utata, rufaa za uthibitishaji kwa kawaida zinapaswa kusafiri hadi kufikia mzizi wa msitu na kisha kushuka kwenye kikoa cha lengo. Kwa kuunda viungo vya msalaba, safari inapunguzwa, ambayo ni muhimu hasa katika mazingira yaliyotawanyika kijiografia.
* **Uaminifu wa Nje**: Hizi huanzishwa kati ya vikoa tofauti, visivyo na uhusiano wowote na ni visivyotawala kwa asili. Kulingana na [nyaraka za Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), uaminifu wa nje ni muhimu kwa kupata rasilimali katika kikoa nje ya msitu wa sasa ambao haujaunganishwa na uaminifu wa msitu. Usalama unaimarishwa kupitia uchujaji wa SID na uaminifu wa nje.
* **Uaminifu wa Mizizi ya Mti**: Uaminifu huu huanzishwa moja kwa moja kati ya kikoa cha mizizi ya msitu na mizizi mpya iliyopangwa. Ingawa sio jambo la kawaida, uaminifu wa mizizi ya mti ni muhimu kwa kuongeza miti mpya ya kikoa kwenye msitu, kuwaruhusu kudumisha jina la kikoa cha kipekee na kuhakikisha uaminifu wa njia mbili. Taarifa zaidi zinaweza kupatikana katika [mwongozo wa Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Uaminifu wa Msitu**: Aina hii ya uaminifu ni uaminifu wa njia mbili kati ya mizizi miwili ya msitu, ikitekeleza pia uchujaji wa SID kuimarisha hatua za usalama.
* **Uaminifu wa MIT**: Uaminifu huu unawekwa na mifumo isiyo ya Windows, [inayofuata RFC4120](https://tools.ietf.org/html/rfc4120) ya Kerberos. Uaminifu wa MIT ni maalum kidogo na unahudumia mazingira yanayohitaji kuingiliana na mifumo inayotumia Kerberos nje ya mfumo wa Windows.
#### Tofauti nyingine katika **mahusiano ya kuaminiana**

* Mahusiano ya kuaminiana yanaweza kuwa **yaliyopitishwa** (A anaamini B, B anaamini C, basi A anaamini C) au **yasiyopitishwa**.
* Mahusiano ya kuaminiana yanaweza kuwekwa kama **kuaminiana pande zote** (wote wanamuamini mwingine) au kama **kuaminiana upande mmoja** (mmoja wao tu anamuamini mwingine).

### Njia ya Shambulio

1. **Tambua** mahusiano ya kuaminiana
2. Angalia kama **mkuu wa usalama** (mtumiaji/kikundi/kompyuta) ana **upatikanaji** wa rasilimali za **uwanja mwingine**, labda kupitia kuingia kwa ACE au kwa kuwa katika vikundi vya uwanja mwingine. Tafuta **mahusiano kati ya uwanja** (kuaminiana kuliumbwa kwa hili labda).
3. kerberoast katika kesi hii inaweza kuwa chaguo lingine.
4. **Ghilibu** **akaunti** ambazo zinaweza **kupinduka** kupitia uwanja.

Washambuliaji wanaweza kupata upatikanaji wa rasilimali katika uwanja mwingine kupitia njia tatu kuu:

* **Uanachama wa Kikundi cha Kienyeji**: Mkuu anaweza kuongezwa kwenye vikundi vya kienyeji kwenye mashine, kama vile kikundi cha "Waadiministrata" kwenye server, kuwapa udhibiti mkubwa juu ya mashine hiyo.
* **Uanachama wa Kikundi cha Uwanja wa Kigeni**: Mkuu pia anaweza kuwa mwanachama wa vikundi ndani ya uwanja wa kigeni. Walakini, ufanisi wa njia hii unategemea asili ya kuaminiana na wigo wa kikundi.
* **Orodha za Kudhibiti Upatikanaji (ACL)**: Mkuu anaweza kutajwa katika **ACL**, hasa kama viungo katika **ACEs** ndani ya **DACL**, kuwapa upatikanaji wa rasilimali maalum. Kwa wale wanaotaka kuchimba zaidi katika uendeshaji wa ACLs, DACLs, na ACEs, karatasi nyeupe iitwayo “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)” ni rasilimali muhimu.
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
Unaweza kutambua ile inayotumiwa na kikoa cha sasa kwa:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Kuingiza SID-History

Kuongeza hadhi ya Mfumo wa Utawala wa Kampuni kwa kudanganya uaminifu na kuingiza SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Kutumia NC ya Usanidi Inayoweza Kuandikwa

Kuelewa jinsi NC ya Jina la Usanidi inavyoweza kutumiwa ni muhimu. NC ya Usanidi inafanya kama hazina kuu ya data ya usanidi kote kwenye msitu katika mazingira ya Active Directory (AD). Data hii inarekebishwa kwa kila Msimamizi wa Kikoa (DC) ndani ya msitu, na DC zinazoweza kuandikwa zikihifadhi nakala inayoweza kuandikwa ya NC ya Usanidi. Ili kutumia hii, mtu lazima awe na **madaraka ya Mfumo kwenye DC**, bora ikiwa ni DC ya mtoto.

**Weka Kiungo cha GPO kwenye eneo la DC kuu**

Chombo cha NC ya Usanidi kinajumuisha habari kuhusu maeneo ya kompyuta zilizojiunga na kikoa zote ndani ya msitu wa AD. Kwa kufanya kazi na madaraka ya Mfumo kwenye DC yoyote, wachomaji wanaweza kuweka viungo vya GPO kwenye maeneo ya DC kuu. Hatua hii inaweza kuhatarisha kikoa cha kuu kwa kubadilisha sera zilizotekelezwa kwenye maeneo haya.

Kwa habari kamili, mtu anaweza kuchunguza utafiti kuhusu [Kupitisha Uchujaji wa SID](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Shambulio la kudhoofisha gMSA yoyote katika msitu**

Mbinu ya shambulio inajumuisha kulenga gMSAs wenye mamlaka ndani ya kikoa. Kifungu cha Mzizi wa KDS, muhimu kwa kuhesabu nywila za gMSAs, kuhifadhiwa ndani ya NC ya Usanidi. Kwa madaraka ya Mfumo kwenye DC yoyote, ni rahisi kupata Kifungu cha Mzizi wa KDS na kuhesabu nywila za gMSA yoyote kote kwenye msitu.

Uchambuzi wa kina unaweza kupatikana katika mjadala kuhusu [Mashambulizi ya Kuamini gMSA ya Dhahabu](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Shambulio la Mabadiliko ya Schema**

Mbinu hii inahitaji subira, kusubiri uundaji wa vitu vipya vya AD vyenye mamlaka. Kwa madaraka ya Mfumo, mchomaji anaweza kurekebisha Schema ya AD ili kumpa mtumiaji yeyote udhibiti kamili juu ya madarasa yote. Hii inaweza kusababisha ufikiaji usioruhusiwa na udhibiti juu ya vitu vipya vilivyoanzishwa vya AD.

Soma zaidi inapatikana kwenye [Mashambulizi ya Kuamini Mabadiliko ya Schema](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Kutoka DA hadi EA na ADCS ESC5**

Udhaifu wa ADCS ESC5 unalenga udhibiti juu ya vitu vya Miundombinu ya Ufunguo wa Umma (PKI) ili kuunda kiolezo cha cheti kinachowezesha uwakilishi kama mtumiaji yeyote ndani ya msitu. Kwa kuwa vitu vya PKI viko ndani ya NC ya Usanidi, kudhoofisha DC ya mtoto inayoweza kuandikwa kunawezesha utekelezaji wa mashambulio ya ESC5.

Maelezo zaidi kuhusu hili yanaweza kusomwa katika [Kutoka DA hadi EA na ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Katika mazingira ambayo hakuna ADCS, mchomaji ana uwezo wa kuweka sehemu muhimu, kama ilivyojadiliwa katika [Kuongeza kutoka kwa Wasimamizi wa Kikoa cha Watoto hadi Wasimamizi wa Kampuni](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Kikoa cha Msitu wa Nje - Moja-Kwa-Moja (Kuingia) au kibidirectional
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
Katika hali hii **kikoa chako kinaaminika** na moja ya nje ikikupa **ruhusa zisizojulikana** juu yake. Utahitaji kugundua **principals zipi za kikoa chako zina ufikivu gani juu ya kikoa cha nje** na kujaribu kuitumia:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Kikoa cha Msitu wa Nje - Moja Kwa Moja (Kuelekea Nje)
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
Katika kesi hii **kikoa chako** kinatoa **madaraka** fulani kwa msingi kutoka **vikoa tofauti**.

Hata hivyo, wakati **kikoa kinapoitwa** na kikoa kinachoitwa, kikoa kilichoitwa **huunda mtumiaji** na **jina linaloweza kutabirika** ambalo hutumia **nywila ya kuaminika**. Hii inamaanisha kwamba ni rahisi **kupata mtumiaji kutoka kikoa kinachoitwa ili kuingia kwenye kikoa kilichoitwa** kwa lengo la kuchunguza na kujaribu kupata madaraka zaidi:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Njia nyingine ya kuhatarisha kikoa kilichoitwa ni kwa kutafuta [**kiungo cha kuaminika cha SQL**](abusing-ad-mssql.md#mssql-trusted-links) kilichoundwa katika **mwelekeo wa kinyume** wa uaminifu wa kikoa (ambao si wa kawaida).

Njia nyingine ya kuhatarisha kikoa kilichoitwa ni kusubiri kwenye kifaa ambapo **mtumiaji kutoka kikoa kilichoitwa anaweza kupata** ili kuingia kupitia **RDP**. Kisha, mshambuliaji anaweza kuingiza nambari katika mchakato wa kikao cha RDP na **kupata kikoa cha asili cha muathiriwa** kutoka hapo.\
Zaidi ya hayo, ikiwa **muathiriwa ameunganisha diski yake ngumu**, kutoka kwenye mchakato wa kikao cha RDP mshambuliaji anaweza kuhifadhi **mlango wa nyuma** kwenye **folda ya kuanza ya diski ngumu**. Mbinu hii inaitwa **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Kupunguza Uharibifu wa Uaminifu wa Kikoa

### **SID Filtering:**

* Hatari ya mashambulizi yanayotumia sifa ya historia ya SID kati ya uaminifu wa misitu inapunguzwa na SID Filtering, ambayo imeamilishwa kwa chaguo-msingi kwenye uaminifu wote wa misitu. Hii inategemea dhana kwamba uaminifu wa ndani wa misitu ni salama, ikizingatiwa misitu, badala ya kikoa, kama mpaka wa usalama kulingana na msimamo wa Microsoft.
* Hata hivyo, kuna changamoto: SID filtering inaweza kuvuruga programu na ufikiaji wa mtumiaji, ikisababisha mara kwa mara kuzimwa kwake.

### **Uthibitishaji wa Uchaguzi:**

* Kwa uaminifu wa misitu, kutumia Uthibitishaji wa Uchaguzi kuhakikisha kuwa watumiaji kutoka misitu miwili hawathibitishwi moja kwa moja. Badala yake, idhini za wazi zinahitajika kwa watumiaji kupata vikoa na seva ndani ya kikoa au misitu inayoitwa.
* Ni muhimu kutambua kwamba hatua hizi hazilindi dhidi ya unyanyasaji wa Writable Configuration Naming Context (NC) au mashambulizi kwenye akaunti ya uaminifu.

[**Maelezo zaidi kuhusu uaminifu wa vikoa katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Ulinzi wa Jumla

[**Jifunze zaidi kuhusu jinsi ya kulinda vibali hapa.**](../stealing-credentials/credentials-protections.md)\\

### **Hatua za Ulinzi kwa Kulinda Vibali**

* **Vikwazo vya Wasimamizi wa Kikoa**: Inapendekezwa kuwa Wasimamizi wa Kikoa wanapaswa kuruhusiwa kuingia kwenye Wadhibiti wa Kikoa pekee, kuepuka matumizi yao kwenye wenyewe.
* **Madaraka ya Akaunti ya Huduma**: Huduma hazipaswi kuendeshwa na madaraka ya Wasimamizi wa Kikoa (DA) ili kudumisha usalama.
* **Upeo wa Muda wa Madaraka**: Kwa kazi zinazohitaji madaraka ya DA, muda wao unapaswa kuwa mdogo. Hii inaweza kufikiwa kwa: `Add-ADGroupMember -Identity ‘Wasimamizi wa Kikoa’ -Wanachama wapyaDA -MemberTimeToLive (New-TimeSpan -Dakika 20)`

### **Kutekeleza Mbinu za Udanganyifu**

* Kutekeleza udanganyifu kunajumuisha kuweka mitego, kama watumiaji au kompyuta bandia, na sifa kama nywila ambazo hazitamaliziki au zimeorodheshwa kama Kuaminika kwa Uteuzi. Mbinu ya kina inajumuisha kuunda watumiaji wenye haki maalum au kuwaongeza kwenye vikundi vya madaraka ya juu.
* Mfano wa vitendo unajumuisha kutumia zana kama: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Zaidi kuhusu kutekeleza mbinu za udanganyifu inaweza kupatikana kwenye [Deploy-Deception kwenye GitHub](https://github.com/samratashok/Deploy-Deception).

### **Kutambua Udanganyifu**

* **Kwa Vitu vya Mtumiaji**: Viashiria vya shaka ni pamoja na ObjectSID isiyo ya kawaida, kuingia mara chache, tarehe za uundaji, na idadi ndogo ya nywila mbaya.
* **Viashiria vya Jumla**: Kulinganisha sifa za vitu vya udanganyifu vinavyowezekana na zile za kweli kunaweza kufunua kutofautiana. Zana kama [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) inaweza kusaidia kutambua udanganyifu kama huo.

### **Kupita Mifumo ya Uchunguzi**

* **Kupita Kugundua kwa Microsoft ATA**:
* **Uorodheshaji wa Mtumiaji**: Kuepuka uorodheshaji wa kikao kwenye Wadhibiti wa Kikoa ili kuzuia ugunduzi wa ATA.
* **Uigaji wa Tiketi**: Kutumia funguo za **aes** kwa uumbaji wa tiketi husaidia kuepuka ugunduzi kwa kutofanya kudorora hadi NTLM.
* **Mashambulizi ya DCSync**: Kutekeleza kutoka kwa Wadhibiti wa Kikoa kuepuka ugunduzi wa ATA kunashauriwa, kwani utekelezaji moja kwa moja kutoka kwa Wadhibiti wa Kikoa utasababisha tahadhari.

## Marejeo

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
