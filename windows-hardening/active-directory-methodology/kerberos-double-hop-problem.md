# Problem dvostrukog skoka u Kerberosu

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS-a ili preuzimanje HackTricks-a u PDF-u**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grupi** ili **telegram grupi** ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova** [**hacktricks repozitorijumu**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijumu**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Uvod

Problem "dvostrukog skoka" u Kerberosu se javlja kada napadač pokušava da koristi **Kerberos autentikaciju preko dva** **skoka**, na primer koristeći **PowerShell**/**WinRM**.

Kada se **autentikacija** vrši putem **Kerberosa**, **poverenički podaci** **nisu** keširani u **memoriji**. Zbog toga, ako pokrenete mimikatz, **nećete pronaći povereničke podatke** korisnika na mašini čak i ako pokreće procese.

To je zato što prilikom povezivanja putem Kerberosa sledeći su koraci:

1. Korisnik1 pruža povereničke podatke i **kontroler domena** vraća Kerberos **TGT** korisniku1.
2. Korisnik1 koristi **TGT** da zatraži **servisnu kartu** za **povezivanje** sa Serverom1.
3. Korisnik1 se **povezuje** sa **Serverom1** i pruža **servisnu kartu**.
4. **Server1** **nema** keširane **povereničke podatke** korisnika1 ili **TGT** korisnika1. Stoga, kada Korisnik1 sa Servera1 pokuša da se prijavi na drugi server, **neće moći da se autentikuje**.

### Neograničeno Delegiranje

Ako je omogućeno **neograničeno delegiranje** na računaru, ovo se neće dogoditi jer će **Server** dobiti **TGT** svakog korisnika koji mu pristupa. Štaviše, ako se koristi neograničeno delegiranje, verovatno možete **ugroziti kontroler domena** iz njega.\
[**Više informacija na stranici o neograničenom delegiranju**](unconstrained-delegation.md).

### CredSSP

Još jedan način da se izbegne ovaj problem koji je [**posebno nesiguran**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) je **Credential Security Support Provider**. Od strane Microsoft-a:

> CredSSP autentikacija delegira korisničke povereničke podatke sa lokalnog računara na udaljeni računar. Ova praksa povećava sigurnosni rizik udaljene operacije. Ako je udaljeni računar kompromitovan, kada mu se proslede poverenički podaci, poverenički podaci mogu se koristiti za kontrolu mrežne sesije.

Visoko se preporučuje da se **CredSSP** onemogući na proizvodnim sistemima, osetljivim mrežama i sličnim okruženjima zbog sigurnosnih razloga. Da biste utvrdili da li je **CredSSP** omogućen, može se pokrenuti komanda `Get-WSManCredSSP`. Ova komanda omogućava **proveru statusa CredSSP** i može se čak izvršiti udaljeno, pod uslovom da je omogućen **WinRM**.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Rešenja

### Pozivanje Komande

Da bi se rešio problem dvostrukog skoka, predstavljen je metod koji uključuje ugniježđeno `Invoke-Command`. Ovo ne rešava problem direktno, već nudi alternativno rešenje bez potrebe za posebnim konfiguracijama. Pristup omogućava izvršavanje komande (`hostname`) na sekundarnom serveru putem PowerShell komande izvršene sa početnog napadajućeg računara ili putem prethodno uspostavljene PS-Session sa prvog servera. Evo kako se to radi:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativno, uspostavljanje PS-Session-a sa prvom serverom i pokretanje `Invoke-Command` koristeći `$cred` se predlaže za centralizovanje zadataka.

### Registruj PSSession Konfiguraciju

Rešenje za zaobilaženje problema dvostrukog skoka uključuje korišćenje `Register-PSSessionConfiguration` sa `Enter-PSSession`. Ovaj metod zahteva drugačiji pristup od `evil-winrm` i omogućava sesiju koja ne pati od ograničenja dvostrukog skoka.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Za lokalne administratore na posrednom cilju, prosleđivanje porta omogućava slanje zahteva ka krajnjem serveru. Korišćenjem `netsh`, pravilo se može dodati za prosleđivanje porta, zajedno sa Windows firewall pravilom koje dozvoljava prosleđeni port.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` može se koristiti za prosleđivanje WinRM zahteva, potencijalno kao manje detektabilna opcija ako je praćenje PowerShell-a zabrinjavajuće. Komanda ispod demonstrira njegovu upotrebu:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instaliranje OpenSSH-a na prvom serveru omogućava rešenje problema dvostrukog skoka, posebno korisno za scenarije skakanja preko posrednika. Ovaj metod zahteva CLI instalaciju i podešavanje OpenSSH-a za Windows. Kada je konfigurisan za autentikaciju lozinkom, ovo omogućava posredničkom serveru da dobije TGT u ime korisnika.

#### Koraci instalacije OpenSSH-a

1. Preuzmite i premestite najnoviji zip fajl sa OpenSSH izdanjem na ciljni server.
2. Otpakujte i pokrenite skriptu `Install-sshd.ps1`.
3. Dodajte pravilo za firewall da otvorite port 22 i proverite da li SSH servisi rade.

Da biste rešili greške `Connection reset`, dozvole možda treba ažurirati kako bi se omogućilo svima čitanje i izvršavanje pristupa u OpenSSH direktorijumu.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Reference

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite da vidite vašu **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS-a ili preuzimanje HackTricks-a u PDF-u**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi** ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**hacktricks repozitorijum**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud repozitorijum**](https://github.com/carlospolop/hacktricks-cloud).

</details>
