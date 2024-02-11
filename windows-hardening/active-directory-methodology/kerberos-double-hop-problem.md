# Kerberos Dubbele Hop Probleem

<details>

<summary><strong>Leer AWS hack van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PRs in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Inleiding

Die Kerberos "Dubbele Hop" probleem ontstaan wanneer 'n aanvaller probeer om **Kerberos-verifikasie oor twee** **hoppe** te gebruik, byvoorbeeld deur gebruik te maak van **PowerShell**/**WinRM**.

Wanneer 'n **verifikasie** plaasvind deur middel van **Kerberos**, word **volmagte** **nie in die geheue gestoor nie**. Daarom sal jy nie volmagte van die gebruiker op die rekenaar vind nie, selfs al voer hy prosesse uit.

Dit is omdat hierdie die stappe is wanneer jy met Kerberos verbind:

1. Gebruiker1 voorsien volmagte en die **domeinbeheerder** gee 'n Kerberos **TGT** aan Gebruiker1.
2. Gebruiker1 gebruik die **TGT** om 'n **dienskaartjie** aan te vra om met Server1 te **verbind**.
3. Gebruiker1 **verbind** met **Server1** en voorsien die **dienskaartjie**.
4. **Server1** het nie die volmagte van Gebruiker1 of die **TGT** van Gebruiker1 in die geheue gestoor nie. Daarom kan Gebruiker1 vanaf Server1 nie op 'n tweede bediener aanmeld nie.

### Onbeperkte Delegasie

As **onbeperkte delegasie** geaktiveer is op die rekenaar, sal dit nie gebeur nie, omdat die **Bediener** 'n **TGT** van elke gebruiker wat dit benader, sal **kry**. Verder kan jy waarskynlik die Domeinbeheerder **kompromitteer** as onbeperkte delegasie gebruik word.\
[**Meer inligting in die bladsy oor onbeperkte delegasie**](unconstrained-delegation.md).

### CredSSP

'n Ander manier om hierdie probleem te vermy, wat [**merkwaardig onveilig**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is, is **Credential Security Support Provider**. Volgens Microsoft:

> CredSSP-verifikasie delegeer die gebruikersvolmagte van die plaaslike rekenaar na 'n afgeleë rekenaar. Hierdie praktyk verhoog die veiligheidsrisiko van die afgeleë bedryf. As die afgeleë rekenaar gekompromitteer word, kan die volmagte wat daaraan oorgedra word, gebruik word om die netwerksessie te beheer.

Dit word sterk aanbeveel dat **CredSSP** gedeaktiveer word op produksiestelsels, sensitiewe netwerke en soortgelyke omgewings weens veiligheidskwessies. Om vas te stel of **CredSSP** geaktiveer is, kan die `Get-WSManCredSSP` opdrag uitgevoer word. Hierdie opdrag maak dit moontlik om die **status van CredSSP te kontroleer** en kan selfs op afstand uitgevoer word, mits **WinRM** geaktiveer is.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Oplossings

### Invoke Commando

Om die dubbele hop-probleem aan te spreek, word 'n metode voorgestel wat 'n geneste `Invoke-Command` gebruik. Dit los die probleem nie direk op nie, maar bied 'n omweg sonder om spesiale konfigurasies te benodig. Die benadering maak dit moontlik om 'n bevel (`hostname`) op 'n sekondêre bediener uit te voer deur middel van 'n PowerShell-bevel wat uitgevoer word vanaf 'n aanvallende masjien of deur middel van 'n voorheen gevestigde PS-sessie met die eerste bediener. Hier is hoe dit gedoen word:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatiewelik word daar voorgestel om 'n PS-sessie met die eerste bediener te vestig en die `Invoke-Command` met behulp van `$cred` uit te voer om take te sentraliseer.

### Registreer PSSession-konfigurasie

'n Oplossing om die dubbele hop-probleem te omseil, behels die gebruik van `Register-PSSessionConfiguration` met `Enter-PSSession`. Hierdie metode vereis 'n ander benadering as `evil-winrm` en maak dit moontlik om 'n sessie te hê wat nie deur die dubbele hop-beperking geraak word nie.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Portstuur

Vir plaaslike administrateurs op 'n tussenliggende teiken, maak portstuur dit moontlik dat versoek na 'n finale bediener gestuur word. Deur `netsh` te gebruik, kan 'n reël vir portstuur bygevoeg word, tesame met 'n Windows-firewallreël om die doorgestuurde poort toe te laat.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` kan gebruik word om WinRM-versoeke deur te stuur, moontlik as 'n minder opspoorbare opsie as PowerShell-monitoring 'n bekommernis is. Die opdrag hieronder demonstreer die gebruik daarvan:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Die installering van OpenSSH op die eerste bediener maak 'n omweg vir die dubbele-hop-probleem moontlik, veral nuttig vir springboksgevalle. Hierdie metode vereis die installering en opstel van OpenSSH vir Windows via die opdraglyn. Wanneer dit gekonfigureer is vir wagwoordverifikasie, maak dit dit moontlik vir die tussenliggende bediener om 'n TGT namens die gebruiker te verkry.

#### OpenSSH-installasiestappe

1. Laai die nuutste OpenSSH-vrystelling zip af en skuif dit na die teikenserver.
2. Pak die lêer uit en voer die `Install-sshd.ps1` skrip uit.
3. Voeg 'n vuremuur-reël by om poort 22 oop te maak en verifieer dat SSH-dienste loop.

Om `Connection reset` foute op te los, moet toestemmings moontlik opgedateer word om almal lees- en uitvoerregte op die OpenSSH-gids toe te laat.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Verwysings

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
