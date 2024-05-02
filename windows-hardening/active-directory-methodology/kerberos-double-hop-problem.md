# Kerberos Dubbele Hop Probleem

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersecurity maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Inleiding

Die Kerberos "Dubbele Hop" probleem kom voor wanneer 'n aanvaller probeer om **Kerberos-verifikasie oor twee** **hops** te gebruik, byvoorbeeld deur **PowerShell**/**WinRM** te gebruik.

Wanneer 'n **verifikasie** plaasvind deur **Kerberos**, word **geloofsbriewe** **nie** in die **geheue gestoor nie**. Daarom sal jy nie geloofsbriewe van die gebruiker op die rekenaar vind as jy mimikatz hardloop nie, selfs al hardloop hy prosesse.

Dit is omdat wanneer jy met Kerberos verbind, hierdie die stappe is:

1. Gebruiker1 voorsien geloofsbriewe en die **domain controller** gee 'n Kerberos **TGT** aan Gebruiker1 terug.
2. Gebruiker1 gebruik die **TGT** om 'n **dienskaartjie** aan te vra om aan **Server1 te koppel**.
3. Gebruiker1 **koppel** aan **Server1** en voorsien die **dienskaartjie**.
4. **Server1** het nie die **gelooofsbriewe** van Gebruiker1 in die geheue gestoor of die **TGT** van Gebruiker1 nie. Daarom, wanneer Gebruiker1 vanaf Server1 probeer om na 'n tweede bediener in te teken, kan hy **nie geïdentifiseer** nie.

### Onbeperkte Delegering

As **onbeperkte delegasie** geaktiveer is op die rekenaar, sal dit nie gebeur nie, aangesien die **Bediener** 'n **TGT** van elke gebruiker wat dit benader, sal **kry**. Verder, as onbeperkte delegasie gebruik word, kan jy waarskynlik die Domeinbeheerder **kompromitteer**.\
[**Meer inligting in die onbeperkte delegasie bladsy**](unconstrained-delegation.md).

### CredSSP

'n Ander manier om hierdie probleem te vermy wat [**merkwaardig onveilig**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is, is **Credential Security Support Provider**. Van Microsoft:

> CredSSP-verifikasie delegeer die gebruikersgelde vanaf die plaaslike rekenaar na 'n afgeleë rekenaar. Hierdie praktyk verhoog die sekuriteitsrisiko van die afgeleë operasie. As die afgeleë rekenaar gekompromitteer is, wanneer geloofsbriewe daaraan oorgedra word, kan die geloofsbriewe gebruik word om die netwerksessie te beheer.

Dit word sterk aanbeveel dat **CredSSP** gedeaktiveer word op produksiestelsels, sensitiewe netwerke, en soortgelyke omgewings weens sekuriteitskwessies. Om te bepaal of **CredSSP** geaktiveer is, kan die `Get-WSManCredSSP` bevel uitgevoer word. Hierdie bevel maak die **ondersoek van CredSSP-status** moontlik en kan selfs op afstand uitgevoer word, mits **WinRM** geaktiveer is.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Oorkomings

### Roep Opdrag Aan

Om die dubbele hup probleem aan te spreek, word 'n metode wat 'n geneste `Invoke-Command` behels, voorgestel. Dit los die probleem nie direk op nie, maar bied 'n oorkomingsoplossing sonder om spesiale konfigurasies nodig te hê. Die benadering maak dit moontlik om 'n opdrag (`hostname`) op 'n sekondêre bediener uit te voer deur 'n PowerShell-opdrag wat vanaf 'n aanvanklike aanvallende masjien uitgevoer word of deur 'n voorheen gevestigde PS-Sessie met die eerste bediener. Hier is hoe dit gedoen word:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### Registreer PSSession-konfigurasie

'n Oplossing om die dubbele hop-probleem te omseil, behels die gebruik van `Register-PSSessionConfiguration` met `Enter-PSSession`. Hierdie metode vereis 'n ander benadering as `evil-winrm` en maak 'n sessie moontlik wat nie deur die dubbele hop-beperking geraak word nie.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PoortDeurstuur

Vir plaaslike administrateurs op 'n tussenliggende teiken, maak poortdeurstuur dit moontlik dat versoek na 'n finale bediener gestuur word. Deur `netsh` te gebruik, kan 'n reël vir poortdeurstuur bygevoeg word, tesame met 'n Windows-firewallreël om die deurgestuurde poort toe te laat.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` kan gebruik word om WinRM-versoeke deur te stuur, moontlik as 'n minder opspoorbare opsie as PowerShell-monitoring 'n bekommernis is. Die onderstaande bevel demonstreer die gebruik daarvan:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Die installering van OpenSSH op die eerste bediener maak 'n omweg vir die dubbele-hop probleem moontlik, veral nuttig vir springkas scenarios. Hierdie metode vereis CLI-installasie en opstelling van OpenSSH vir Windows. Wanneer dit ingestel is vir Wagwoordverifikasie, maak dit dit moontlik vir die bemiddelende bediener om 'n TGT namens die gebruiker te verkry.

#### OpenSSH-installasiestappe

1. Laai die nuutste OpenSSH vrystelling zip af en skuif dit na die teikenbediener.
2. Pak die lêer uit en hardloop die `Install-sshd.ps1` skrip.
3. Voeg 'n firewall-reël by om poort 22 oop te maak en verifieer dat SSH-diens hardloop.

Om `Verbindingsreset` foute op te los, mag toestemmings bygewerk moet word om almal lees- en uitvoertoegang tot die OpenSSH-gids toe te laat.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Verwysings

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>
