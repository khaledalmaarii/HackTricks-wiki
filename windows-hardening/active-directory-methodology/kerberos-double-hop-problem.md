# Kerberos Double Hop Problem

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introduction

Die Kerberos "Double Hop" probleem verskyn wanneer 'n aanvaller probeer om **Kerberos-outeentifikasie oor twee** **hops** te gebruik, byvoorbeeld deur **PowerShell**/**WinRM**.

Wanneer 'n **outeentifikasie** deur **Kerberos** plaasvind, word **akkrediteer** **nie** in **geheue** **gecache** nie. Daarom, as jy mimikatz uitvoer, sal jy **nie akkrediteer** van die gebruiker op die masjien vind nie, selfs al is hy besig om prosesse te loop.

Dit is omdat wanneer jy met Kerberos verbind, dit die stappe is:

1. Gebruiker1 verskaf akkrediteer en die **domeinbeheerder** keer 'n Kerberos **TGT** terug na Gebruiker1.
2. Gebruiker1 gebruik **TGT** om 'n **dienskaartjie** aan te vra om met Server1 te **verbinde**.
3. Gebruiker1 **verbinde** met **Server1** en verskaf **dienskaartjie**.
4. **Server1** **het nie** **akkrediteer** van Gebruiker1 gecache of die **TGT** van Gebruiker1 nie. Daarom, wanneer Gebruiker1 van Server1 probeer om in te log op 'n tweede bediener, kan hy **nie outentifiseer** nie.

### Unconstrained Delegation

As **unconstrained delegation** op die rekenaar geaktiveer is, sal dit nie gebeur nie, aangesien die **Server** 'n **TGT** van elke gebruiker wat dit toegang gee, **sal kry**. Boonop, as unconstrained delegation gebruik word, kan jy waarskynlik die **Domeinbeheerder** daarvan **kompromitteer**.\
[**Meer inligting op die unconstrained delegation bladsy**](unconstrained-delegation.md).

### CredSSP

'n Ander manier om hierdie probleem te vermy wat [**duidelik onveilig**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is, is **Credential Security Support Provider**. Van Microsoft:

> CredSSP-outeentifikasie delegeer die gebruiker se akkrediteer van die plaaslike rekenaar na 'n afstandlike rekenaar. Hierdie praktyk verhoog die sekuriteitsrisiko van die afstandlike operasie. As die afstandlike rekenaar gekompromitteer word, kan die akkrediteer wat aan dit oorgedra word, gebruik word om die netwerk sessie te beheer.

Dit word sterk aanbeveel dat **CredSSP** op produksiesisteme, sensitiewe netwerke en soortgelyke omgewings gedeaktiveer word weens sekuriteitskwessies. Om te bepaal of **CredSSP** geaktiveer is, kan die `Get-WSManCredSSP` opdrag uitgevoer word. Hierdie opdrag stel jou in staat om die **status van CredSSP** te **kontroleer** en kan selfs op afstand uitgevoer word, mits **WinRM** geaktiveer is.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Om die dubbele sprong probleem aan te spreek, word 'n metode met 'n geneste `Invoke-Command` voorgestel. Dit los die probleem nie direk op nie, maar bied 'n omweg sonder die behoefte aan spesiale konfigurasies. Die benadering stel in staat om 'n opdrag (`hostname`) op 'n sekondêre bediener uit te voer deur 'n PowerShell-opdrag wat vanaf 'n aanvanklike aanvalmasjien of deur 'n voorheen gevestigde PS-sessie met die eerste bediener uitgevoer word. Hier is hoe dit gedoen word:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatiewelik, word dit voorgestel om 'n PS-Session met die eerste bediener te vestig en die `Invoke-Command` te gebruik met `$cred` om take te sentraliseer.

### Registreer PSSession Konfigurasie

'n Oplossing om die dubbel hop probleem te omseil behels die gebruik van `Register-PSSessionConfiguration` met `Enter-PSSession`. Hierdie metode vereis 'n ander benadering as `evil-winrm` en laat 'n sessie toe wat nie ly aan die dubbel hop beperking nie.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Vir plaaslike administrateurs op 'n intermediêre teiken, laat port forwarding toe dat versoeke na 'n finale bediener gestuur word. Deur `netsh` te gebruik, kan 'n reël vir port forwarding bygevoeg word, saam met 'n Windows-vuurmuurreël om die voortgelei poort toe te laat.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` kan gebruik word om WinRM versoeke te stuur, moontlik as 'n minder opspoorbare opsie as PowerShell monitering 'n bekommernis is. Die onderstaande opdrag demonstreer die gebruik daarvan:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Die installering van OpenSSH op die eerste bediener stel 'n omseiling van die dubbel-hop probleem in, wat veral nuttig is vir jump box scenario's. Hierdie metode vereis CLI installasie en opstelling van OpenSSH vir Windows. Wanneer dit geconfigureer is vir Wagwoordverifikasie, laat dit die intermediêre bediener toe om 'n TGT namens die gebruiker te verkry.

#### OpenSSH Installasiestappe

1. Laai die nuutste OpenSSH vrystelling zip af en skuif dit na die teikenbediener.
2. Unzip en voer die `Install-sshd.ps1` skrip uit.
3. Voeg 'n firewall-reël by om poort 22 te open en verifieer dat SSH dienste aan die gang is.

Om `Connection reset` foute op te los, mag dit nodig wees om toestemmings op te dateer om almal lees- en uitvoertoegang op die OpenSSH gids toe te laat.
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

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
