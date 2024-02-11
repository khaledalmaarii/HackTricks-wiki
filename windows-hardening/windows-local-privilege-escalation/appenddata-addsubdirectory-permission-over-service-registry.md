<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


**Die oorspronklike pos is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Opsomming

Daar is twee registerleutels gevind wat deur die huidige gebruiker geskryf kan word:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Daar is voorgestel om die toestemmings van die **RpcEptMapper**-diens te kontroleer deur die **regedit GUI** te gebruik, spesifiek die venster **Advanced Security Settings** se **Effective Permissions**-koppelvlak. Hierdie benadering maak dit moontlik om die verleen toestemmings aan spesifieke gebruikers of groepe te assesseer sonder om elke Access Control Entry (ACE) afsonderlik te ondersoek.

'n Skermkiekie het die toestemmings wat aan 'n lae-bevoorregte gebruiker toegeken is, gewys, waarvan die **Create Subkey**-toestemming opmerklik was. Hierdie toestemming, ook bekend as **AppendData/AddSubdirectory**, stem ooreen met die bevindinge van die skripsie.

Daar is opgemerk dat daar nie direk sekere waardes gewysig kan word nie, maar die vermoë om nuwe subleutels te skep, wel bestaan. 'n Voorbeeld wat uitgelig is, was 'n poging om die **ImagePath**-waarde te verander, wat gelei het tot 'n toegang geweier boodskap.

Ten spyte van hierdie beperkings is daar 'n potensiaal vir bevoorregte eskalasie geïdentifiseer deur die moontlikheid om die **Performance**-subleutel binne die registerstruktuur van die **RpcEptMapper**-diens te benut, 'n subleutel wat nie standaard teenwoordig is nie. Dit kan DLL-registrasie en prestasiemonitoring moontlik maak.

Dokumentasie oor die **Performance**-subleutel en die gebruik daarvan vir prestasiemonitoring is geraadpleeg, wat gelei het tot die ontwikkeling van 'n bewys-van-konsep DLL. Hierdie DLL, wat die implementering van die **OpenPerfData**, **CollectPerfData**, en **ClosePerfData**-funksies demonstreer, is getoets deur middel van **rundll32**, wat sy operasionele sukses bevestig het.

Die doel was om die **RPC Endpoint Mapper-diens** te dwing om die vervaardigde Prestasie-DLL te laai. Waarnemings het getoon dat die uitvoering van WMI-klasnavrae wat verband hou met Prestasiedata via PowerShell gelei het tot die skep van 'n loglêer, wat die uitvoering van willekeurige kode onder die **LOCAL SYSTEM**-konteks moontlik gemaak het, en dus verhoogde bevoorregting verleen het.

Die volharding en potensiële implikasies van hierdie kwesbaarheid is beklemtoon, waarby die relevansie daarvan vir post-exploitasiestrategieë, laterale beweging en ontduiking van antivirus/EDR-stelsels uitgelig is.

Alhoewel die kwesbaarheid aanvanklik onbedoeld deur die skripsie bekendgestel is, is daar beklemtoon dat die uitbuiting daarvan beperk is tot verouderde weergawes van Windows (bv. **Windows 7 / Server 2008 R2**) en plaaslike toegang vereis.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
