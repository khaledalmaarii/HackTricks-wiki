# BloodHound & Ander AD Enum-hulpmiddels

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) is van die Sysinternal Suite:

> 'n Gevorderde Active Directory (AD) kyker en redigeerder. Jy kan AD Explorer gebruik om 'n AD-databasis maklik te navigeer, gunsteling-plekke te definieer, objekteienskappe en -eienskappe sonder om dialoogvensters oop te maak, toestemmings te wysig, 'n objek se skema te besigtig en gesofistikeerde soektogte uit te voer wat jy kan stoor en herhaal.

### Oorsig

AD Explorer kan afskrifte van 'n AD skep sodat jy dit offline kan ondersoek.\
Dit kan gebruik word om kwesbaarhede offline te ontdek, of om verskillende toestande van die AD-databasis oor tyd te vergelyk.

Jy sal die gebruikersnaam, wagwoord en rigting om te verbind (enige AD-gebruiker is nodig) benodig.

Om 'n afskrif van AD te neem, gaan na `File` --> `Create Snapshot` en voer 'n naam vir die afskrif in.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) is 'n hulpmiddel wat verskillende artefakte uit 'n AD-omgewing onttrek en kombineer. Die inligting kan aangebied word in 'n **spesiaal geformateerde** Microsoft Excel **verslag** wat opsommings met metriek bevat om analise te fasiliteer en 'n holistiese prentjie van die huidige toestand van die teiken AD-omgewing te gee.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

Vanaf [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound is 'n enkelbladsy Javascript-webtoepassing, gebou op [Linkurious](http://linkurio.us/), saamgestel met [Electron](http://electron.atom.io/), met 'n [Neo4j](https://neo4j.com/) databasis wat gevoed word deur 'n C# data-insamelaar.

BloodHound gebruik grafiekteorie om die verborge en dikwels onbedoelde verhoudings binne 'n Active Directory- of Azure-omgewing te onthul. Aanvallers kan BloodHound gebruik om hoogs komplekse aanvalspaaie te identifiseer wat andersins onmoontlik sou wees om vinnig te identifiseer. Verdedigers kan BloodHound gebruik om dieselfde aanvalspaaie te identifiseer en uit te skakel. Beide blou en rooi spanne kan BloodHound gebruik om 'n dieper begrip van voorregverhoudings in 'n Active Directory- of Azure-omgewing te verkry.

So, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound)is 'n fantastiese hulpmiddel wat outomaties 'n domein kan opsom, alle inligting kan stoor, moontlike voorregverhogingspaaie kan vind en alle inligting met grafieke kan vertoon.

Bloodhound bestaan uit 2 hoofdele: **ingestors** en die **visualiseringstoepassing**.

Die **ingestors** word gebruik om die domein te **opsom en alle inligting te onttrek** in 'n formaat wat die visualiseringstoepassing sal verstaan.

Die **visualiseringstoepassing gebruik neo4j** om te wys hoe al die inligting verband hou en om verskillende maniere te wys om voorregte in die domein te verhoog.

### Installasie
Na die skepping van BloodHound CE is die hele projek opgedateer vir gebruiksgemak met Docker. Die maklikste manier om te begin, is om die vooraf gekonfigureerde Docker Compose-konfigurasie te gebruik.

1. Installeer Docker Compose. Dit behoort ingesluit te wees by die [Docker Desktop](https://www.docker.com/products/docker-desktop/) installasie.
2. Voer uit:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Vind die lukraak gegenereerde wagwoord in die terminale uitset van Docker Compose.
4. Gaan in 'n webblaaier na http://localhost:8080/ui/login. Teken in met 'n gebruikersnaam van admin en die lukraak gegenereerde wagwoord van die logboeke.

Na hierdie stap moet jy die lukraak gegenereerde wagwoord verander en sal jy die nuwe koppelvlak gereed hê, waarvandaan jy die ingestors direk kan aflaai.

### SharpHound

Hulle het verskeie opsies, maar as jy SharpHound vanaf 'n rekenaar wat by die domein aangesluit is, wil hardloop, met jou huidige gebruiker en alle inligting onttrek, kan jy die volgende doen:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Jy kan meer lees oor **CollectionMethod** en lus sessie [hier](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

As jy SharpHound wil uitvoer met verskillende geloofsbriewe, kan jy 'n CMD netonly sessie skep en SharpHound daarvandaan uitvoer:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Leer meer oor Bloodhound in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) is 'n instrument om **kwesbaarhede** in Active Directory geassosieerde **Group Policy** te vind. \
Jy moet **group3r uitvoer** vanaf 'n gasheer binne die domein met behulp van **enige domein-gebruiker**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **evalueer die veiligheidstoestand van 'n AD-omgewing** en verskaf 'n mooi **verslag** met grafieke.

Om dit uit te voer, kan jy die uitvoerbare lêer `PingCastle.exe` uitvoer en dit sal 'n **interaktiewe sessie** begin wat 'n opsie-meny voorstel. Die verstekopsie om te gebruik is **`healthcheck`** wat 'n basis **oorsig** van die **domein** sal vestig, en **verkeerde konfigurasies** en **kwesbaarhede** sal vind.&#x20;

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
