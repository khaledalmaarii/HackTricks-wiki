# BloodHound & Other AD Enum Tools

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) is van die Sysinternal Suite:

> 'n Gevorderde Active Directory (AD) kyker en redigeerder. Jy kan AD Explorer gebruik om maklik deur 'n AD databasis te navigeer, gunsteling plekke te definieer, objek eienskappe en attribuut te sien sonder om dialoogvensters te open, regte te redigeer, 'n objek se skema te sien, en gesofistikeerde soektogte uit te voer wat jy kan stoor en weer uitvoer.

### Snapshots

AD Explorer kan snapshots van 'n AD skep sodat jy dit aflyn kan nagaan.\
Dit kan gebruik word om kwesbaarhede aflyn te ontdek, of om verskillende toestande van die AD DB oor tyd te vergelyk.

Jy sal die gebruikersnaam, wagwoord, en rigting benodig om te verbind (enige AD gebruiker is benodig).

Om 'n snapshot van AD te neem, gaan na `File` --> `Create Snapshot` en voer 'n naam vir die snapshot in.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) is 'n hulpmiddel wat verskeie artefakte uit 'n AD omgewing onttrek en kombineer. Die inligting kan in 'n **spesiaal geformateerde** Microsoft Excel **verslag** aangebied word wat opsommingsoorsigte met metrieke insluit om analise te fasiliteer en 'n holistiese prentjie van die huidige toestand van die teiken AD omgewing te bied.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound is 'n enkele bladsy Javascript-webtoepassing, gebou op [Linkurious](http://linkurio.us/), saamgestel met [Electron](http://electron.atom.io/), met 'n [Neo4j](https://neo4j.com/) databasis wat gevoed word deur 'n C# data-insamelaar.

BloodHound gebruik grafteorie om die versteekte en dikwels onbedoelde verhoudings binne 'n Active Directory of Azure-omgewing te onthul. Aanvallers kan BloodHound gebruik om maklik hoogs komplekse aanvalspaaie te identifiseer wat andersins onmoontlik sou wees om vinnig te identifiseer. Verdedigers kan BloodHound gebruik om daardie selfde aanvalspaaie te identifiseer en te elimineer. Beide blou en rooi span kan BloodHound gebruik om maklik 'n dieper begrip van priviligeverhoudings in 'n Active Directory of Azure-omgewing te verkry.

So, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound)is 'n wonderlike hulpmiddel wat 'n domein outomaties kan opnoem, al die inligting kan stoor, moontlike privilige-eskalasiepaaie kan vind en al die inligting kan vertoon met behulp van grafieke.

Booldhound bestaan uit 2 hoofdele: **ingestors** en die **visualiseringstoepassing**.

Die **ingestors** word gebruik om **die domein op te noem en al die inligting te onttrek** in 'n formaat wat die visualiseringstoepassing sal verstaan.

Die **visualiseringstoepassing gebruik neo4j** om te wys hoe al die inligting verwant is en om verskillende maniere te wys om privilige in die domein te eskaleer.

### Installasie
Na die skepping van BloodHound CE, is die hele projek opgedateer vir gebruiksgemak met Docker. Die maklikste manier om te begin is om sy vooraf-gekonfigureerde Docker Compose-konfigurasie te gebruik.

1. Installeer Docker Compose. Dit behoort ingesluit te wees met die [Docker Desktop](https://www.docker.com/products/docker-desktop/) installasie.
2. Voer uit:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Vind die ewekansig gegenereerde wagwoord in die terminaluitvoer van Docker Compose.  
4. In 'n blaaier, navigeer na http://localhost:8080/ui/login. Teken in met 'n gebruikersnaam van admin en die ewekansig gegenereerde wagwoord uit die logs.  

Na hierdie sal jy die ewekansig gegenereerde wagwoord moet verander en jy sal die nuwe koppelvlak gereed hê, waarvan jy direk die ingestors kan aflaai.  

### SharpHound  

Hulle het verskeie opsies, maar as jy SharpHound vanaf 'n rekenaar wat by die domein aangesluit is, wil uitvoer, met jou huidige gebruiker en al die inligting wil onttrek, kan jy doen:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Jy kan meer lees oor **CollectionMethod** en lus sessie [hier](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

As jy SharpHound met verskillende geloofsbriewe wil uitvoer, kan jy 'n CMD netonly sessie skep en SharpHound van daar af uitvoer:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Leer meer oor Bloodhound in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) is 'n hulpmiddel om **kwesbaarhede** in Active Directory geassosieer met **Groep Beleid** te vind. \
Jy moet **group3r** vanaf 'n gasheer binne die domein gebruik met **enige domein gebruiker**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **evalueer die sekuriteitsposisie van 'n AD-omgewing** en bied 'n mooi **verslag** met grafieke.

Om dit te laat loop, kan jy die binêre `PingCastle.exe` uitvoer en dit sal 'n **interaktiewe sessie** begin wat 'n menu van opsies aanbied. Die standaardopsie om te gebruik is **`healthcheck`** wat 'n basislyn **oorsig** van die **domein** sal vestig, en **misconfigurasies** en **kwesbaarhede** sal vind.&#x20;

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
