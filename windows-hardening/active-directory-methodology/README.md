# Active Directory Metodologie

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basiese oorsig

**Active Directory** dien as 'n fundamentele tegnologie, wat **netwerkadministrateurs** in staat stel om doeltreffend **domeine**, **gebruikers**, en **objekte** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, wat die organisasie van 'n groot aantal gebruikers in hanteerbare **groepe** en **subgroepe** vergemaklik, terwyl dit **toegangregte** op verskeie vlakke beheer.

Die struktuur van **Active Directory** bestaan uit drie primêre lae: **domeine**, **bome**, en **woude**. 'n **domein** omvat 'n versameling van objekte, soos **gebruikers** of **toestelle**, wat 'n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur 'n gedeelde struktuur verbind is, en 'n **woud** verteenwoordig die versameling van verskeie bome, wat deur **vertrouensverhoudings** met mekaar verbind is, wat die boonste laag van die organisatoriese struktuur vorm. Spesifieke **toegang** en **kommunikasie regte** kan op elk van hierdie vlakke aangewys word.

Belangrike konsepte binne **Active Directory** sluit in:

1. **Gids** – Huis al die inligting rakende Active Directory objekte.
2. **Objek** – Dui entiteite binne die gids aan, insluitend **gebruikers**, **groepe**, of **gedeelde vouers**.
3. **Domein** – Dien as 'n houer vir gidsobjekte, met die vermoë dat verskeie domeine binne 'n **woud** saam kan bestaan, elk wat sy eie objekversameling handhaaf.
4. **Boom** – 'n Groepering van domeine wat 'n gemeenskaplike worteldomein deel.
5. **Woud** – Die hoogtepunt van organisatoriese struktuur in Active Directory, saamgestel uit verskeie bome met **vertrouensverhoudings** tussen hulle.

**Active Directory Domein Dienste (AD DS)** omvat 'n reeks dienste wat krities is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domein Dienste** – Sentraliseer data berging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **verifikasie** en **soek** funksies.
2. **Sertifikaat Dienste** – Toesig oor die skepping, verspreiding, en bestuur van veilige **digitale sertifikate**.
3. **Liggewig Gids Dienste** – Ondersteun gids-geaktiveerde toepassings deur die **LDAP protokol**.
4. **Gids Federasie Dienste** – Verskaf **enkele-aanmelding** vermoëns om gebruikers oor verskeie webtoepassings in 'n enkele sessie te verifieer.
5. **Regte Bestuur** – Help om kopiereg materiaal te beskerm deur die ongeoorloofde verspreiding en gebruik daarvan te reguleer.
6. **DNS Diens** – Krities vir die resolusie van **domeinnaam**.

Vir 'n meer gedetailleerde verduideliking, kyk: [**TechTerms - Active Directory Definisie**](https://techterms.com/definition/active\_directory)

### **Kerberos Verifikasie**

Om te leer hoe om 'n **AD** aan te val, moet jy die **Kerberos verifikasie proses** regtig goed verstaan.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Cheat Sheet

Jy kan baie vind op [https://wadcoms.github.io/](https://wadcoms.github.io) om 'n vinnige oorsig te kry van watter opdragte jy kan uitvoer om 'n AD te evalueer/exploit.

## Recon Active Directory (Geen krediete/sessies)

As jy net toegang het tot 'n AD omgewing maar jy het geen krediete/sessies nie, kan jy:

* **Pentest die netwerk:**
* Skandeer die netwerk, vind masjiene en oop poorte en probeer om **kwesbaarhede te exploiteer** of **krediete** van hulle te **onttrek** (byvoorbeeld, [drukker kan baie interessante teikens wees](ad-information-in-printers.md)).
* Om DNS te evalueer kan inligting oor sleutelbedieners in die domein gee soos web, drukker, gedeeltes, vpn, media, ens.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Kyk na die Algemene [**Pentesting Metodologie**](../../generic-methodologies-and-resources/pentesting-methodology.md) om meer inligting te vind oor hoe om dit te doen.
* **Kyk vir null en Gaste toegang op smb dienste** (dit sal nie op moderne Windows weergawes werk nie):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* 'n Meer gedetailleerde gids oor hoe om 'n SMB bediener te evalueer kan hier gevind word:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Evalueer Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* 'n Meer gedetailleerde gids oor hoe om LDAP te evalueer kan hier gevind word (pay **spesiale aandag aan die anonieme toegang**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Besoedel die netwerk**
* Versamel krediete [**deur dienste te vervang met Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Toegang tot gasheer deur [**die relay aanval te misbruik**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Versamel krediete **deur** [**valse UPnP dienste met evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Trek gebruikersname/names uit interne dokumente, sosiale media, dienste (hoofsaaklik web) binne die domein omgewings en ook van die publiek beskikbaar.
* As jy die volledige name van maatskappywerkers vind, kan jy verskillende AD **gebruikersnaam konvensies** probeer (**[**lees dit**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die mees algemene konvensies is: _NaamVan_, _Naam.Van_, _NamVan_ (3 letters van elkeen), _Nam.Van_, _NVaan_, _N.Van_, _VanNaam_, _Van.Naam_, _VanN_, _Van.N_, 3 _ewekansige letters en 3 ewekansige nommers_ (abc123).
* Gereedskap:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Gebruiker evalueering

* **Anonieme SMB/LDAP enum:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
* **Kerbrute enum**: Wanneer 'n **ongeldige gebruikersnaam aangevra** word, sal die bediener reageer met die **Kerberos fout** kode _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, wat ons in staat stel om te bepaal dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal of die **TGT in 'n AS-REP** antwoord of die fout _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_ uitlok, wat aandui dat die gebruiker verplig is om voorverifikasie te doen.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) Bediening**

As jy een van hierdie bedieners in die netwerk gevind het, kan jy ook **gebruikersenumerasie teen dit** uitvoer. Byvoorbeeld, jy kan die hulpmiddel [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
Jy kan lysies van gebruikersname in [**hierdie github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) vind.

Jy moet egter die **naam van die mense wat by die maatskappy werk** hê van die rekonstruksie stap wat jy voorheen gedoen het. Met die naam en van kan jy die skrip [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige gebruikersname te genereer.
{% endhint %}

### Om een of verskeie gebruikersname te ken

Goed, jy weet jy het reeds 'n geldige gebruikersnaam maar geen wagwoorde nie... Probeer dan:

* [**ASREPRoast**](asreproast.md): As 'n gebruiker **nie** die attribuut _DONT\_REQ\_PREAUTH_ het nie, kan jy **'n AS\_REP boodskap** vir daardie gebruiker aan vra wat sekere data bevat wat deur 'n afgeleide van die gebruiker se wagwoord geënkripteer is.
* [**Password Spraying**](password-spraying.md): Kom ons probeer die mees **gewone wagwoorde** met elkeen van die ontdekte gebruikers, dalk gebruik 'n gebruiker 'n slegte wagwoord (hou die wagwoordbeleid in gedagte!).
* Let daarop dat jy ook **OWA bedieners kan spuit** om toegang tot die gebruikers se posbedieners te probeer kry.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Vergiftiging

Jy mag dalk in staat wees om **uit te vind** van sommige uitdaging **hashes** om **vergiftiging** van sommige protokolle van die **netwerk** te kraak:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

As jy daarin geslaag het om die aktiewe gids te enumereer, sal jy **meer e-posse en 'n beter begrip van die netwerk** hê. Jy mag dalk in staat wees om NTML [**relay-aanvalle**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* te dwing om toegang tot die AD omgewing te kry.

### Steel NTLM Krediete

As jy **toegang tot ander rekenaars of gedeeltes** met die **null of gas gebruiker** kan kry, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, as dit op een of ander manier toegang verkry, 'n **NTML-authentisering teen jou** sal **aktiveer** sodat jy die **NTLM uitdaging** kan steel om dit te kraak:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumereer Aktiewe Gids MET krediete/sessie

Vir hierdie fase moet jy **die krediete of 'n sessie van 'n geldige domeinrekening gecompromitteer het.** As jy 'n paar geldige krediete of 'n shell as 'n domein gebruiker het, **moet jy onthou dat die opsies wat voorheen gegee is steeds opsies is om ander gebruikers te kompromitteer**.

Voordat jy die geverifieerde enumerasie begin, moet jy weet wat die **Kerberos dubbele hop probleem is.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumerasie

Om 'n rekening gecompromitteer te hê is 'n **groot stap om die hele domein te begin kompromitteer**, want jy gaan in staat wees om die **Aktiewe Gids Enumerasie te begin:**

Ten opsigte van [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike kwesbare gebruiker vind, en ten opsigte van [**Password Spraying**](password-spraying.md) kan jy 'n **lys van al die gebruikersname** kry en die wagwoord van die gecompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde probeer.

* Jy kan die [**CMD gebruik om 'n basiese rekonstruksie uit te voer**](../basic-cmd-for-pentesters.md#domain-info)
* Jy kan ook [**powershell vir rekonstruksie gebruik**](../basic-powershell-for-pentesters/) wat meer stil sal wees
* Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
* 'n Ander wonderlike hulpmiddel vir rekonstruksie in 'n aktiewe gids is [**BloodHound**](bloodhound.md). Dit is **nie baie stil nie** (afhangende van die versamelingsmetodes wat jy gebruik), maar **as jy nie omgee** nie, moet jy dit beslis probeer. Vind waar gebruikers RDP kan, vind pad na ander groepe, ens.
* **Ander geoutomatiseerde AD enumerasie hulpmiddels is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**DNS rekords van die AD**](ad-dns-records.md) aangesien dit dalk interessante inligting kan bevat.
* 'n **hulpmiddel met GUI** wat jy kan gebruik om die gids te enumereer is **AdExplorer.exe** van **SysInternal** Suite.
* Jy kan ook in die LDAP databasis soek met **ldapsearch** om na krediete in die velde _userPassword_ & _unixUserPassword_, of selfs vir _Description_ te kyk. cf. [Wagwoord in AD Gebruiker kommentaar op PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
* As jy **Linux** gebruik, kan jy ook die domein enumereer met [**pywerview**](https://github.com/the-useless-one/pywerview).
* Jy kan ook probeer om geoutomatiseerde hulpmiddels soos:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Alle domein gebruikers onttrek**

Dit is baie maklik om al die domein gebruikersname van Windows te verkry (`net user /domain`, `Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Alhoewel hierdie Enumerasie afdeling klein lyk, is dit die belangrikste deel van alles. Toegang die skakels (hoofsaaklik die een van cmd, powershell, powerview en BloodHound), leer hoe om 'n domein te enumereer en oefen totdat jy gemaklik voel. Tydens 'n assessering sal dit die sleutelmoment wees om jou pad na DA te vind of om te besluit dat daar niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS kaartjies** wat deur dienste wat aan gebruikersrekeninge gekoppel is, gebruik word en die kraken van hul enkripsie—wat gebaseer is op gebruikerswagwoorde—**aflyn**.

Meer hieroor in:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Afgeleë verbinding (RDP, SSH, FTP, Win-RM, ens)

Sodra jy 'n paar krediete verkry het, kan jy kyk of jy toegang tot enige **masjien** het. Hiervoor kan jy **CrackMapExec** gebruik om te probeer om op verskeie bedieners met verskillende protokolle te verbind, volgens jou poort skanderings.

### Plaaslike Privilege Escalation

As jy gecompromitteerde krediete of 'n sessie as 'n gewone domein gebruiker het en jy het **toegang** met hierdie gebruiker tot **enige masjien in die domein**, moet jy probeer om jou pad te vind om **privileges plaaslik te verhoog en krediete te soek**. Dit is omdat jy slegs met plaaslike administrateurprivileges in staat sal wees om **hashes van ander gebruikers** in geheue (LSASS) en plaaslik (SAM) te **dump**.

Daar is 'n volledige bladsy in hierdie boek oor [**plaaslike privilege escalasie in Windows**](../windows-local-privilege-escalation/) en 'n [**kontrolelys**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Huidige Sessie Kaartjies

Dit is baie **onwaarskynlik** dat jy **kaartjies** in die huidige gebruiker sal vind wat jou toestemming gee om **onverwagte hulpbronne** te benader, maar jy kan kyk:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

As jy daarin geslaag het om die aktiewe gids te enumereer, sal jy **meer e-posse en 'n beter begrip van die netwerk** hê. Jy mag in staat wees om NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** af te dwing.**

### **Soek na Kredensiale in Rekenaar Deelshares**

Nou dat jy 'n paar basiese kredensiale het, moet jy kyk of jy enige **interessante lêers kan vind wat binne die AD gedeel word**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige herhalende taak (en nog meer as jy honderde dokumente moet nagaan).

[**Volg hierdie skakel om meer te leer oor gereedskap wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Steel NTLM Kredensiale

As jy **toegang tot ander rekenaars of deelshares** kan kry, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, as dit op een of ander manier toegang verkry, **'n NTML-authentisering teen jou sal aktiveer** sodat jy die **NTLM-uitdaging** kan steel om dit te kraak:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geverifieerde gebruiker toegelaat om die **domeinbeheerder te kompromitteer**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Privilege escalation on Active Directory MET bevoorregte kredensiale/sessie

**Vir die volgende tegnieke is 'n gewone domein gebruiker nie genoeg nie, jy het 'n paar spesiale voorregte/kredensiale nodig om hierdie aanvalle uit te voer.**

### Hash ekstraksie

Hopelik het jy daarin geslaag om 'n **lokale admin** rekening te **kompromitteer** met behulp van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitend relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [bevoorregte eskalasie plaaslik](../windows-local-privilege-escalation/).\
Dan is dit tyd om al die hashes in geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hashes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sodra jy die hash van 'n gebruiker het**, kan jy dit gebruik om **te verteenwoordig**.\
Jy moet 'n **gereedskap** gebruik wat die **NTLM-authentisering met** daardie **hash** sal **uitvoer**, **of** jy kan 'n nuwe **sessionlogon** skep en daardie **hash** binne die **LSASS** **injekteer**, sodat wanneer enige **NTLM-authentisering uitgevoer word**, daardie **hash gebruik sal word.** Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Hierdie aanval is daarop gemik om **die gebruiker se NTLM-hash te gebruik om Kerberos-kaarte aan te vra**, as 'n alternatief vir die algemene Pass The Hash oor die NTLM-protokol. Daarom kan dit veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos toegelaat word** as authentiseringsprotokol.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

In die **Pass The Ticket (PTT)** aanvalmetode, **steel aanvallers 'n gebruiker se authentiseringsticket** in plaas van hul wagwoord of hashwaardes. Hierdie gesteelde kaart word dan gebruik om die **gebruiker te verteenwoordig**, wat ongeoorloofde toegang tot hulpbronne en dienste binne 'n netwerk verkry.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Kredensiale Hergebruik

As jy die **hash** of **wagwoord** van 'n **lokale administrateur** het, moet jy probeer om **lokaal in te teken** op ander **rekenaars** daarmee.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Let wel, dit is baie **luidrugtig** en **LAPS** sal dit **verlig**.
{% endhint %}

### MSSQL Misbruik & Vertroude Skakels

As 'n gebruiker die voorregte het om **MSSQL-instansies** te **toegang**, kan hy dit gebruik om **opdragte** in die MSSQL-gasheer uit te voer (as dit as SA loop), die NetNTLM **hash** te **steel** of selfs 'n **relay** **aanval** uit te voer.\
Ook, as 'n MSSQL-instansie vertrou word (databasis skakel) deur 'n ander MSSQL-instansie. As die gebruiker voorregte oor die vertroude databasis het, sal hy in staat wees om die **vertrouensverhouding te gebruik om ook in die ander instansie navrae uit te voer**. Hierdie vertroue kan geketting word en op 'n sekere punt mag die gebruiker 'n verkeerd geconfigureerde databasis vind waar hy opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor bosvertroue.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Onbeperkte Afvaardiging

As jy enige rekenaarobjek met die attribuut [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) vind en jy het domeinvoorregte op die rekenaar, sal jy in staat wees om TGT's uit die geheue van elke gebruiker wat op die rekenaar aanmeld, te dump.\
So, as 'n **Domein Admin op die rekenaar aanmeld**, sal jy in staat wees om sy TGT te dump en hom na te doen met behulp van [Pass the Ticket](pass-the-ticket.md).\
Danksy beperkte afvaardiging kan jy selfs 'n **Drukbediener outomaties kompromenteer** (hopelik sal dit 'n DC wees).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Beperkte Afvaardiging

As 'n gebruiker of rekenaar toegelaat word vir "Beperkte Afvaardiging", sal dit in staat wees om **enige gebruiker na te doen om toegang tot sekere dienste in 'n rekenaar te verkry**.\
Dan, as jy die **hash** van hierdie gebruiker/rekenaar **kompromenteer**, sal jy in staat wees om **enige gebruiker** (selfs domeinadmins) na te doen om toegang tot sekere dienste te verkry.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Hulpbronne-gebaseerde Beperkte Afvaardiging

Om **SKRYF** voorreg op 'n Aktiewe Gids objek van 'n afgeleë rekenaar te hê, stel die verkryging van kode-uitvoering met **verhoogde voorregte** moontlik:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACLs Misbruik

Die gecompromitteerde gebruiker kan 'n paar **interessante voorregte oor sekere domeinobjekte** hê wat jou kan laat **beweeg** lateraal/**verhoog** voorregte.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Drukspooler diens misbruik

Die ontdekking van 'n **Spool diens wat luister** binne die domein kan **misbruik** word om **nuwe akrediteer** te **verkry** en **voorregte te verhoog**.

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Derdeparty sessies misbruik

As **ander gebruikers** die **gecompromitteerde** masjien **toegang**, is dit moontlik om **akrediteer uit die geheue te versamel** en selfs **beacons in hul prosesse in te spuit** om hulle na te doen.\
Gewoonlik sal gebruikers die stelsel via RDP toegang, so hier is hoe om 'n paar aanvalle oor derdeparty RDP-sessies uit te voer:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** bied 'n stelsel vir die bestuur van die **lokale Administrateur wagwoord** op domein-verbonden rekenaars, wat verseker dat dit **gevalle** is, uniek is, en gereeld **verander**. Hierdie wagwoorde word in Aktiewe Gids gestoor en toegang word beheer deur ACLs slegs aan gemagtigde gebruikers. Met voldoende toestemmings om toegang tot hierdie wagwoorde te verkry, word dit moontlik om na ander rekenaars te pivot.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Sertifikaat Diefstal

**Die versameling van sertifikate** van die gecompromitteerde masjien kan 'n manier wees om voorregte binne die omgewing te verhoog:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Sertifikaat Templates Misbruik

As **kwetsbare templates** geconfigureer is, is dit moontlik om hulle te misbruik om voorregte te verhoog:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-exploitatie met hoë voorregte rekening

### Dumping Domein Akrediteer

Sodra jy **Domein Admin** of selfs beter **Enterprise Admin** voorregte kry, kan jy die **domeindatabasis** dump: _ntds.dit_.

[**Meer inligting oor DCSync aanval kan hier gevind word**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel kan hier gevind word**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistensie

Sommige van die tegnieke wat voorheen bespreek is, kan gebruik word vir persistensie.\
Byvoorbeeld, jy kan:

*   Maak gebruikers kwesbaar vir [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Maak gebruikers kwesbaar vir [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   Gee [**DCSync**](./#dcsync) voorregte aan 'n gebruiker

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silwer Kaart

Die **Silwer Kaart aanval** skep 'n **legitieme Ticket Granting Service (TGS) kaart** vir 'n spesifieke diens deur die **NTLM hash** te gebruik (byvoorbeeld, die **hash van die PC rekening**). Hierdie metode word gebruik om **toegang tot die diens voorregte** te verkry.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Goue Kaart

'n **Goue Kaart aanval** behels dat 'n aanvaller toegang verkry tot die **NTLM hash van die krbtgt rekening** in 'n Aktiewe Gids (AD) omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGTs)** te teken, wat noodsaaklik is vir die verifikasie binne die AD netwerk.

Sodra die aanvaller hierdie hash verkry, kan hulle **TGTs** vir enige rekening wat hulle kies skep (Silwer kaart aanval).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamant Kaart

Hierdie is soos goue kaarte wat op 'n manier vervals is wat **algemene goue kaart opsporingsmeganismes omseil**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Sertifikate Rekening Persistensie**

**Om sertifikate van 'n rekening te hê of in staat te wees om hulle aan te vra** is 'n baie goeie manier om in die gebruikersrekening te kan volhard (selfs as hy die wagwoord verander):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Sertifikate Domein Persistensie**

**Om sertifikate te gebruik is ook moontlik om met hoë voorregte binne die domein te volhard:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder Groep

Die **AdminSDHolder** objek in Aktiewe Gids verseker die sekuriteit van **voorregte groepe** (soos Domein Admins en Enterprise Admins) deur 'n standaard **Toegangsbeheerlys (ACL)** oor hierdie groepe toe te pas om ongeoorloofde veranderinge te voorkom. egter, hierdie kenmerk kan misbruik word; as 'n aanvaller die AdminSDHolder se ACL verander om volle toegang aan 'n gewone gebruiker te gee, kry daardie gebruiker uitgebreide beheer oor al die voorregte groepe. Hierdie sekuriteitsmaatreël, wat bedoel is om te beskerm, kan dus omgekeerd werk, wat ongeoorloofde toegang toelaat tensy dit noukeurig gemonitor word.

[**Meer inligting oor AdminDSHolder Groep hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Akrediteer

Binne elke **Domein Beheerder (DC)** bestaan 'n **lokale administrateur** rekening. Deur admin regte op so 'n masjien te verkry, kan die lokale Administrateur hash met behulp van **mimikatz** onttrek word. Daarna is 'n registerwysiging nodig om **die gebruik van hierdie wagwoord te aktiveer**, wat vir afstandstoegang tot die lokale Administrateur rekening toelaat.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL Persistensie

Jy kan **spesiale toestemmings** aan 'n **gebruiker** oor sekere spesifieke domeinobjekte gee wat die gebruiker sal laat **verhoog** voorregte in die toekoms.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Sekuriteitsbeskrywings

Die **sekuriteitsbeskrywings** word gebruik om die **toestemmings** wat 'n **objek** oor 'n **objek** het, te **stoor**. As jy net 'n **klein verandering** in die **sekuriteitsbeskrywing** van 'n objek kan maak, kan jy baie interessante voorregte oor daardie objek verkry sonder om lid van 'n voorregte groep te wees.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skelet Sleutel

Verander **LSASS** in geheue om 'n **universale wagwoord** te vestig, wat toegang tot alle domeinrekeninge verleen.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Pasgemaakte SSP

[Leer wat 'n SSP (Security Support Provider) hier is.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **akrediteer** wat gebruik word om toegang tot die masjien te verkry, in **duidelike teks** te **vang**.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Dit registreer 'n **nuwe Domein Beheerder** in die AD en gebruik dit om **attribuutte** (SIDHistory, SPNs...) op gespesifiseerde objek te **druk** **sonder** om enige **logs** rakende die **wysigings** te laat. Jy **het DA** voorregte nodig en moet binne die **worteldomein** wees.\
Let daarop dat as jy verkeerde data gebruik, baie lelike logs sal verskyn.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS Persistensie

Voorheen het ons bespreek hoe om voorregte te verhoog as jy **genoeg toestemming het om LAPS wagwoorde te lees**. egter, hierdie wagwoorde kan ook gebruik word om **persistensie te handhaaf**.\
Kyk:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Bos Voorregte Verhoging - Domein Vertroue

Microsoft beskou die **Bos** as die sekuriteitsgrens. Dit impliseer dat **die kompromitering van 'n enkele domein moontlik kan lei tot die hele Bos wat gecompromitteer word**.

### Basiese Inligting

'n [**domein vertroue**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) is 'n sekuriteitsmeganisme wat 'n gebruiker van een **domein** in staat stel om toegang tot hulpbronne in 'n ander **domein** te verkry. Dit skep essensieel 'n skakel tussen die verifikasiesisteme van die twee domeine, wat toelaat dat verifikasie bevestigings naatloos vloei. Wanneer domeine 'n vertroue opstel, ruil hulle spesifieke **sleutels** uit en hou dit binne hul **Domein Beheerders (DCs)**, wat noodsaaklik is vir die integriteit van die vertroue.

In 'n tipiese scenario, as 'n gebruiker 'n diens in 'n **vertroude domein** wil toegang, moet hulle eers 'n spesiale kaart aan vra wat bekend staan as 'n **inter-realm TGT** van hul eie domein se DC. Hierdie TGT is versleuteld met 'n gedeelde **sleutel** wat albei domeine ooreengekom het. Die gebruiker bied dan hierdie TGT aan die **DC van die vertroude domein** aan om 'n dienskaart (**TGS**) te verkry. Na suksesvolle validasie van die inter-realm TGT deur die vertroude domein se DC, stel dit 'n TGS uit, wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **klient rekenaar** in **Domein 1** begin die proses deur sy **NTLM hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** van sy **Domein Beheerder (DC1)** aan te vra.
2. DC1 stel 'n nuwe TGT uit as die klient suksesvol geverifieer word.
3. Die klient vra dan 'n **inter-realm TGT** van DC1 aan, wat nodig is om toegang tot hulpbronne in **Domein 2** te verkry.
4. Die inter-realm TGT is versleuteld met 'n **vertrouensleutel** wat tussen DC1 en DC2 as deel van die twee-rigting domein vertroue gedeel word.
5. Die klient neem die inter-realm TGT na **Domein 2 se Domein Beheerder (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde vertrouensleutel en, as geldig, stel dit 'n **Ticket Granting Service (TGS)** uit vir die bediener in Domein 2 wat die klient wil toegang.
7. Laastens, bied die klient hierdie TGS aan die bediener aan, wat versleuteld is met die bediener se rekening hash, om toegang tot die diens in Domein 2 te verkry.

### Verskillende vertroue

Dit is belangrik om op te let dat **'n vertroue 1 rigting of 2 rigtings kan wees**. In die 2 rigtings opsies, sal albei domeine mekaar vertrou, maar in die **1 rigting** vertrouensverhouding sal een van die domeine die **vertroude** en die ander die **vertrouende** domein wees. In die laaste geval, **sal jy slegs in staat wees om toegang tot hulpbronne binne die vertrouende domein van die vertroude een te verkry**.

As Domein A Domein B vertrou, is A die vertrouende domein en B is die vertroude een. Boonop, in **Domein A**, sal dit 'n **Uitgaande vertroue** wees; en in **Domein B**, sal dit 'n **Inkomende vertroue** wees.

**Verskillende vertrouende verhoudings**

* **Ouers-Kind Vertroue**: Dit is 'n algemene opstelling binne dieselfde bos, waar 'n kinderdomein outomaties 'n twee-rigting transitive vertroue met sy ouerdomein het. Essensieel beteken dit dat verifikasie versoeke naatloos tussen die ouer en die kind kan vloei.
* **Kruiskoppel Vertroue**: Genoem "kortpad vertroue," hierdie word tussen kinderdomeine gevestig om verwysingsprosesse te versnel. In komplekse bosse moet verifikasie verwysings tipies tot die boswortel reis en dan af na die teikendomein. Deur kruiskoppels te skep, word die reis verkort, wat veral voordelig is in geografies verspreide omgewings.
* **Buitelandse Vertroue**: Hierdie word tussen verskillende, nie-verwante domeine opgestel en is nie-transitief van aard. Volgens [Microsoft se dokumentasie](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), is buitelandse vertroue nuttig vir toegang tot hulpbronne in 'n domein buite die huidige bos wat nie met 'n bosvertroue verbind is nie. Sekuriteit word versterk deur SID filtrering met buitelandse vertroue.
* **Boomwortel Vertroue**: Hierdie vertroue word outomaties gevestig tussen die bosworteldomein en 'n nuut bygevoegde boomwortel. Alhoewel dit nie algemeen teëgekom word nie, is boomwortel vertroue belangrik vir die byvoeging van nuwe domeinbome aan 'n bos, wat hulle in staat stel om 'n unieke domeinnaam te handhaaf en twee-rigting transitiwiteit te verseker. Meer inligting kan gevind word in [Microsoft se gids](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Bos Vertroue**: Hierdie tipe vertroue is 'n twee-rigting transitive vertroue tussen twee bosworteldomeine, wat ook SID filtrering afdwing om sekuriteitsmaatreëls te verbeter.
* **MIT Vertroue**: Hierdie vertroue word gevestig met nie-Windows, [RFC4120-nakoming](https://tools.ietf.org/html/rfc4120) Kerberos domeine. MIT vertroue is 'n bietjie meer gespesialiseerd en dien omgewings wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem vereis.

#### Ander verskille in **vertrouende verhoudings**

* 'n Vertrouensverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dan A vertrou C) of **nie-transitief** wees.
* 'n Vertrouensverhouding kan opgestel word as **bidireksionele vertroue** (albei vertrou mekaar) of as **een-rigting vertroue** (slegs een van hulle vertrou die ander).

### Aanvalspad

1. **Lys** die vertrouende verhoudings
2. Kyk of enige **sekuriteitsbeginsel** (gebruiker/groep/rekenaar) **toegang** tot hulpbronne van die **ander domein** het, dalk deur ACE inskrywings of deur in groepe van die ander domein te wees. Soek na **verhoudings oor domeine** (die vertroue is waarskynlik hiervoor geskep).
1. kerberoast in hierdie geval kan 'n ander opsie wees.
3. **Kompromitteer** die **rekeninge** wat deur domeine kan **pivot**.

Aanvallers kan toegang tot hulpbronne in 'n ander domein verkry deur drie primêre meganismes:

* **Plaaslike Groep Lidmaatskap**: Beginsels mag by plaaslike groepe op masjiene gevoeg word, soos die “Administrateurs” groep op 'n bediener, wat hulle beduidende beheer oor daardie masjien verleen.
* **Buitelandse Domein Groep Lidmaatskap**: Beginsels kan ook lede van groepe binne die buitelandse domein wees. Die doeltreffendheid van hierdie metode hang egter af van die aard van die vertroue en die omvang van die groep.
* **Toegangsbeheerlyste (ACLs)**: Beginsels mag in 'n **ACL** gespesifiseer word, veral as entiteite in **ACEs** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne bied. Vir diegene wat die meganika van ACLs, DACLs, en ACEs verder wil verken, is die witpapier getiteld “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)” 'n onontbeerlike hulpbron.

### Kind-naar-Ouder bos voorregte verhoging
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
Daar is **2 vertroude sleutels**, een vir _Kind --> Ouers_ en nog een vir _Ouers_ --> _Kind_.\
Jy kan die een wat deur die huidige domein gebruik word, met:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

Verhoog as Enterprise admin na die kind/ouer domein deur die vertroue met SID-History-inspuiting te misbruik:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Exploit writeable Configuration NC

Om te verstaan hoe die Configuration Naming Context (NC) misbruik kan word, is van kardinale belang. Die Configuration NC dien as 'n sentrale berging vir konfigurasie data oor 'n woud in Active Directory (AD) omgewings. Hierdie data word na elke Domeinbeheerder (DC) binne die woud gerepliceer, met skryfbare DC's wat 'n skryfbare kopie van die Configuration NC handhaaf. Om dit te misbruik, moet 'n mens **SYSTEM regte op 'n DC** hê, verkieslik 'n kind DC.

**Link GPO aan wortel DC webwerf**

Die Configuration NC se Sites hou inligting oor alle domein-verbonden rekenaars se webwerwe binne die AD woud. Deur met SYSTEM regte op enige DC te werk, kan aanvallers GPO's aan die wortel DC webwerwe koppel. Hierdie aksie kan die worteldomein potensieel in gevaar stel deur beleid wat op hierdie webwerwe toegepas word, te manipuleer.

Vir diepgaande inligting kan 'n mens navorsing oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) verken.

**Kompromenteer enige gMSA in die woud**

'n Aanvalsvector behels die teiken van bevoorregte gMSA's binne die domein. Die KDS Root-sleutel, wat noodsaaklik is vir die berekening van gMSA se wagwoorde, word binne die Configuration NC gestoor. Met SYSTEM regte op enige DC, is dit moontlik om toegang tot die KDS Root-sleutel te verkry en die wagwoorde vir enige gMSA oor die woud te bereken.

Gedetailleerde analise kan gevind word in die bespreking oor [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Hierdie metode vereis geduld, terwyl daar gewag word vir die skepping van nuwe bevoorregte AD-objekte. Met SYSTEM regte kan 'n aanvaller die AD Schema wysig om enige gebruiker volledige beheer oor alle klasse te verleen. Dit kan lei tot ongemagtigde toegang en beheer oor nuutgeskepte AD-objekte.

Verder leesstof is beskikbaar oor [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 kwesbaarheid teiken beheer oor Public Key Infrastructure (PKI) objekte om 'n sertifikaat sjabloon te skep wat autentisering as enige gebruiker binne die woud moontlik maak. Aangesien PKI objekte in die Configuration NC woon, stel die kompromentering van 'n skryfbare kind DC die uitvoering van ESC5-aanvalle in staat.

Meer besonderhede hieroor kan gelees word in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's waar ADCS ontbreek, het die aanvaller die vermoë om die nodige komponente op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
In hierdie scenario **word jou domein vertrou** deur 'n eksterne een wat jou **onbepaalde toestemmings** oor dit gee. Jy sal moet uitvind **watter prinsipale van jou domein watter toegang oor die eksterne domein het** en dan probeer om dit te benut:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Eksterne Woud Domein - Eenrigting (Uitgaand)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In hierdie scenario **jou domein** **vertrou** sekere **privileges** aan 'n hoof van **verskillende domeine**.

Wanneer 'n **domein vertrou** word deur die vertrouende domein, **skep die vertroude domein 'n gebruiker** met 'n **voorspelbare naam** wat as **wagwoord die vertroude wagwoord** gebruik. Dit beteken dat dit moontlik is om **toegang te verkry tot 'n gebruiker van die vertrouende domein om binne die vertroude een te kom** om dit te evalueer en te probeer om meer privileges te verhoog:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

'n Ander manier om die vertroude domein te kompromitteer, is om 'n [**SQL vertroude skakel**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

'n Ander manier om die vertroude domein te kompromitteer, is om te wag op 'n masjien waar 'n **gebruiker van die vertroude domein toegang kan verkry** om in te log via **RDP**. Dan kan die aanvaller kode in die RDP-sessieproses inspuit en **toegang verkry tot die oorspronklike domein van die slagoffer** van daar.\
Boonop, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP-sessie** proses **terugdeure** in die **opstartgids van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Misbruik van domeinvertroue mitigering

### **SID Filtrering:**

* Die risiko van aanvalle wat die SID-geskiedenisattribuut oor woudvertroue benut, word gemitigeer deur SID Filtrering, wat standaard geaktiveer is op alle inter-woudvertroue. Dit is gebaseer op die aanname dat intra-woudvertroue veilig is, met die woud, eerder as die domein, as die sekuriteitsgrens volgens Microsoft se standpunt.
* Daar is egter 'n vangnet: SID filtrering kan toepassings en gebruikers toegang ontwrig, wat lei tot die af en toe deaktivering daarvan.

### **Selektiewe Verifikasie:**

* Vir inter-woudvertroue, verseker die gebruik van Selektiewe Verifikasie dat gebruikers van die twee woude nie outomaties geverifieer word nie. In plaas daarvan is eksplisiete toestemmings nodig vir gebruikers om toegang te verkry tot domeine en bedieners binne die vertrouende domein of woud.
* Dit is belangrik om te noem dat hierdie maatreëls nie beskerm teen die uitbuiting van die skryfbare Konfigurasie Naam Konteks (NC) of aanvalle op die vertrouingsrekening nie.

[**Meer inligting oor domeinvertroue in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Sommige Algemene Verdedigings

[**Leer meer oor hoe om kredensiale te beskerm hier.**](../stealing-credentials/credentials-protections.md)\\

### **Defensiewe Maatreëls vir Kredensiaalbeskerming**

* **Domein Administrateurs Beperkings**: Dit word aanbeveel dat Domein Administrateurs slegs toegelaat word om in te log op Domein Beheerders, en dat hulle nie op ander gasheer gebruik word nie.
* **Diensrekening Privileges**: Dienste moet nie met Domein Administrateur (DA) privileges gedra word om sekuriteit te handhaaf nie.
* **Tydelike Privilege Beperking**: Vir take wat DA privileges vereis, moet die duur daarvan beperk word. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementering van Misleidingstegnieke**

* Die implementering van misleiding behels die opstelling van lokvalle, soos lokgebruikers of rekenaars, met kenmerke soos wagwoorde wat nie verval nie of as Vertrou vir Delegasie gemerk is. 'n Gedetailleerde benadering sluit die skep van gebruikers met spesifieke regte of die toevoeging daarvan aan hoëprivilege groepe in.
* 'n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Meer oor die implementering van misleidingstegnieke kan gevind word by [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van Misleiding**

* **Vir Gebruikerobjekte**: Verdagte aanduiders sluit ongewone ObjectSID, ongewone aanmeldings, skeppingsdatums, en lae slegte wagwoord tellings in.
* **Algemene Aanduiders**: Die vergelyking van eienskappe van potensiële lokobjekte met dié van werklike kan inkonsekwenthede onthul. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleidings te identifiseer.

### **Om Ontdekkingsisteme te Omseil**

* **Microsoft ATA Ontdekking Omseiling**:
* **Gebruiker Enumerasie**: Vermy sessie-evaluering op Domein Beheerders om ATA ontdekking te voorkom.
* **Tiket Impersonasie**: Die gebruik van **aes** sleutels vir tiket skepping help om ontdekking te ontduik deur nie na NTLM af te gradeer nie.
* **DCSync Aanvalle**: Dit word aanbeveel om van 'n nie-Domein Beheerder uit te voer om ATA ontdekking te vermy, aangesien direkte uitvoering vanaf 'n Domein Beheerder waarskuwings sal aktiveer.

## Verwysings

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

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
