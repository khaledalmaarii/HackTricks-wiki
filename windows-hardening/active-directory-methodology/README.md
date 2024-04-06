# Active Directory Methodology

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese oorsig

**Aktiewe Gids** dien as 'n fundamentele tegnologie wat **netwerkadministrateurs** in staat stel om doeltreffend **domeine**, **gebruikers** en **voorwerpe** binne 'n netwerk te skep en te bestuur. Dit is ontwerp om te skaal, wat die organisering van 'n groot aantal gebruikers in bestuurbare **groepe** en **subgroepe** fasiliteer, terwyl **toegangsregte** op verskillende vlakke beheer word.

Die struktuur van **Aktiewe Gids** bestaan uit drie primêre lae: **domeine**, **bome** en **woude**. 'n **Domein** omvat 'n versameling voorwerpe, soos **gebruikers** of **toestelle**, wat 'n gemeenskaplike databasis deel. **Bome** is groepe van hierdie domeine wat deur 'n gemeenskaplike struktuur gekoppel is, en 'n **woud** verteenwoordig die versameling van verskeie bome wat deur **vertrouensverhoudings** met mekaar verbind is en die boonste laag van die organisatoriese struktuur vorm. Spesifieke **toegangs-** en **kommunikasieregte** kan op elkeen van hierdie vlakke aangewys word.

Kernkonsepte binne **Aktiewe Gids** sluit in:

1. **Gids** - Bevat alle inligting met betrekking tot Aktiewe Gids-voorwerpe.
2. **Voorwerp** - Dui entiteite binne die gids aan, insluitend **gebruikers**, **groepe** of **gedeelde lêers**.
3. **Domein** - Diens as 'n houer vir gidsvoorwerpe, met die vermoë vir meerdere domeine om binne 'n **woud** te bestaan, elk met sy eie voorwerpsversameling.
4. **Boom** - 'n Groepering van domeine wat 'n gemeenskaplike worteldomein deel.
5. **Woud** - Die hoogste vlak van die organisatoriese struktuur in Aktiewe Gids, bestaande uit verskeie bome met **vertrouensverhoudings** tussen hulle.

**Aktiewe Gids-domeindienste (AD DS)** omvat 'n verskeidenheid dienste wat krities is vir die gesentraliseerde bestuur en kommunikasie binne 'n netwerk. Hierdie dienste sluit in:

1. **Domeindienste** - Sentraliseer data-opberging en bestuur interaksies tussen **gebruikers** en **domeine**, insluitend **outentisering** en **soekfunksies**.
2. **Sertifikaatdienste** - Hou toesig oor die skepping, verspreiding en bestuur van veilige **digitale sertifikate**.
3. **Ligtegewig Gidsdienste** - Ondersteun gidsgeaktiveerde toepassings deur middel van die **LDAP-protokol**.
4. **Gidsfederasiedienste** - Verskaf **enkel-aanmelding**-vermoëns om gebruikers oor verskeie webtoepassings in 'n enkele sessie te outentiseer.
5. **Regtebestuur** - Help om kopieregsmateriaal te beskerm deur die ongemagtigde verspreiding en gebruik daarvan te reguleer.
6. **DNS-diens** - Krities vir die oplossing van **domeinname**.

Vir 'n meer gedetailleerde verduideliking, kyk na: [**TechTerms - Aktiewe Gids-definisie**](https://techterms.com/definition/active\_directory)

### **Kerberos-outentisering**

Om te leer hoe om 'n AD aan te val, moet jy die **Kerberos-outentiseringsproses** baie goed verstaan.\
[**Lees hierdie bladsy as jy nog nie weet hoe dit werk nie.**](kerberos-authentication.md)

## Spiekbriefie

Jy kan na [https://wadcoms.github.io/](https://wadcoms.github.io) gaan om 'n vinnige oorsig te kry van watter opdragte jy kan uitvoer om 'n AD te ondersoek/uit te buit.

## Ondersoek Aktiewe Gids (Geen geloofsbriewe/sessies)

As jy net toegang het tot 'n AD-omgewing, maar jy het geen geloofsbriewe/sessies nie, kan jy:

* **Pentest die netwerk:**
* Skandeer die netwerk, vind masjiene en oop poorte en probeer **kwesbaarhede uitbuit** of **geloofsbriewe** daaruit onttrek (byvoorbeeld, [drukkers kan baie interessante teikens wees](ad-information-in-printers.md).
* Die opnoem van DNS kan inligting gee oor sleutelbedieners in die domein soos web, drukkers, aandele, vpn, media, ens.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Kyk na die algemene [**Pentest-metodologie**](../../generic-methodologies-and-resources/pentesting-methodology.md) om meer inligting te vind oor hoe om dit te doen.
* **Kyk vir nul- en Gaste-toegang op smb-dienste** (dit sal nie werk op moderne Windows-weergawes nie):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* 'n Meer gedetailleerde gids oor hoe om 'n SMB-bediener op te noem, kan hier gevind word:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Noem Ldap op**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* 'n Meer gedetailleerde gids oor hoe om LDAP op te noem, kan hier gevind word (gee **spesiale aandag aan die anonieme toegang**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Vergiftig die netwerk**
* Versamel geloofsbriewe deur \[**dienste te verpersoonlik met Responder**]\(../../generic-methodologies-and-resources/pentesting-network/spoofing

### Gebruikersopsporing

* **Anonieme SMB/LDAP-opsporing:** Kyk na die [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) en [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) bladsye.
* **Kerbrute-opsporing**: Wanneer 'n **ongeldige gebruikersnaam aangevra** word, sal die bediener reageer met die **Kerberos-foutkode** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, wat ons in staat stel om vas te stel dat die gebruikersnaam ongeldig was. **Geldige gebruikersname** sal óf die **TGT in 'n AS-REP**-reaksie veroorsaak, óf die fout _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_ aandui, wat aandui dat die gebruiker verplig is om vooraf-verifikasie uit te voer.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```

* **OWA (Outlook Web Access) Bediener**

As jy een van hierdie bedieners in die netwerk gevind het, kan jy ook **gebruikersopname teen dit uitvoer**. Byvoorbeeld, jy kan die instrument [**MailSniper**](https://github.com/dafthack/MailSniper) gebruik:

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
Jy kan lys van gebruikersname vind in [**hierdie github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* en hierdie een ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Maar jy moet die **name van die mense wat by die maatskappy werk** hê van die rekogniseringstap wat jy voorheen moes uitvoer. Met die naam en van kan jy die skrip [**namemash.py**](https://gist.github.com/superkojiman/11076951) gebruik om potensiële geldige gebruikersname te genereer.
{% endhint %}

### Om een of verskeie gebruikersname te ken

Ok, so jy weet jy het reeds 'n geldige gebruikersnaam maar geen wagwoorde nie... Probeer dan:

* [**ASREPRoast**](asreproast.md): As 'n gebruiker **nie** die eienskap _DONT\_REQ\_PREAUTH_ het nie, kan jy 'n AS\_REP-boodskap vir daardie gebruiker aanvra wat sommige data sal bevat wat deur 'n afleiding van die gebruiker se wagwoord versleutel is.
* [**Password Spraying**](password-spraying.md): Laat ons die mees **algemene wagwoorde** probeer met elkeen van die ontdekte gebruikers, miskien gebruik 'n gebruiker 'n swak wagwoord (hou die wagwoordbeleid in gedagte!).
* Let daarop dat jy ook **OWA-bedieners kan bespuit** om toegang tot die gebruikers se posbedieners te kry.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Vergiftiging

Jy kan dalk **uitdagingshasings** verkry om te kraak deur sommige protokolle van die **netwerk te vergiftig**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

As jy daarin geslaag het om die aktiewe gids op te som, sal jy **meer e-posse en 'n beter begrip van die netwerk** hê. Jy kan dalk NTML [**relay-aanvalle**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* afdwing om toegang tot die AD-omgewing te kry.

### Steel NTML-legitimasie

As jy toegang het tot ander rekenaars of gedeeltes met die **null- of gasgebruiker**, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, as dit op een of ander manier geopen word, 'n NTML-legitimasie teen jou sal **ontlok** sodat jy die NTML-uitdaging kan steel om dit te kraak:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Opnoem van aktiewe gids MET legitimasie/sessie

Vir hierdie fase moet jy **die legitimasie of 'n sessie van 'n geldige domeinrekening gekompromitteer het.** As jy geldige legitimasie het of 'n skulp as 'n domein-gebruiker het, **moet jy onthou dat die opsies wat voorheen gegee is, steeds opsies is om ander gebruikers te kompromitteer**.

Voordat jy die geauthentiseerde opnoeming begin, moet jy weet wat die **Kerberos-dubbelhop-probleem** is.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Opnoeming

Om 'n rekening gekompromitteer te hê, is 'n **groot stap om die hele domein te kompromitteer**, omdat jy in staat sal wees om die **Aktiewe Gids Opnoeming te begin**:

Met betrekking tot [**ASREPRoast**](asreproast.md) kan jy nou elke moontlike kwesbare gebruiker vind, en met betrekking tot [**Password Spraying**](password-spraying.md) kan jy 'n **lys van alle gebruikersname** kry en die wagwoord van die gekompromitteerde rekening, leë wagwoorde en nuwe belowende wagwoorde probeer.

* Jy kan die [**CMD gebruik om 'n basiese rekognisering uit te voer**](../basic-cmd-for-pentesters.md#domain-info)
* Jy kan ook [**powershell vir rekognisering**](../basic-powershell-for-pentesters/) gebruik wat meer onsigbaar sal wees
* Jy kan ook [**powerview gebruik**](../basic-powershell-for-pentesters/powerview.md) om meer gedetailleerde inligting te onttrek
* 'n Ander fantastiese hulpmiddel vir rekognisering in 'n aktiewe gids is [**BloodHound**](bloodhound.md). Dit is **nie baie onsigbaar nie** (afhangende van die versamelingsmetodes wat jy gebruik nie), maar **as jy nie omgee nie** kan jy dit beslis probeer. Vind waar gebruikers RDP kan gebruik, vind pad na ander groepe, ens.
* **Ander outomatiese AD-opnoemingshulpmiddels is:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**DNS-rekords van die AD**](ad-dns-records.md) omdat dit dalk interessante inligting bevat.
* 'n **Hulpmiddel met 'n GUI** wat jy kan gebruik om die gids op te noem, is **AdExplorer.exe** van die **SysInternal**-pakket.
* Jy kan ook in die LDAP-databasis soek met **ldapsearch** om na legitimasie in die veld _userPassword_ & _unixUserPassword_ te soek, of selfs vir _Beskrywing_. sien [Wagwoord in AD-gebruikersopmerking op PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) vir ander metodes.
* As jy **Linux** gebruik, kan jy ook die domein opnoem deur [**pywerview**](https://github.com/the-useless-one/pywerview) te gebruik.
* Jy kan ook outomatiese hulpmiddels probeer soos:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
* **Opnoem van alle domeingebruikers**

Dit is baie maklik om al die domeingebruikersname van Windows te verkry (`net user /domain`, `Get-DomainUser` of `wmic useraccount get name,sid`). In Linux kan jy gebruik: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` of `enum4linux -a -u "user" -p "password" <DC IP>`

> Al lyk hierdie Opnoemingsgedeelte klein, dit is die belangrikste deel van alles. Besoek die skakels (veral die een van cmd, powershell, powerview en BloodHound), leer hoe om 'n domein op te noem en oefen totdat jy gemaklik voel. Gedurende 'n assessering sal dit die sleutelmoment wees om jou pad na DA te vind of om te besluit dat niks gedoen kan word nie.

### Kerberoast

Kerberoasting behels die verkryging van **TGS-kaartjies** wat deur dienste wat aan gebruikersrekeninge gekoppel is, gebruik word en die kodering daarvan—wat gebaseer is op gebruikerswagwoorde—**offline** kraak.

Meer hieroor in:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Verrekenaar verbinding (RDP, SSH, FTP, Win-RM, ens.)

Sodra jy sekere geloofsbriewe verkry het, kan jy nagaan of jy toegang het tot enige **rekenaar**. Hiervoor kan jy **CrackMapExec** gebruik om te probeer om op verskeie bedieners aan te sluit met verskillende protokolle, volgens jou poortskandering.

### Plaaslike bevoorregte verhoging

As jy gekompromitteerde geloofsbriewe het of 'n sessie as 'n gewone domein-gebruiker het en jy het **toegang** met hierdie gebruiker tot **enige rekenaar in die domein**, moet jy probeer om jou pad te vind om **plaaslike bevoorregte verhoging te bewerkstellig en geloofsbriewe te buit**. Dit is omdat jy slegs met plaaslike administrateurbevoegdhede in staat sal wees om hasings van ander gebruikers in die geheue (LSASS) en plaaslik (SAM) te **dump**.

Daar is 'n volledige bladsy in hierdie boek oor [**plaaslike bevoorregte verhoging in Windows**](../windows-local-privilege-escalation/) en 'n [**kontrolelys**](../checklist-windows-privilege-escalation.md). Moenie ook vergeet om [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) te gebruik nie.

### Huidige sessiekaartjies

Dit is baie **onwaarskynlik** dat jy **kaartjies** sal vind in die huidige gebruiker wat jou toestemming gee om toegang te verkry tot onverwagte hulpbronne, maar jy kan dit nagaan:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTML Relay

As jy daarin geslaag het om die aktiewe gids op te som, sal jy **meer e-posse en 'n beter begrip van die netwerk hê**. Jy mag dalk in staat wees om NTML [**relay-aanvalle**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)\*\* te dwing\*\*.

### **Soek na geloofsbriewe in rekenaaraandele**

Nou dat jy 'n paar basiese geloofsbriewe het, moet jy kyk of jy enige interessante lêers kan **vind wat binne die AD gedeel word**. Jy kan dit handmatig doen, maar dit is 'n baie vervelige herhalende taak (en nog meer as jy honderde dokumente moet nagaan).

[**Volg hierdie skakel om uit te vind oor gereedskap wat jy kan gebruik.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Steel NTLM-geloofsbriewe

As jy **toegang tot ander rekenaars of aandele** het, kan jy **lêers plaas** (soos 'n SCF-lêer) wat, as dit op een of ander manier geopen word, 'n **NTML-verifikasie teen jou sal aktiveer**, sodat jy die **NTLM-uitdaging** kan steel om dit te kraak:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Hierdie kwesbaarheid het enige geautehtiseerde gebruiker in staat gestel om die domeinbeheerder te **kompromitteer**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Voorregverhoging op Aktiewe Gids MET voorregte geloofsbriewe/sessie

**Vir die volgende tegnieke is 'n gewone domeingebruiker nie genoeg nie, jy het spesiale voorregte/geloofsbriewe nodig om hierdie aanvalle uit te voer.**

### Hash-onttrekking

Hopelik het jy daarin geslaag om 'n plaaslike administrateur-rekening te **kompromitteer** deur gebruik te maak van [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) insluitend relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [voorregte plaaslik verhoog](../windows-local-privilege-escalation/).\
Dan is dit tyd om al die hasings in die geheue en plaaslik te dump.\
[**Lees hierdie bladsy oor verskillende maniere om die hasings te verkry.**](https://github.com/carlospolop/hacktricks/blob/af/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass die Hash

**Sodra jy die has van 'n gebruiker het**, kan jy dit gebruik om hom te **impersoneer**.\
Jy moet 'n **hulpmiddel** gebruik wat die **NTLM-verifikasie met** daardie **hash sal uitvoer**, **of** jy kan 'n nuwe **sessieaanmelding** skep en daardie **hash** binne die **LSASS** inspuit, sodat wanneer enige **NTLM-verifikasie uitgevoer word**, daardie **hash gebruik sal word**. Die laaste opsie is wat mimikatz doen.\
[**Lees hierdie bladsy vir meer inligting.**](../ntlm/#pass-the-hash)

### Over Pass die Hash/Pass die Sleutel

Hierdie aanval het ten doel om die gebruiker se NTLM-hash te gebruik om Kerberos-kaartjies aan te vra, as 'n alternatief vir die gewone Pass The Hash oor NTLM-protokol. Dit kan dus veral **nuttig wees in netwerke waar die NTLM-protokol gedeaktiveer is** en slegs Kerberos as verifikasieprotokol toegelaat word.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass die Kaartjie

In die **Pass The Ticket (PTT)**-aanvalsmetode steel aanvallers 'n gebruiker se verifikasiekaartjie in plaas van hul wagwoord of haswaardes. Hierdie gesteelde kaartjie word dan gebruik om die gebruiker te **impersoneer** en ongemagtigde toegang tot hulpbronne en dienste binne 'n netwerk te verkry.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Geloofsbriewe Hergebruik

As jy die **hash** of **wagwoord** van 'n **plaaslike administrateur** het, moet jy probeer om daarmee **plaaslik aan te meld** by ander **rekenaars**.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

{% hint style="warning" %}
Let daarop dat dit nogal **lawaaierig** is en dat **LAPS** dit sal **verlig**.
{% endhint %}

### MSSQL Misbruik & Vertroue Skakels

As 'n gebruiker die voorregte het om **toegang te verkry tot MSSQL-instanties**, kan hy dit gebruik om opdragte uit te voer in die MSSQL-gashuis (as dit as SA uitgevoer word), die NetNTLM **hash** te **steel** of selfs 'n **relay-aanval** uit te voer.\
As 'n MSSQL-instantie vertrou (databasis skakel) word deur 'n ander MSSQL-instantie. As die gebruiker voorregte het oor die vertroue databasis, sal hy in staat wees om die vertrouensverhouding te gebruik om ook navrae in die ander instantie uit te voer. Hierdie vertrouens kan geketting word en op 'n punt mag die gebruiker 'n verkeerd gekonfigureerde databasis vind waar hy opdragte kan uitvoer.\
**Die skakels tussen databasisse werk selfs oor bosvertrouens.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Onbeperkte Delegasie

As jy enige Rekenaarvoorwerp vind met die eienskap [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) en jy het domeinvoorregte op die rekenaar, sal jy in staat wees om TGT's uit die geheue van elke gebruiker wat op die rekenaar inteken, te dump.\
Dus, as 'n **Domein Admin inteken op die rekenaar**, sal jy sy TGT kan dump en hom kan voorstel deur [Pass the Ticket](pass-the-ticket.md) te gebruik.\
Dankie aan beperkte delegasie kan jy selfs **outomaties 'n Drukbediener kompromitteer** (hopelik sal dit 'n DC wees).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Beperkte Delegasie

As 'n gebruiker of rekenaar toegelaat word vir "Beperkte Delegasie", sal hy in staat wees om **enige gebruiker te voorstel om toegang te verkry tot sekere dienste op 'n rekenaar**.\
Dan, as jy die **hash kompromitteer** van hierdie gebruiker/rekenaar, sal jy in staat wees om **enige gebruiker** (selfs domeinadministrateurs) voor te stel om toegang te verkry tot sekere dienste.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Hulpbron-gebaseerde Beperkte Delegasie

Deur **SKRYF-voorreg** op 'n Active Directory-voorwerp van 'n afgeleë rekenaar te hê, kan jy kode-uitvoering met **verhoogde voorregte** verkry:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### ACL-misbruik

Die gekompromitteerde gebruiker kan sekere **interessante voorregte oor sommige domeinvoorwerpe** hê wat jou in staat kan stel om **sydelings te beweeg**/**voorregte te verhoog**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Drukker Spooler-diensmisbruik

Die ontdekking van 'n **Spool-diens wat luister** binne die domein kan misbruik word om nuwe legitimasie te verkry en voorregte te verhoog.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Misbruik van derde party sessies

As **ander gebruikers** die **gekompromitteerde** masjien **toegang** verkry, is dit moontlik om legitimasie uit die geheue te versamel en selfs **beacons in hul prosesse in te spuit** om hulle voor te stel.\
Gewoonlik sal gebruikers toegang tot die stelsel verkry via RDP, so hier is hoe om 'n paar aanvalle uit te voer oor derde party RDP-sessies:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** bied 'n stelsel vir die bestuur van die **plaaslike Administrateur wagwoord** op domein-gekoppelde rekenaars, wat verseker dat dit **willekeurig**, uniek en gereeld **verander** word. Hierdie wagwoorde word in Active Directory gestoor en toegang word beheer deur ACL's slegs aan gemagtigde gebruikers. Met voldoende toestemmings om hierdie wagwoorde te verkry, word dit moontlik om na ander rekenaars te draai.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Sertifikaatdiefstal

**Die versameling van sertifikate** van die gekompromitteerde masjien kan 'n manier wees om voorregte binne die omgewing te verhoog:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Misbruik van Sertifikaatsjablone

As **kwesbare sjablone** gekonfigureer is, is dit moontlik om dit te misbruik om voorregte te verhoog:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-exploitasie met 'n rekening met hoë voorregte

### Dumping van Domeinlegitimasie

Sodra jy **Domein Admin** of selfs beter **Enterprise Admin** voorregte verkry, kan jy die **domein-databasis** dump: _ntds.dit_.

[**Meer inligting oor DCSync-aanval kan hier gevind word**](dcsync.md).

[**Meer inligting oor hoe om die NTDS.dit te steel, kan hier gevind word**](https://github.com/carlospolop/hacktricks/blob/af/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Volharding

Sommige van die tegnieke wat voorheen bespreek is, kan gebruik word vir volharding.\
Byvoorbeeld kan jy:

* Gebruikers kwesbaar maak vir [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <gebruikersnaam> -Set @{serviceprincipalname="fake/NOTHING"}r
```

* Gebruikers kwesbaar maak vir [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <gebruikersnaam> -XOR @{UserAccountControl=4194304}
```

* [**DCSync**](./#dcsync) voorregte aan 'n gebruiker verleen

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silwernommer

Die **Silwernommer-aanval** skep 'n **wettige Ticket Granting Service (TGS)-kaartjie** vir 'n spesifieke diens deur die gebruik van die **NTLM-hash** (byvoorbeeld die **hash van die rekenaarrekening**). Hierdie metode word gebruik om toegang tot die diensvoorregte te verkry.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Goue Kaartjie

'n **Goue Kaartjie-aanval** behels dat 'n aanvaller toegang verkry tot die **NTLM-hash van die krbtgt-rekening** in 'n Active Directory (AD)-omgewing. Hierdie rekening is spesiaal omdat dit gebruik word om alle **Ticket Granting Tickets (TGT's)** te onderteken, wat noodsaaklik is vir die outentisering binne die AD-netwerk.

Sodra die aanvaller hierdie hash verkry, kan hulle TGT's vir enige rekening skep wat hulle kies (Silwernommer-aanval).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamantkaartjie

Hierdie is soos goue kaartjies wat op 'n manier vervals is wat **gewone goue kaartjie-opsporingsmeganismes omseil**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Sertifikaatrekening Volharding**

**Die besit van sertifikate van 'n rekening of die vermoë om dit aan te vra**, is

### **Sertifikaat Domein Volharding**

**Dit is ook moontlik om met sertifikate volharding met hoë voorregte binne die domein te handhaaf:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### AdminSDHolder Groep

Die **AdminSDHolder**-voorwerp in Active Directory verseker die veiligheid van **bevoorregte groepe** (soos Domein Admins en Onderneming Admins) deur 'n standaard **Toegangbeheerlys (ACL)** oor hierdie groepe toe te pas om ongemagtigde veranderinge te voorkom. Hierdie funksie kan egter uitgebuit word; as 'n aanvaller die ACL van AdminSDHolder wysig om volle toegang aan 'n gewone gebruiker te gee, verkry daardie gebruiker uitgebreide beheer oor alle bevoorregte groepe. Hierdie veiligheidsmaatreël, bedoel om te beskerm, kan dus terugskiet en ongemagtigde toegang toelaat tensy dit noukeurig gemonitor word.

[**Meer inligting oor die AdminSDHolder Groep hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Legitimasie

Binne elke **Domeinbeheerder (DC)** bestaan 'n **plaaslike administrateur**-rekening. Deur administratiewe regte op so 'n masjien te verkry, kan die plaaslike Administrateur-hash onttrek word deur **mimikatz** te gebruik. Hierna is 'n registerwyziging nodig om die gebruik van hierdie wagwoord te aktiveer, wat afstandsbeheer van die plaaslike Administrateur-rekening moontlik maak.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### ACL Volharding

Jy kan 'n **gebruiker** sekere **spesiale toestemmings** gee oor sekere spesifieke domeinvoorwerpe wat die gebruiker in die toekoms in staat stel om voorregte te verhoog.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Sekuriteitsbeskrywers

Die **sekuriteitsbeskrywers** word gebruik om die **toestemmings** wat 'n **voorwerp** oor 'n **voorwerp** het, te **stoor**. As jy net 'n **klein verandering** in die **sekuriteitsbeskrywer** van 'n voorwerp kan maak, kan jy baie interessante voorregte oor daardie voorwerp verkry sonder om lid van 'n bevoorregte groep te wees.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skelet Sleutel

Verander **LSASS** in die geheue om 'n **universele wagwoord** te vestig wat toegang tot alle domeinrekeninge verleen.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Aangepaste SSP

[Leer wat 'n SSP (Sekuriteitsondersteuningsverskaffer) is hier.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Jy kan jou **eie SSP** skep om die **legitimasiebesonderhede** wat gebruik word om toegang tot die masjien te verkry, in **duidelike teks** vas te lê.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Dit registreer 'n **nuwe Domeinbeheerder** in die AD en gebruik dit om eienskappe (SIDHistory, SPNs...) op gespesifiseerde voorwerpe te **stuur** sonder om enige **logboeke** oor die **veranderings** agter te laat. Jy **benodig DA-voorregte** en moet binne die **worteldomein** wees.\
Let daarop dat as jy verkeerde data gebruik, sal lelike logboeke verskyn.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### LAPS Volharding

Vroeër het ons bespreek hoe om voorregte te verhoog as jy **genoeg toestemming het om LAPS-wagwoorde te lees**. Hierdie wagwoorde kan egter ook gebruik word om **volharding te handhaaf**.\
Kyk:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Bos Voorregverhoging - Domeinvertroue

Microsoft beskou die **Bos** as die veiligheidsgrens. Dit beteken dat **die kompromittering van 'n enkele domein potensieel kan lei tot die kompromittering van die hele Bos**.

### Basiese Inligting

'n [**Domeinvertroue**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) is 'n sekuriteitsmeganisme wat 'n gebruiker van die een **domein** in staat stel om hulpbronne in 'n ander **domein** te benader. Dit skep in wese 'n skakeling tussen die outentiseringsstelsels van die twee domeine, wat toelaat dat outentiseringsverifikasies vlot vloei. Wanneer domeine 'n vertroue opstel, ruil en behou hulle spesifieke **sleutels** binne hul **Domeinbeheerders (DC's)**, wat van kritieke belang is vir die integriteit van die vertroue.

In 'n tipiese scenario, as 'n gebruiker toegang tot 'n diens in 'n **vertroue domein** wil verkry, moet hulle eers 'n spesiale kaartjie, bekend as 'n **inter-realm TGT**, van hul eie domein se DC aanvra met behulp van hul **NTLM-hash**. Hierdie TGT word versleutel met 'n gedeelde **sleutel** waaroor beide domeine saamgestem het. Die gebruiker bied dan hierdie TGT aan die **DC van die vertroue domein** aan om 'n dienskaartjie (**TGS**) te verkry. Nadat die inter-realm TGT suksesvol deur die DC van die vertroue domein geverifieer is, gee dit 'n TGS uit wat die gebruiker toegang tot die diens verleen.

**Stappe**:

1. 'n **Kliëntrekenaar** in **Domein 1** begin die proses deur sy **NTLM-hash** te gebruik om 'n **Ticket Granting Ticket (TGT)** van sy **Domeinbeheerder (DC1)** aan te vra.
2. DC1 gee 'n nuwe TGT uit as die kliënt suksesvol geoutentiseer is.
3. Die kliënt vra dan 'n **inter-realm TGT** van DC1 aan, wat nodig is om hulpbronne in **Domein 2** te benader.
4. Die inter-realm TGT word versleutel met 'n **vertrouingssleutel** wat gedeel word tussen DC1 en DC2 as deel van die tweerigting domeinvertroue.
5. Die kliënt neem die inter-realm TGT na **Domein 2 se Domeinbeheerder (DC2)**.
6. DC2 verifieer die inter-realm TGT met behulp van sy gedeelde vertrouingssleutel en, indien geldig, gee dit 'n **Ticket Granting Service (TGS)** vir die bediener in Domein 2 wat die kliënt wil benader.
7. Uiteindelik bied die kliënt hierdie TGS aan die bediener aan, wat versleutel is met die rekeninghash van die bediener, om toegang tot die diens in Domein 2 te verkry.

### Verskillende vertroues

Dit is belangrik om op te let dat **'n vertroue eenrigting of tweerigting kan wees**. In die tweerigting opsies sal beide domeine mekaar vertrou, maar in die \*\*eenrigting vertroue verhouding sal een van die domeine die vertroue en die ander die vertrouende domein we

#### Ander verskille in **vertrouensverhoudings**

* 'n Vertrouensverhouding kan ook **transitief** wees (A vertrou B, B vertrou C, dan vertrou A C) of **nie-transitief**.
* 'n Vertrouensverhouding kan opgestel word as **bidireksionele vertroue** (beide vertrou mekaar) of as **eenrigting vertroue** (slegs een van hulle vertrou die ander).

### Aanvalspad

1. **Enumerate** die vertrouensverhoudings
2. Kyk of enige **sekuriteitsprinsipe** (gebruiker/groep/rekenaar) toegang het tot hulpbronne van die **ander domein**, dalk deur ACE-inskrywings of deur in groepe van die ander domein te wees. Soek na **verhoudings tussen domeine** (die vertroue is waarskynlik hiervoor geskep).
3. Kerberoast in hierdie geval kan 'n ander opsie wees.
4. **Kompromitteer** die **rekeninge** wat deur domeine kan **pivot**.

Aanvallers met toegang tot hulpbronne in 'n ander domein kan dit doen deur drie primêre meganismes:

* **Plaaslike Groepslidmaatskap**: Prinsipale kan bygevoeg word by plaaslike groepe op rekenaars, soos die "Administrators" groep op 'n bediener, wat hulle aansienlike beheer oor daardie rekenaar gee.
* **Vreemde Domein Groepslidmaatskap**: Prinsipale kan ook lede wees van groepe binne die vreemde domein. Die doeltreffendheid van hierdie metode hang egter af van die aard van die vertroue en die omvang van die groep.
* **Toegangbeheerlyste (ACL's)**: Prinsipale kan gespesifiseer word in 'n **ACL**, veral as entiteite in **ACE's** binne 'n **DACL**, wat hulle toegang tot spesifieke hulpbronne bied. Vir diegene wat die meganika van ACL's, DACL's en ACE's dieper wil verken, is die witpapier getiteld "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)" 'n onskatbare bron.

### Kind-tot-ouer bos voorregverhoging

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
Daar is **2 vertroue sleutels**, een vir _Kind --> Ouers_ en nog een vir _Ouers_ --> _Kind_.\
Jy kan die een wat deur die huidige domein gebruik word, kry met:

```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### SID-History-injeksie

Skalering as Enterprise-admin na die kind/ouer domein deur die vertroue met SID-History-injeksie te misbruik:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Uitbuiting van skryfbare Konfigurasie NC

Dit is noodsaaklik om te verstaan hoe die Konfigurasie-naamkonteks (NC) uitgebuit kan word. Die Konfigurasie NC dien as 'n sentrale bewaarplek vir konfigurasiedata regoor 'n bos in Active Directory (AD)-omgewings. Hierdie data word gerepliseer na elke Domeinbeheerder (DC) binne die bos, met skryfbare DC's wat 'n skryfbare kopie van die Konfigurasie NC onderhou. Om hiervan gebruik te maak, moet 'n persoon **STELSEL-voorregte op 'n DC** hê, verkieslik 'n kind-DC.

**Skakel GPO aan die wortel-DC-webwerf**

Die Konfigurasie NC se "Sites"-houer bevat inligting oor al die rekenaars wat by die AD-bos aangesluit is binne die domein. Deur te werk met STELSEL-voorregte op enige DC, kan aanvallers GPO's aan die wortel-DC-webwerwe koppel. Hierdie aksie stel die worteldomein potensieel bloot deur beleid wat op hierdie webwerwe toegepas word, te manipuleer.

Vir in-diepte inligting kan navorsing oor [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) ondersoek word.

**Kompromitteer enige gMSA in die bos**

'n Aanvalvektor behels die teiken van bevoorregte gMSA's binne die domein. Die KDS Root-sleutel, wat noodsaaklik is vir die berekening van gMSA-wagwoorde, word binne die Konfigurasie NC gestoor. Met STELSEL-voorregte op enige DC is dit moontlik om toegang tot die KDS Root-sleutel te verkry en die wagwoorde vir enige gMSA regoor die bos te bereken.

Gedetailleerde analise kan gevind word in die bespreking oor [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema-veranderingsaanval**

Hierdie metode vereis geduld, waar jy moet wag vir die skepping van nuwe bevoorregte AD-voorwerpe. Met STELSEL-voorregte kan 'n aanvaller die AD-skema wysig om enige gebruiker volledige beheer oor alle klasse te gee. Dit kan lei tot ongemagtigde toegang en beheer oor nuutgeskepte AD-voorwerpe.

Verdere leesstof is beskikbaar oor [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Van DA tot EA met ADCS ESC5**

Die ADCS ESC5-kwesbaarheid teiken beheer oor Openbare Sleutelinfrastruktuur (PKI)-voorwerpe om 'n sertifikaatsjabloon te skep wat outentisering as enige gebruiker binne die bos moontlik maak. Aangesien PKI-voorwerpe in die Konfigurasie NC bly, maak die kompromittering van 'n skryfbare kind-DC die uitvoering van ESC5-aanvalle moontlik.

Meer besonderhede hieroor kan gelees word in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenario's waar ADCS ontbreek, het die aanvaller die vermoë om die nodige komponente op te stel, soos bespreek in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Eksterne Bosdomein - Eenrigting (Inkomend) of tweerigting

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

In hierdie scenario word **jou domein vertrou** deur 'n eksterne domein wat jou **onbepaalde toestemmings** daaroor gee. Jy sal moet vasstel **watter beginsels van jou domein watter toegang oor die eksterne domein het** en dan probeer om dit uit te buit:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Eksterne Bosdomein - Eenrigting (Uitgaande)

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

In hierdie scenario **vertrou** **jou domein** sekere **bevoegdhede** toe aan 'n **beginsel van 'n ander domein**.

Wanneer 'n **domein vertrou** word deur die vertrouende domein, skep die vertroude domein 'n gebruiker met 'n **voorspelbare naam** wat die vertroude wagwoord gebruik. Dit beteken dat dit moontlik is om **toegang te verkry tot 'n gebruiker van die vertrouende domein om binne te kom in die vertroude domein** om dit te ondersoek en te probeer om meer bevoegdhede te verkry:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

'n Ander manier om die vertroude domein te kompromitteer, is om 'n [**SQL vertroude skakel**](abusing-ad-mssql.md#mssql-trusted-links) te vind wat in die **teenoorgestelde rigting** van die domeinvertroue geskep is (wat nie baie algemeen is nie).

'n Ander manier om die vertroude domein te kompromitteer, is om te wag in 'n masjien waar 'n **gebruiker van die vertroude domein toegang kan verkry** om in te teken via **RDP**. Die aanvaller kan dan kode inspuit in die RDP-sessieproses en van daar af **toegang verkry tot die oorspronklike domein van die slagoffer**.\
Verder, as die **slagoffer sy hardeskyf gemonteer het**, kan die aanvaller vanuit die **RDP-sessieproses** **agterdeure** in die **opstartmap van die hardeskyf** stoor. Hierdie tegniek word **RDPInception** genoem.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Beperking van misbruik van domeinvertroue

### **SID-filtering:**

* Die risiko van aanvalle wat gebruik maak van die SID-geskiedenis atribuut oor bosvertroue word beperk deur SID-filtering, wat standaard geaktiveer is op alle inter-bosvertroue. Dit berus op die aanname dat intra-bosvertroue veilig is, waar die bos eerder as die domein as die veiligheidsgrens beskou word volgens Microsoft se standpunt.
* Daar is egter 'n vang: SID-filtering kan programme en gebruikerstoegang ontwrig, wat soms lei tot die deaktivering daarvan.

### **Selektiewe outentifikasie:**

* Vir inter-bosvertroue verseker selektiewe outentifikasie dat gebruikers van die twee bome nie outomaties geoutentifiseer word nie. In plaas daarvan is eksplisiete toestemmings nodig vir gebruikers om toegang te verkry tot domeine en bedieners binne die vertrouende domein of bos.
* Dit is belangrik om daarop te let dat hierdie maatreëls nie beskerm teen die uitbuiting van die skryfbare Konfigurasie Naamgewingskonteks (NC) of aanvalle op die vertroue-rekening nie.

[**Meer inligting oor domeinvertroue in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Sekere Algemene Verdedigings

[**Leer meer oor hoe om geloofsbriewe te beskerm hier.**](../stealing-credentials/credentials-protections.md)\\

### **Verdedigingsmaatreëls vir die beskerming van geloofsbriewe**

* **Beperkings vir domeinadministrateurs**: Dit word aanbeveel dat domeinadministrateurs slegs toegelaat word om in te teken op domeinbeheerders, en nie op ander gasheeromgewings nie.
* **Bevoegdhede van diensrekeninge**: Dienste moet nie met domeinadministrateur (DA) bevoegdhede uitgevoer word nie om sekuriteit te handhaaf.
* **Tydelike beperking van bevoegdhede**: Vir take wat DA-bevoegdhede vereis, moet hul duur beperk word. Dit kan bereik word deur: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementering van misleidingstegnieke**

* Die implementering van misleiding behels die opstel van valstrikke, soos lokgebruikers of -rekenaars, met kenmerke soos wagwoorde wat nie verval nie of as Vertrou vir Delegasie gemerk is. 'n Gedetailleerde benadering behels die skep van gebruikers met spesifieke regte of om hulle by hoë bevoorregte groepe te voeg.
* 'n Praktiese voorbeeld behels die gebruik van hulpmiddels soos: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Meer oor die implementering van misleidingstegnieke kan gevind word by [Deploy-Deception op GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifisering van misleiding**

* **Vir gebruikersvoorwerpe**: Verdagte aanduiders sluit ongewone ObjectSID, selde intekening, skeppingsdatums en lae tellings van slegte wagwoorde in.
* **Algemene aanduiders**: Deur eienskappe van potensiële lokvoorwerpe te vergelyk met dié van egte voorwerpe, kan teenstrydighede aan die lig kom. Hulpmiddels soos [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) kan help om sulke misleidings te identifiseer.

### **Omseilings van opsporingstelsels**

* **Microsoft ATA Opsetvermyding**:
* **Gebruikerstelling**: Vermy sessieopstelling op domeinbeheerders om ATA-opsporing te voorkom.
* **Kaartjie-impersonasie**: Die gebruik van **aes**-sleutels vir kaartjie-skepping help om opsporing te omseil deur nie af te gradeer na NTLM nie.
* **DCSync-aanvalle**: Dit word aanbeveel om dit uit te voer vanaf 'n nie-domeinbeheerder om ATA-opsporing te vermy, aangesien direkte uitvoering vanaf 'n domeinbeheerder waarskuwings sal veroorsaak.

## Verwysings

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil hê jou **maatskappy moet geadverteer word in HackTricks** of **HackTricks in PDF aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
