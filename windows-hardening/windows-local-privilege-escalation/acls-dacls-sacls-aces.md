# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik en outomatiese werkstrome te bou wat aangedryf word deur die wêreld se mees gevorderde gemeenskaplike gereedskap.\
Kry vandag toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## **Toegangbeheerlys (ACL)**

'n Toegangbeheerlys (ACL) bestaan uit 'n geordende stel Toegangbeheerinskrywings (ACE's) wat die beskerming vir 'n voorwerp en sy eienskappe bepaal. In wese bepaal 'n ACL watter aksies deur watter sekuriteitsbeginsels (gebruikers of groepe) toegelaat of geweier word op 'n gegewe voorwerp.

Daar is twee tipes ACL's:

- **Diskresionêre Toegangbeheerlys (DACL):** Spesifiseer watter gebruikers en groepe toegang tot 'n voorwerp het of nie het nie.
- **Stelseltoegangbeheerlys (SACL):** Beheer die ouditering van toegangspogings tot 'n voorwerp.

Die proses om 'n lêer te benader, behels dat die stelsel die sekuriteitsbeskrywer van die voorwerp vergelyk met die gebruiker se toegangsteken om te bepaal of toegang verleen moet word en die omvang van daardie toegang, gebaseer op die ACE's.

### **Kernkomponente**

- **DACL:** Bevat ACE's wat toegangsmagtigings aan gebruikers en groepe verleen of ontken vir 'n voorwerp. Dit is in wese die hoof-ACL wat toegangsregte bepaal.

- **SACL:** Word gebruik vir ouditering van toegang tot voorwerpe, waar ACE's die tipes toegang definieer wat in die Sekuriteitsgebeurtenisjoernaal aangeteken moet word. Dit kan van onschatbare waarde wees om ongemagtigde toegangspogings op te spoor of toegangsprobleme op te los.

### **Stelselinteraksie met ACL's**

Elke gebruikersessie is gekoppel aan 'n toegangsteken wat sekuriteitsinligting bevat wat relevant is vir daardie sessie, insluitend gebruikers-, groepidentiteite en voorregte. Hierdie teken bevat ook 'n aanmeldings-SID wat die sessie uniek identifiseer.

Die Plaaslike Sekuriteitsowerheid (LSASS) verwerk toegangsversoeke tot voorwerpe deur die DACL te ondersoek vir ACE's wat ooreenstem met die sekuriteitsbeginsel wat toegang probeer verkry. Toegang word onmiddellik verleen as geen relevante ACE's gevind word nie. Anders vergelyk LSASS die ACE's met die sekuriteitsbeginsel se SID in die toegangsteken om toegangsgeregtigheid te bepaal.

### **Opgesomde Proses**

- **ACL's:** Definieer toegangsmagtigings deur middel van DACL's en ouditeringsreëls deur middel van SACL's.
- **Toegangsteken:** Bevat gebruikers-, groep- en voorreginligting vir 'n sessie.
- **Toegangsbesluit:** Word geneem deur DACL ACE's te vergelyk met die toegangsteken; SACL's word gebruik vir ouditering.


### ACE's

Daar is **drie hooftipes Toegangsbeheerinskrywings (ACE's)**:

- **Toegang Geweier ACE**: Hierdie ACE ontken uitdruklik toegang tot 'n voorwerp vir gespesifiseerde gebruikers of groepe (in 'n DACL).
- **Toegang Toegelaat ACE**: Hierdie ACE verleen uitdruklik toegang tot 'n voorwerp vir gespesifiseerde gebruikers of groepe (in 'n DACL).
- **Stelseloudit ACE**: Geplaas binne 'n Stelseltoegangbeheerlys (SACL), is hierdie ACE verantwoordelik vir die genereer van ouditlogboeke tydens toegangspogings tot 'n voorwerp deur gebruikers of groepe. Dit dokumenteer of toegang toegelaat of ontken is en die aard van die toegang.

Elke ACE het **vier kritieke komponente**:

1. Die **Sekuriteitsidentifiseerder (SID)** van die gebruiker of groep (of hul hoofnaam in 'n grafiese voorstelling).
2. 'n **Vlag** wat die ACE-tipe identifiseer (toegang geweier, toegelaat, of stelseloudit).
3. **Oorerwingvlagte** wat bepaal of kindervoorwerpe die ACE van hul ouer kan oorneem.
4. 'n **[Toegangsmerk](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)**, 'n 32-bis-waarde wat die verleen regte van die voorwerp spesifiseer.

Toegangsbepaling word uitgevoer deur elke ACE opeenvolgend te ondersoek totdat:

- 'n **Toegang Geweier ACE** die versoekte regte uitdruklik ontken vir 'n trustee wat in die toegangsteken geïdentifiseer word.
- **Toegang Toegelaat ACE(s)** verleen uitdruklik alle versoekte regte aan 'n trustee in die toegangsteken.
- Nadat alle ACE's nagegaan is, as enige versoekte reg **nie uitdruklik toegelaat is nie**, word toegang implisiet **ontken**.


### Volgorde van ACE's

Die manier waarop **ACE's** (reëls wat sê wie toegang tot iets kan hê of nie) in 'n lys genaamd **DACL** geplaas word, is baie belangrik. Dit is omdat sodra die stelsel toegang gee of ontken op grond van hierdie reëls, hou dit op om na die res te kyk.

Daar is 'n beste manier om hierdie ACE's te organiseer, en dit word **"kanoniese volgorde"** genoem. Hierdie metode help om seker te maak dat alles glad en regverdig werk. So gaan dit vir stelsels soos **Windows 2000** en **Windows Server 2003**:

- Plaas eers al die reëls wat **spesifiek vir hierdie item** gemaak is, voor die reëls wat van 'n ander plek af kom, soos 'n ouermap.
- Plaas in daardie spesifieke reëls diegene wat sê **"nee" (ontken)** voor diegene wat sê **"ja" (toelaat)**.
-
### GUI Voorbeeld

**[Voorbeeld van hier](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

Dit is het klassieke beveiligingstabblad van een map waarop de ACL, DACL en ACE's worden weergegeven:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Als we op de **Geavanceerde knop** klikken, krijgen we meer opties zoals overerving:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

En als je een beveiligingsprincipe toevoegt of bewerkt:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

En tot slot hebben we de SACL in het tabblad Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Toegangsbeheer uitleg op een vereenvoudigde manier

Bij het beheren van toegang tot bronnen, zoals een map, gebruiken we lijsten en regels die bekend staan als Access Control Lists (ACL's) en Access Control Entries (ACE's). Deze bepalen wie wel of geen toegang heeft tot bepaalde gegevens.

#### Toegang weigeren aan een specifieke groep

Stel je voor dat je een map hebt met de naam "Kosten" en dat je wilt dat iedereen er toegang toe heeft, behalve het marketingteam. Door de regels correct in te stellen, kunnen we ervoor zorgen dat het marketingteam expliciet de toegang wordt ontzegd voordat iedereen anders toegang krijgt. Dit wordt gedaan door de regel om toegang te weigeren aan het marketingteam vóór de regel die toegang verleent aan iedereen te plaatsen.

#### Toegang verlenen aan een specifiek lid van een geweigerde groep

Laten we zeggen dat Bob, de marketingdirecteur, toegang nodig heeft tot de map "Kosten", ook al mag het marketingteam normaal gesproken geen toegang hebben. We kunnen een specifieke regel (ACE) voor Bob toevoegen die hem toegang verleent en deze vóór de regel plaatsen die toegang weigert aan het marketingteam. Op deze manier krijgt Bob toegang ondanks de algemene beperking voor zijn team.

#### Begrijpen van Access Control Entries

ACE's zijn de individuele regels in een ACL. Ze identificeren gebruikers of groepen, specificeren welke toegang is toegestaan ​​of geweigerd en bepalen hoe deze regels van toepassing zijn op sub-items (overerving). Er zijn twee hoofdtypen ACE's:

- **Generieke ACE's**: Deze zijn breed van toepassing en beïnvloeden ofwel alle soorten objecten of maken alleen onderscheid tussen containers (zoals mappen) en niet-containers (zoals bestanden). Bijvoorbeeld een regel die gebruikers toestaat de inhoud van een map te zien, maar geen toegang geeft tot de bestanden erin.

- **Objectspecifieke ACE's**: Deze bieden meer nauwkeurige controle en stellen regels in voor specifieke soorten objecten of zelfs individuele eigenschappen binnen een object. Bijvoorbeeld, in een map met gebruikers, kan een regel een gebruiker toestaan ​​om hun telefoonnummer bij te werken, maar niet hun inloguren.

Elke ACE bevat belangrijke informatie zoals op wie de regel van toepassing is (met behulp van een Security Identifier of SID), wat de regel toestaat of weigert (met behulp van een toegangsmasker) en hoe deze wordt geërfd door andere objecten.

#### Belangrijkste verschillen tussen ACE-typen

- **Generieke ACE's** zijn geschikt voor eenvoudige toegangsbeheerscenario's, waar dezelfde regel van toepassing is op alle aspecten van een object of op alle objecten binnen een container.

- **Objectspecifieke ACE's** worden gebruikt voor complexere scenario's, vooral in omgevingen zoals Active Directory, waar je mogelijk de toegang tot specifieke eigenschappen van een object anders moet beheren.

Samengevat helpen ACL's en ACE's bij het definiëren van nauwkeurige toegangscontroles, waarbij alleen de juiste personen of groepen toegang hebben tot gevoelige informatie of bronnen, met de mogelijkheid om toegangsrechten aan te passen tot op het niveau van individuele eigenschappen of objecttypen.

### Indeling van Access Control Entry

| ACE-veld   | Beschrijving                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Vlag die het type ACE aangeeft. Windows 2000 en Windows Server 2003 ondersteunen zes soorten ACE's: drie generieke ACE-typen die zijn gekoppeld aan alle beveiligbare objecten en drie objectspecifieke ACE-typen die kunnen voorkomen voor Active Directory-objecten.                                                                                                                                                                                                                                                            |
| Vlaggen       | Set van bitvlaggen die overerving en auditing regelen.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Grootte        | Aantal bytes geheugen dat is toegewezen voor de ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Toegangsmasker | 32-bits waarde waarvan de bits overeenkomen met toegangsrechten voor het object. Bits kunnen aan of uit worden gezet, maar de betekenis van de instelling hangt af van het type ACE. Bijvoorbeeld, als de bit die overeenkomt met het recht om machtigingen te lezen is ingeschakeld en het ACE-type Deny is, weigert het ACE het recht om de machtigingen van het object te lezen. Als dezelfde bit is ingeschakeld maar het ACE-type Allow is, verleent het ACE het recht om de machtigingen van het object te lezen. Meer details van het toegangsmasker worden weergegeven in de volgende tabel. |
| SID         | Identificeert een gebruiker of groep waarvan de toegang wordt gecontroleerd of bewaakt door deze ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Indeling van het toegangsmasker

| Bit (bereik) | Betekenis                            | Beschrijving/Voorbeeld                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Objectspecifieke toegangsrechten      | Gegevens lezen, Uitvoeren, Gegevens toevoegen           |
| 16 - 22     | Standaardtoegangsrechten             | Verwijderen, ACL schrijven, Eigenaar schrijven            |
| 23          | Kan beveiligings-ACL openen            |                                           |
| 24 - 27     | Gereserveerd                           |                                           |
| 28          | Generiek ALLES (Lezen, Schrijven, Uitvoeren) | Alles hieronder                          |
| 29          | Generiek Uitvoeren                    | Alles wat nodig is om een programma uit te voeren |
| 30          | Generiek Schrijven                      | Alles wat nodig is om naar een bestand te schrijven   |
| 31          | Generiek Lezen                       | Alles wat nodig is om een bestand te lezen       |

## Verwysings

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere manieren om HackTricks te ondersteunen:

* Als je je **bedrijf wilt adverteren in HackTricks** of **HackTricks in PDF wilt downloaden**, bekijk dan de [**ABONNEMENTSPAKKETTEN**](https://github.com/sponsors/carlospolop)!
* Koop de [**officiële PEASS & HackTricks-merchandise**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), onze collectie exclusieve [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Doe mee aan de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https
