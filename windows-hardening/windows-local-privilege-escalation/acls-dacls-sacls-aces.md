# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **outomatiseer werkstrome** aangedryf deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## **Toegangsbeheerlys (ACL)**

'n Toegangsbeheerlys (ACL) bestaan uit 'n geordende stel Toegangsbeheerinskrywings (ACE's) wat die beskerming vir 'n voorwerp en sy eienskappe bepaal. In wese bepaal 'n ACL watter aksies deur watter sekuriteitsprinsipale (gebruikers of groepe) toegelaat of ontken word op 'n gegewe voorwerp.

Daar is twee tipes ACL's:

* **Diskresionêre Toegangsbeheerlys (DACL):** Spesifiseer watter gebruikers en groepe toegang tot 'n voorwerp het of nie.
* **Stelseltoegangsbeheerlys (SACL):** Beheer die ouditering van toegangspogings tot 'n voorwerp.

Die proses van toegang tot 'n lêer behels dat die stelsel die sekuriteitsbeskrywing van die voorwerp teen die gebruiker se toegangstoken nakyk om te bepaal of toegang verleen moet word en die omvang van daardie toegang, gebaseer op die ACE's.

### **Kernkomponente**

* **DACL:** Bevat ACE's wat toegangsgemagtigings aan gebruikers en groepe verleen of ontken vir 'n voorwerp. Dit is in wese die hoof-ACL wat toegangsregte bepaal.
* **SACL:** Word gebruik vir ouditering van toegang tot voorwerpe, waar ACE's die tipes toegang definieer wat in die Sekuriteitsgebeurtenisjoernaal gelog moet word. Dit kan van onschatbare waarde wees om ongemagtigde toegangspogings op te spoor of toegangsprobleme op te los.

### **Stelselinteraksie met ACL's**

Elke gebruikersessie is geassosieer met 'n toegangstoken wat sekuriteitsinligting wat relevant is vir daardie sessie bevat, insluitend gebruiker-, groepidentiteite en voorregte. Hierdie token bevat ook 'n aanmeldings-SID wat die sessie uniek identifiseer.

Die Plaaslike Sekuriteitsowerheid (LSASS) verwerk toegangsaanvrae tot voorwerpe deur die DACL te ondersoek vir ACE's wat ooreenstem met die sekuriteitsprinsipaal wat toegang probeer verkry. Toegang word onmiddellik verleen as geen relevante ACE's gevind word nie. Andersins vergelyk LSASS die ACE's teen die sekuriteitsprinsipaal se SID in die toegangstoken om toegangsgeregtigheid te bepaal.

### **Gesommeerde Proses**

* **ACL's:** Definieer toegangsgemagtigings deur DACL's en ouditeringsreëls deur SACL's.
* **Toegangstoken:** Bevat gebruiker-, groep- en voorreginligting vir 'n sessie.
* **Toegangsbesluit:** Word gemaak deur DACL ACE's met die toegangstoken te vergelyk; SACL's word gebruik vir ouditering.

### ACE's

Daar is **drie hooftipes Toegangsbeheerinskrywings (ACE's)**:

* **Toegang Geweier ACE**: Hierdie ACE ontken uitdruklik toegang tot 'n voorwerp vir gespesifiseerde gebruikers of groepe (in 'n DACL).
* **Toegang Toegelaat ACE**: Hierdie ACE verleen uitdruklik toegang tot 'n voorwerp vir gespesifiseerde gebruikers of groepe (in 'n DACL).
* **Stelseloudit ACE**: Geplaas binne 'n Stelseltoegangsbeheerlys (SACL), is hierdie ACE verantwoordelik vir die genereer van ouditlogs tydens toegangspogings tot 'n voorwerp deur gebruikers of groepe. Dit dokumenteer of toegang toegelaat of ontken is en die aard van die toegang.

Elke ACE het **vier kritiese komponente**:

1. Die **Sekuriteitsidentifiseerder (SID)** van die gebruiker of groep (of hul hoofnaam in 'n grafiese voorstelling).
2. 'n **Vlag** wat die ACE-tipe identifiseer (toegang geweier, toegelaat, of stelseloudit).
3. **Oorerwingvlagte** wat bepaal of kindervoorwerpe die ACE van hul ouer kan oorneem.
4. 'n [**toegangsmasker**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 'n 32-bis-waarde wat die verleen regte van die voorwerp spesifiseer.

Toegangsbepaling word uitgevoer deur elke ACE sekwensieel te ondersoek totdat:

* 'n **Toegang Geweier ACE** die versoekte regte uitdruklik ontken aan 'n trustee wat in die toegangstoken geïdentifiseer is.
* **Toegang Toegelaat ACE(s)** verleen alle versoekte regte uitdruklik aan 'n trustee in die toegangstoken.
* Na die ondersoek van alle ACE's, as enige versoekte reg nie uitdruklik toegelaat is nie, word toegang implisiet **ontken**.

### Volgorde van ACE's

Die manier waarop **ACE's** (reëls wat sê wie toegang tot iets kan hê of nie) in 'n lys genaamd **DACL** geplaas word, is baie belangrik. Dit is omdat sodra die stelsel toegang gee of ontken gebaseer op hierdie reëls, hou dit op om na die res te kyk.

Daar is 'n beste manier om hierdie ACE's te organiseer, en dit word **"kanoniese volgorde"** genoem. Hierdie metode help om seker te maak dat alles glad en regtig werk. Dit gaan so vir stelsels soos **Windows 2000** en **Windows Server 2003**:

* Plaas eers al die reëls wat **spesifiek vir hierdie item** gemaak is voor diegene wat van elders kom, soos 'n ouermap.
* In daardie spesifieke reëls, plaas diegene wat sê **"nee" (ontken)** voor diegene wat sê **"ja" (toelaat)**.
* Vir die reëls wat van elders kom, begin met diegene van die **nabyste bron**, soos die ouer, en gaan dan terug van daar af. Weer, plaas **"nee"** voor **"ja."**

Hierdie opstelling help op twee groot maniere:

* Dit maak seker dat as daar 'n spesifieke **"nee"** is, dit geëerbiedig word, ongeag watter ander **"ja"** reëls daar is.
* Dit laat die eienaar van 'n item die **laaste sê** hê oor wie binnekom, voordat enige reëls van ouermappe of verder terug in werking tree.

Deur dit op hierdie manier te doen, kan die eienaar van 'n lêer of vouer baie presies wees oor wie toegang kry, en verseker dat die regte mense binnekom en die verkeerde nie.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

So, hierdie **"kanoniese volgorde"** gaan oor die verseker dat die toegangsreëls duidelik en goed werk, spesifieke reëls eerste plaas en alles op 'n slim manier organiseer.

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **outomatiseer werkstrome** aangedryf deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### GUI Voorbeeld

[**Voorbeeld van hier**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Dit is die klassieke sekuriteitstaba van 'n vouer wat die ACL, DACL en ACEs wys:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

As ons op die **Gevorderde knoppie** klik, sal ons meer opsies soos erfenis kry:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

En as jy 'n Sekuriteitsprinsipaal byvoeg of wysig:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

En laastens het ons die SACL in die Oudit-taba:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Verduideliking van Toegangsbeheer op 'n Vereenvoudigde Manier

Wanneer ons toegang tot hulpbronne, soos 'n vouer, bestuur, gebruik ons lyste en reëls bekend as Toegangsbeheerlyste (ACLs) en Toegangsbeheerinskrywings (ACEs). Hierdie definieer wie sekere data kan of nie kan benader nie.

#### Toegang tot 'n Spesifieke Groep Weier

Stel jou het 'n vouer genaamd Koste, en jy wil hê dat almal dit kan benader behalwe vir 'n bemarkingsspan. Deur die reëls korrek op te stel, kan ons verseker dat die bemarkingsspan uitdruklik die toegang ontneem word voordat almal anders toegang kry. Dit word gedoen deur die reël om toegang te weier aan die bemarkingsspan voor die reël wat toegang verleen aan almal te plaas.

#### Toegang verleen aan 'n Spesifieke Lid van 'n Geweierde Groep

Laat ons sê Bob, die bemarkingsdirekteur, toegang tot die Koste-vouer nodig het, selfs al behoort die bemarkingsspan normaalweg nie toegang te hê nie. Ons kan 'n spesifieke reël (ACE) vir Bob byvoeg wat hom toegang verleen, en dit voor die reël plaas wat toegang aan die bemarkingsspan weier. Op hierdie manier kry Bob toegang ten spyte van die algemene beperking op sy span.

#### Begrip van Toegangsbeheerinskrywings

ACEs is die individuele reëls in 'n ACL. Hulle identifiseer gebruikers of groepe, spesifiseer watter toegang toegelaat of geweier word, en bepaal hoe hierdie reëls van toepassing is op sub-items (erfenis). Daar is twee hooftipes ACEs:

* **Generiese ACEs**: Hierdie is breed van toepassing, wat óf op alle tipes voorwerpe van toepassing is óf slegs onderskei tussen houers (soos vouers) en nie-houers (soos lêers). Byvoorbeeld, 'n reël wat gebruikers toelaat om die inhoud van 'n vouer te sien maar nie die lêers binne-in te benader nie.
* **Voorwerpspesifieke ACEs**: Hierdie bied meer presiese beheer, wat reëls toelaat om ingestel te word vir spesifieke tipes voorwerpe of selfs individuele eienskappe binne 'n voorwerp. Byvoorbeeld, in 'n gids van gebruikers, mag 'n reël 'n gebruiker toelaat om hul telefoonnommer op te dateer maar nie hul aanmeldingstye nie.

Elke ACE bevat belangrike inligting soos vir wie die reël geld (deur 'n Sekuriteitsidentifiseerder of SID te gebruik), wat die reël toelaat of weier (deur 'n toegangsmerk te gebruik), en hoe dit deur ander voorwerpe geërf word.

#### Sleutelverskille Tussen ACE-tipes

* **Generiese ACEs** is geskik vir eenvoudige toegangsbeheerscenarios, waar dieselfde reël van toepassing is op alle aspekte van 'n voorwerp of op alle voorwerpe binne 'n houer.
* **Voorwerpspesifieke ACEs** word gebruik vir meer komplekse scenarios, veral in omgewings soos Aktiewe Gids, waar jy dalk toegang tot spesifieke eienskappe van 'n voorwerp anders moet beheer.

Kortom, ACLs en ACEs help om presiese toegangsbeheer te definieer, wat verseker dat slegs die regte individue of groepe toegang tot sensitiewe inligting of hulpbronne het, met die vermoë om toegangsregte tot op die vlak van individuele eienskappe of voorwerptipes aan te pas.

### Toegangsbeheerinskrywinguitleg

| ACE-veld   | Beskrywing                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipe        | Vlag wat die tipe ACE aandui. Windows 2000 en Windows Server 2003 ondersteun ses tipes ACE: Drie generiese ACE-tipes wat aan alle beveiligbare voorwerpe geheg is. Drie voorwerp-spesifieke ACE-tipes wat vir Aktiewe Gids-voorwerpe kan voorkom.                                                                                                                                                                                                                                                            |
| Vlae       | Stel van bietjievlags wat erfenis en ouditering beheer.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Grootte        | Aantal bytes van geheue wat vir die ACE toegewys is.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Toegangsmerk | 32-bisewaarde waarvan die bietjies ooreenstem met toegangsregte vir die voorwerp. Bietjies kan óf aan óf af gestel word, maar die betekenis van die instelling hang af van die ACE-tipe. Byvoorbeeld, as die bietjie wat ooreenstem met die reg om toestemmings te lees, aangeskakel is, en die ACE-tipe is Weier, weier die ACE die reg om die voorwerp se toestemmings te lees. As dieselfde bietjie aangeskakel is maar die ACE-tipe is Toelaat, verleen die ACE die reg om die voorwerp se toestemmings te lees. Meer besonderhede van die Toegangsmerk verskyn in die volgende tabel. |
| SID         | Identifiseer 'n gebruiker of groep wie se toegang deur hierdie ACE beheer of gemonitor word.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Toegangsmerkuitleg

| Bietjie (Reeks) | Betekenis                            | Beskrywing/Voorbeeld                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Voorwerp Spesifieke Toegangsregte      | Lees data, Uitvoer, Voeg data by           |
| 16 - 22     | Standaard Toegangsregte             | Skrap, Skryf ACL, Skryf Eienaar            |
| 23          | Kan toegang tot sekuriteits-ACL verkry            |                                           |
| 24 - 27     | Voorbehou                           |                                           |
| 28          | Generiese ALLES (Lees, Skryf, Uitvoer) | Alles hieronder                          |
| 29          | Generiese Uitvoer                    | Alles wat nodig is om 'n program uit te voer |
| 30          | Generiese Skryf                      | Alles wat nodig is om na 'n lêer te skryf   |
| 31          | Generiese Lees                       | Alles wat nodig is om 'n lêer te lees       |

## Verwysings

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)
