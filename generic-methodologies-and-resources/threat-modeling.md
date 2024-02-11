# Bedreigingsmodellering

## Bedreigingsmodellering

Welkom by HackTricks se omvattende gids oor Bedreigingsmodellering! Gaan op 'n ontdekkingsreis van hierdie kritieke aspek van sibersekerheid, waar ons potensiële kwesbaarhede in 'n stelsel identifiseer, verstaan en strategieë daarteen beplan. Hierdie draad dien as 'n stap-vir-stap-gids vol werklike voorbeelde, nuttige sagteware en maklik verstaanbare verduidelikings. Ideaal vir beginners en ervare beoefenaars wat hul sibersekerheidverdediging wil versterk.

### Algemeen Gebruikte Scenarios

1. **Sagteware-ontwikkeling**: As deel van die Veilige Sagteware-ontwikkelingslewensiklus (SSDLC) help bedreigingsmodellering om **potensiële bronne van kwesbaarhede** in die vroeë stadiums van ontwikkeling te identifiseer.
2. **Penetreringstoetsing**: Die Penetreringstoetsuitvoeringsstandaard (PTES) raamwerk vereis **bedreigingsmodellering om die kwesbaarhede van die stelsel te verstaan** voordat die toets uitgevoer word.

### Bedreigingsmodel in 'n neutedop

'n Bedreigingsmodel word tipies voorgestel as 'n diagram, beeld of 'n ander vorm van visuele voorstelling wat die beplande argitektuur of bestaande bou van 'n toepassing uitbeeld. Dit vertoon ooreenkomste met 'n **data vloei diagram**, maar die sleutelonderskeid lê in sy veiligheidsgeoriënteerde ontwerp.

Bedreigingsmodelle bevat dikwels elemente wat in rooi gemerk is, wat potensiële kwesbaarhede, risiko's of hindernisse simboliseer. Om die proses van risiko-identifikasie te stroomlyn, word die CIA (Vertroulikheid, Integriteit, Beskikbaarheid) driehoek gebruik, wat die basis vorm van baie bedreigingsmodelleringsmetodologieë, met STRIDE as een van die mees algemene. Die gekose metodologie kan egter wissel afhangende van die spesifieke konteks en vereistes.

### Die CIA Driehoek

Die CIA Driehoek is 'n wyd erken model in die veld van inligtingsbeveiliging, wat staan vir Vertroulikheid, Integriteit en Beskikbaarheid. Hierdie drie pilare vorm die grondslag waarop baie veiligheidsmaatreëls en -beleide gebou word, insluitend bedreigingsmodelleringsmetodologieë.

1. **Vertroulikheid**: Verseker dat die data of stelsel nie deur ongemagtigde individue benader word nie. Dit is 'n sentrale aspek van veiligheid wat gepaste toegangskontroles, enkripsie en ander maatreëls vereis om data-oortredings te voorkom.
2. **Integriteit**: Die akkuraatheid, konsekwentheid en betroubaarheid van die data oor sy lewensiklus. Hierdie beginsel verseker dat die data nie deur ongemagtigde partye verander of geknoei word nie. Dit behels dikwels kontrolesomme, hasing en ander data-verifikasiemetodes.
3. **Beskikbaarheid**: Dit verseker dat data en dienste toeganklik is vir gemagtigde gebruikers wanneer dit nodig is. Dit behels dikwels oortolligheid, fouttoleransie en hoë-beskikbaarheidskonfigurasies om stelsels te laat werk selfs in die aangesig van onderbrekings.

### Bedreigingsmodelleringsmetodologieë

1. **STRIDE**: Ontwikkel deur Microsoft, STRIDE is 'n akroniem vir **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service en Elevation of Privilege**. Elke kategorie verteenwoordig 'n tipe bedreiging, en hierdie metodologie word algemeen gebruik in die ontwerpfase van 'n program of stelsel om potensiële bedreigings te identifiseer.
2. **DREAD**: Dit is 'n ander metodologie van Microsoft wat gebruik word vir risiko-assessering van geïdentifiseerde bedreigings. DREAD staan vir **Damage potential, Reproducibility, Exploitability, Affected users en Discoverability**. Elkeen van hierdie faktore word geskore, en die resultaat word gebruik om geïdentifiseerde bedreigings te prioritiseer.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Dit is 'n sewe-stap, **risiko-sentriese** metodologie. Dit sluit die definisie en identifikasie van sekuriteitsdoelwitte, die skep van 'n tegniese omvang, toepassingsontbinding, bedreigingsanalise, kwesbaarheidsanalise en risiko-/triage-assessering in.
4. **Trike**: Dit is 'n risikogebaseerde metodologie wat fokus op die verdediging van bates. Dit begin vanuit 'n **risikobestuur**-perspektief en kyk na bedreigings en kwesbaarhede in daardie konteks.
5. **VAST** (Visual, Agile en Simple Threat modeling): Hierdie benadering streef daarna om meer toeganklik te wees en integreer in Agile-ontwikkelingsomgewings. Dit kombineer elemente uit die ander metodologieë en fokus op **visuele voorstellings van bedreigings**.
6. **OCTAVE** (Operationally Critical Threat, Asset en Vulnerability Evaluation): Ontwikkel deur die CERT Koördinasiesentrum, is hierdie raamwerk gerig op **organisatoriese risiko-assessering eerder as spesifieke stelsels of sagteware**.

## Hulpmiddels

Daar is verskeie hulpmiddels en sagteware-oplossings beskikbaar wat kan **help** met die skep en bestuur van bedreigingsmodelle. Hier is 'n paar wat jy kan oorweeg.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

'n Gevorderde kruisplatform- en multifunksie-GUI-webspinnekop-/kruiper vir sibersekerheidsprofessionele. Spider Suite kan gebruik word vir aanvalsoppervlakkaartlegging en -analise.

**Gebruik**

1. Kies 'n URL en Kruip

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Sien Grafiek

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

'n Opensource-projek van OWASP, Threat Dragon is 'n web- en lessenaarprogram wat stelseldiagrammering sowel as 'n reël-enjin insluit om bedreigings/mitigasies outomaties te genereer.

**Gebruik**

1. Skep Nuwe Projek

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Soms kan dit so lyk:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Lanseer Nuwe Projek

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Stoor Die Nuwe Projek

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Skep jou model

Jy kan hulpmiddels soos SpiderSuite Crawler gebruik om jou inspirasie te gee, 'n basiese model sal iets soos dit lyk

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Net 'n bietjie verduideliking oor die entiteite:

* Proses (Die entiteit self soos Webbediener of webfunksionaliteit)
* Akteur ( 'n Persoon soos 'n Webwerfbesoeker, Gebruiker of Administrateur)
* Data Vloei Llyn (Aanwysing van Interaksie)
* Vertrouensgrens (Verskillende netwerksegmente of omvang.)
* Berg (Dinge waar data gestoor word, soos Databasisse)

5. Skep 'n Bedreiging (Stap 1)

Eerstens moet jy die laag kies waarin jy 'n bedreiging wil byvoeg

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Nou kan jy die bedreiging skep

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Hou in gedagte dat daar 'n verskil is tussen Akteurbedreigings en Prosesbedreigings. As jy 'n bedreiging by 'n Akteur wil voeg, sal jy slegs "Spoofing" en "Repudiation" kan kies. In ons voorbeeld voeg ons egter 'n bedreiging by 'n Prosesentiteit, so ons sal dit in die bedreigingskeppingkas sien:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6.
