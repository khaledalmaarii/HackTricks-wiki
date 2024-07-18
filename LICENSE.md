{% hint style="success" %}
Leer & oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Kopiereg © Carlos Polop 2021. Behalwe waar anders aangedui (die eksterne inligting wat in die boek gekopieer is, behoort aan die oorspronklike skrywers), is die teks op <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> deur Carlos Polop gelisensieer onder die <a href="https://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Erkenning-GeenKommerselewe 4.0 Internasionaal (CC BY-NC 4.0)</a>.

Lisensie: Erkenning-GeenKommerselewe 4.0 Internasionaal (CC BY-NC 4.0)<br>Mensleesbare Lisensie: https://creativecommons.org/licenses/by-nc/4.0/<br>Volledige Regsterme: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>Formatering: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# creative commons

# Erkenning-GeenKommerselewe 4.0 Internasionaal

Creative Commons Corporation ("Creative Commons") is nie 'n prokureursfirma nie en verskaf nie regsdienste of regadvies nie. Verspreiding van Creative Commons openbare lisensies skep nie 'n prokureur-kliënt of ander verhouding nie. Creative Commons maak sy lisensies en verwante inligting beskikbaar op 'n "soos-is" basis. Creative Commons gee geen waarborge met betrekking tot sy lisensies, enige materiaal gelisensieer onder hul voorwaardes enige verwante inligting nie. Creative Commons verwerp alle aanspreeklikheid vir skade wat voortspruit uit hul gebruik tot die volle omvang moontlik.

## Gebruik van Creative Commons Openbare Lisensies

Creative Commons openbare lisensies bied 'n standaardstel voorwaardes wat skeppers en ander regshouers kan gebruik om oorspronklike werke van outeurskap en ander materiaal wat onderhewig is aan kopiereg en sekere ander regte soos gespesifiseer in die openbare lisensie hieronder, te deel. Die volgende oorwegings is slegs vir inligtingsdoeleindes, is nie uitputtend nie, en vorm nie deel van ons lisensies nie.

* __Oorwegings vir lisensiehouers:__ Ons openbare lisensies is bedoel vir gebruik deur diegene wat gemagtig is om die publiek toestemming te gee om materiaal op maniere te gebruik wat andersins deur kopiereg en sekere ander regte beperk word. Ons lisensies is onherroeplik. Lisensiehouers moet die terme en voorwaardes van die lisensie wat hulle kies, lees en verstaan voordat hulle dit toepas. Lisensiehouers moet ook alle regte verseker wat nodig is voordat hulle ons lisensies toepas sodat die publiek die materiaal kan hergebruik soos verwag. Lisensiehouers moet enige materiaal wat nie onderhewig is aan die lisensie, duidelik merk. Dit sluit ander CC-gelisensieerde materiaal in, of materiaal wat onder 'n uitsondering of beperking tot kopiereg gebruik word. [Meer oorwegings vir lisensiehouers](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Oorwegings vir die publiek:__ Deur een van ons openbare lisensies te gebruik, gee 'n lisensiehouer die publiek toestemming om die gelisensieerde materiaal te gebruik onder gespesifiseerde terme en voorwaardes. As die toestemming van die lisensiehouer nie nodig is om enige rede nie – byvoorbeeld, as gevolg van enige toepaslike uitsondering of beperking tot kopiereg – dan word daardie gebruik nie deur die lisensie gereguleer nie. Ons lisensies verleen slegs toestemmings onder kopiereg en sekere ander regte waaroor 'n lisensiehouer die gesag het om te verleen. Die gebruik van die gelisensieerde materiaal kan nog steeds beperk word om ander redes, insluitend omdat ander kopiereg of ander regte in die materiaal het. 'n Lisensiehouer kan spesiale versoeke maak, soos om te vra dat alle veranderinge gemerk of beskryf word. Alhoewel nie deur ons lisensies vereis nie, word jy aangemoedig om daardie versoeke te respekteer waar redelik. [Meer oorwegings vir die publiek](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Creative Commons Erkenning-GeenKommerselewe 4.0 Internasionaal Openbare Lisensie

Deur die Gelisensieerde Regte (hieronder gedefinieer) uit te oefen, aanvaar en stem jy in om gebonde te wees aan die terme en voorwaardes van hierdie Creative Commons Erkenning-GeenKommerselewe 4.0 Internasionaal Openbare Lisensie ("Openbare Lisensie"). Vir sover hierdie Openbare Lisensie geïnterpreteer kan word as 'n kontrak, word jy die Gelisensieerde Regte verleen in oorweging van jou aanvaarding van hierdie terme en voorwaardes, en die Lisensiehouer verleen jou sulke regte in oorweging van die voordele wat die Lisensiehouer ontvang deur die Gelisensieerde Materiaal beskikbaar te stel onder hierdie terme en voorwaardes.

## Afdeling 1 - Definisies.

a. __Aangepaste Materiaal__ beteken materiaal onderhewig aan Kopiereg en Soortgelyke Regte wat afgelei is van of gebaseer is op die Gelisensieerde Materiaal en waarin die Gelisensieerde Materiaal vertaal, verander, gereël, getransformeer, of andersins gewysig is op 'n wyse wat toestemming vereis onder die Kopiereg en Soortgelyke Regte wat deur die Lisensiehouer besit word. Vir doeleindes van hierdie Openbare Lisensie, waar die Gelisensieerde Materiaal 'n musiekwerk, uitvoering, of klankopname is, word Aangepaste Materiaal altyd geproduseer waar die Gelisensieerde Materiaal gesinkroniseer is in getimede verhouding met 'n bewegende beeld.

b. __Lisensie van die Aanpasser__ beteken die lisensie wat jy toepas op Jou Kopiereg en Soortgelyke Regte in Jou bydraes tot Aangepaste Materiaal in ooreenstemming met die terme en voorwaardes van hierdie Openbare Lisensie.

c. __Kopiereg en Soortgelyke Regte__ beteken kopiereg en/of soortgelyke regte wat nou verwant is aan kopiereg, insluitend, sonder beperking, uitvoering, uitsending, klankopname, en Sui Generis Databasisregte, ongeag hoe die regte geëtiketteer of gekategoriseer word. Vir doeleindes van hierdie Openbare Lisensie is die regte gespesifiseer in Afdeling 2(b)(1)-(2) nie Kopiereg en Soortgelyke Regte nie.

d. __Doeltreffende Tegnologiese Maatreëls__ beteken daardie maatreëls wat, in die afwesigheid van behoorlike gesag, nie omseil mag word onder wette wat verpligtinge nakom ingevolge Artikel 11 van die WIPO Kopieregverdrag wat op 20 Desember 1996 aanvaar is, en/of soortgelyke internasionale ooreenkomste.

e. __Uitsonderings en Beperkings__ beteken billike gebruik, billike hantering, en/of enige ander uitsondering of beperking tot Kopiereg en Soortgelyke Regte wat van toepassing is op jou gebruik van die Gelisensieerde Materiaal.

f. __Gelisensieerde Materiaal__ beteken die artistieke of letterkundige werk, databasis, of ander materiaal waarop die Lisensiehouer hierdie Openbare Lisensie toegepas het.

g. __Gelisensieerde Regte__ beteken die regte wat aan jou verleen word onderhewig aan die terme en voorwaardes van hierdie Openbare Lisensie, wat beperk is tot alle Kopiereg en Soortgelyke Regte wat van toepassing is op jou gebruik van die Gelisensieerde Materiaal en waaroor die Lisensiehouer die gesag het om te lisensieer.

h. __Lisensiehouer__ beteken die individu(e) of entiteit(e) wat regte verleen onder hierdie Openbare Lisensie.

i. __NieKommerseel__ beteken nie hoofsaaklik bedoel vir of gerig op kommersiële voordeel of monetêre vergoeding nie. Vir doeleindes van hierdie Openbare Lisensie is die uitruil van die Gelisensieerde Materiaal vir ander materiaal onderhewig aan Kopiereg en Soortgelyke Regte deur digitale lêerdeling of soortgelyke metodes NieKommerseel mits daar geen betaling van monetêre vergoeding in verband met die uitruil is nie.

j. __Deel__ beteken om materiaal aan die publiek te voorsien deur enige middel of proses wat toestemming onder die Gelisensieerde Regte vereis, soos reproduksie, openbare vertoning, openbare uitvoering, verspreiding, disseminasie, kommunikasie, of invoer, en om materiaal beskikbaar te stel aan die publiek, insluitend op maniere waarop lede van die publiek die materiaal vanaf 'n plek en op 'n tyd individueel deur hulle gekies kan toegang verkry.

k. __Sui Generis Databasisregte__ beteken regte anders as kopiereg wat voortspruit uit Direktief 96/9/EG van die Europese Parlement en die Raad van 11 Maart 1996 oor die regsbewaring van databasisse, soos gewysig en/of opvolg, sowel as ander essensieel ekwivalente regte enige plek in die wêreld.

l. __Jy__ beteken die individu of entiteit wat die Gelisensieerde Regte uitoefen onder hierdie Openbare Lisensie. Jou het 'n ooreenstemmende betekenis.
## Afdeling 2 - Omvang.

a. ___ Lisensieverlening.___

1. Onderworpe aan die bepalings en voorwaardes van hierdie Openbare Lisensie, verleen die Lisensiehouer hiermee aan U 'n wêreldwye, vry van koninklike regte, nie-onderlisensieerbare, nie-eksklusiewe, onherroeplike lisensie om die Gelisensieerde Regte in die Gelisensieerde Materiaal uit te oefen om:

A. die Gelisensieerde Materiaal, geheel of gedeeltelik, slegs vir Niekommersiële doeleindes te reproduseer en te Deel; en

B. Aangepaste Materiaal te produseer, te reproduseer en te Deel vir Niekommersiële doeleindes slegs.

2. __Uitsluitings en Beperkings.__ Vir die vermyding van twyfel, waar Uitsluitings en Beperkings van toepassing is op U gebruik, is hierdie Openbare Lisensie nie van toepassing nie, en U hoef nie aan sy bepalings en voorwaardes te voldoen nie.

3. __Termyn.__ Die termyn van hierdie Openbare Lisensie word gespesifiseer in Afdeling 6(a).

4. __Media en formate; tegniese wysigings toegelaat.__ Die Lisensiehouer mag U magtig om die Gelisensieerde Regte in alle media en formate, hetsy nou bekend of hierna geskep, uit te oefen, en om tegniese wysigings wat nodig is om dit te doen, aan te bring. Die Lisensiehouer doen afstand van en/of stem in om enige reg of gesag te ontken om U te verbied om tegniese wysigings wat nodig is om die Gelisensieerde Regte uit te oefen, insluitende tegniese wysigings wat nodig is om Effektiewe Tegnologiese Maatreëls te omseil. Vir doeleindes van hierdie Openbare Lisensie, produseer die eenvoudige aanbring van wysigings wat deur hierdie Afdeling 2(a)(4) gemagtig is, nooit Aangepaste Materiaal nie.

5. __Afnemers stroomafwaarts.__

A. __Aanbod van die Lisensiehouer - Gelisensieerde Materiaal.__ Elke ontvanger van die Gelisensieerde Materiaal ontvang outomaties 'n aanbod van die Lisensiehouer om die Gelisensieerde Regte uit te oefen onder die bepalings en voorwaardes van hierdie Openbare Lisensie.

B. __Geen stroomafwaartse beperkings nie.__ U mag nie enige bykomende of verskillende bepalings of voorwaardes aanbied of afdwing nie, of enige Effektiewe Tegnologiese Maatreëls op die Gelisensieerde Materiaal toepas nie indien dit die uitoefening van die Gelisensieerde Regte deur enige ontvanger van die Gelisensieerde Materiaal beperk nie.

6. __Geen goedkeuring.__ Niks in hierdie Openbare Lisensie vorm of mag beskou word as toestemming om te beweer of te impliseer dat U, of dat U gebruik van die Gelisensieerde Materiaal, verbind is met, of geborg, ondersteun, of amptelike status verleen is deur, die Lisensiehouer of ander wat aangewys is om erkenning te ontvang soos voorsien in Afdeling 3(a)(1)(A)(i).

b. ___Ander regte.___

1. Morele regte, soos die reg op integriteit, word nie onder hierdie Openbare Lisensie gelisensieer nie, en ook nie publisiteit, privaatheid, en/of ander soortgelyke persoonlikheidsregte nie; egter, in die mate moontlik, doen die Lisensiehouer afstand van en/of stem in om enige sulke regte wat deur die Lisensiehouer gehou word tot die beperkte mate wat nodig is om U in staat te stel om die Gelisensieerde Regte uit te oefen, maar andersins nie.

2. Patent- en handelsmerkregte word nie onder hierdie Openbare Lisensie gelisensieer nie.

3. In die mate moontlik, doen die Lisensiehouer afstand van enige reg om koninklike gelde van U te eis vir die uitoefening van die Gelisensieerde Regte, hetsy direk of deur 'n innoverende genootskap onder enige vrywillige of afstandbare statutêre of verpligte lisensieskema. In alle ander gevalle behou die Lisensiehouer uitdruklik enige reg voor om sulke koninklike gelde te eis, insluitende wanneer die Gelisensieerde Materiaal gebruik word anders as vir Niekommersiële doeleindes.

## Afdeling 3 - Lisensie Voorwaardes.

U uitoefening van die Gelisensieerde Regte is uitdruklik onderhewig aan die volgende voorwaardes.

a. ___Erkenning.___

1. Indien U die Gelisensieerde Materiaal Deel (insluitend in gewysigde vorm), moet U:

A. die volgende behou indien dit deur die Lisensiehouer saam met die Gelisensieerde Materiaal voorsien word:

i. identifikasie van die skepper(s) van die Gelisensieerde Materiaal en enige ander wat aangewys is om erkenning te ontvang, op enige redelike wyse versoek deur die Lisensiehouer (insluitend per skuilnaam indien aangewys);

ii. 'n kopieregkennisgewing;

iii. 'n kennisgewing wat na hierdie Openbare Lisensie verwys;

iv. 'n kennisgewing wat na die vrywaring van waarborge verwys;

v. 'n URI of hiperkoppeling na die Gelisensieerde Materiaal tot die mate wat redelikerwys moontlik is;

B. aandui indien U die Gelisensieerde Materiaal gewysig het en 'n aanduiding van enige vorige wysigings behou; en

C. aandui dat die Gelisensieerde Materiaal gelisensieer is onder hierdie Openbare Lisensie, en die teks van, of die URI of hiperkoppeling na, hierdie Openbare Lisensie insluit.

2. U kan die voorwaardes in Afdeling 3(a)(1) op enige redelike wyse bevredig gebaseer op die medium, middels, en konteks waarin U die Gelisensieerde Materiaal Deel. Byvoorbeeld, dit mag redelik wees om die voorwaardes te bevredig deur 'n URI of hiperkoppeling na 'n hulpbron te voorsien wat die vereiste inligting insluit.

3. Indien versoek deur die Lisensiehouer, moet U enige van die inligting wat vereis word deur Afdeling 3(a)(1)(A) tot die mate wat redelikerwys moontlik is, verwyder.

4. Indien U Aangepaste Materiaal wat U produseer Deel, moet die Lisensie van die Aanpasser wat U toepas, nie ontvangers van die Aangepaste Materiaal verhoed om aan hierdie Openbare Lisensie te voldoen nie.

## Afdeling 4 - Sui Generis Databasisregte.

Indien die Gelisensieerde Regte Sui Generis Databasisregte insluit wat van toepassing is op U gebruik van die Gelisensieerde Materiaal:

a. vir die vermyding van twyfel, verleen Afdeling 2(a)(1) U die reg om alle of 'n substansiële gedeelte van die inhoud van die databasis vir Niekommersiële doeleindes slegs te onttrek, hergebruik, reproduseer, en Deel;

b. indien U alle of 'n substansiële gedeelte van die databasisinhoud insluit in 'n databasis waarin U Sui Generis Databasisregte het, dan is die databasis waarin U Sui Generis Databasisregte het (maar nie sy individuele inhoud) Aangepaste Materiaal; en

c. U moet voldoen aan die voorwaardes in Afdeling 3(a) indien U alle of 'n substansiële gedeelte van die inhoud van die databasis Deel.

Vir die vermyding van twyfel, vuller hierdie Afdeling 4 aan en vervang nie U verpligtinge onder hierdie Openbare Lisensie waar die Gelisensieerde Regte ander Kopiereg- en Soortgelyke Regte insluit.

## Afdeling 5 - Vrywaring van Waarborg en Beperking van Aanspreeklikheid.

a. __Tensy andersins afsonderlik aangegaan deur die Lisensiehouer, bied die Lisensiehouer die Gelisensieerde Materiaal aan soos dit is en beskikbaar is, en maak geen verteenwoordigings of waarborge van enige aard oor die Gelisensieerde Materiaal nie, hetsy uitdruklik, geïmpliseer, statutêr, of andersins. Dit sluit, sonder beperking, waarborge van titel, verhandelbaarheid, geskiktheid vir 'n bepaalde doel, nie-skending, afwesigheid van latente of ander foute, akkuraatheid, of die teenwoordigheid of afwesigheid van foute, of dit bekend is of ontdek kan word. Waar waarborgontkenning nie heeltemal of gedeeltelik toegelaat word nie, mag hierdie waarborgontkenning nie op U van toepassing wees nie.__

b. __In geen geval sal die Lisensiehouer aanspreeklik wees teenoor U op enige regsteorie (insluitend, sonder beperking, nalatigheid) of andersins vir enige direkte, spesiale, indirekte, insidentele, gevolglike, strafregtelike, voorbeeldige, of ander verliese, koste, uitgawes, of skade wat voortspruit uit hierdie Openbare Lisensie of die gebruik van die Gelisensieerde Materiaal, selfs indien die Lisensiehouer in kennis gestel is van die moontlikheid van sulke verliese, koste, uitgawes, of skade. Waar 'n aanspreeklikheidsbeperking nie heeltemal of gedeeltelik toegelaat word nie, mag hierdie beperking nie op U van toepassing wees nie.__

c. Die waarborgontkenning en aanspreeklikheidsbeperking hierbo verskaf moet geïnterpreteer word op 'n wyse wat, in die mate moontlik, die naaste aan 'n absolute waarborgontkenning en afstand van alle aanspreeklikheid benader.

## Afdeling 6 - Termyn en Beëindiging.

a. Hierdie Openbare Lisensie is van toepassing vir die termyn van die Kopiereg- en Soortgelyke Regte wat hier gelisensieer word. Indien U egter nie aan hierdie Openbare Lisensie voldoen nie, verval U regte ingevolge hierdie Openbare Lisensie outomaties.

b. Waar U reg om die Gelisensieerde Materiaal te gebruik beëindig het ingevolge Afdeling 6(a), word dit herstel:

1. outomaties op die datum waarop die oortreding reggestel is, op voorwaarde dat dit binne 30 dae na U ontdekking van die oortreding reggestel word; of

2. op uitdruklike herstel deur die Lisensiehouer.

Vir die vermyding van twyfel, hierdie Afdeling 6(b) beïnvloed nie enige reg wat die Lisensiehouer mag hê om remedies te soek vir U oortredings van hierdie Openbare Lisensie nie.

c. Vir die vermyding van twyfel, mag die Lisensiehouer ook die Gelisensieerde Materiaal aanbied onder afsonderlike bepalings of voorwaardes of ophou om die Gelisensieerde Materiaal op enige tyd te versprei; egter, om dit te doen, sal hierdie Openbare Lisensie nie beëindig nie.

d. Afdelings 1, 5, 6, 7, en 8 oorleef die beëindiging van hierdie Openbare Lisensie.
## Afdeling 7 - Ander Voorwaardes en Kondisies.

a. Die Lisensiehouer sal nie gebonde wees aan enige bykomende of verskillende terme of kondisies wat deur U gekommunikeer word tensy uitdruklik ooreengekom nie.

b. Enige reëlings, verstandhoudings, of ooreenkomste met betrekking tot die Gelisensieerde Materiaal wat nie hierin vermeld word nie, is afsonderlik van en onafhanklik van die terme en kondisies van hierdie Openbare Lisensie.

## Afdeling 8 - Interpretasie.

a. Vir die vermyding van twyfel, hierdie Openbare Lisensie verminder nie, en mag nie geïnterpreteer word om, enige beperkinge, beperkings, of voorwaardes op te lê op enige gebruik van die Gelisensieerde Materiaal wat wettiglik gemaak kan word sonder toestemming onder hierdie Openbare Lisensie nie.

b. Vir sover moontlik, indien enige bepaling van hierdie Openbare Lisensie as onafdwingbaar beskou word, sal dit outomaties hervorm word tot die minimum om dit afdwingbaar te maak. Indien die bepaling nie hervorm kan word nie, sal dit uit hierdie Openbare Lisensie geskei word sonder om die afdwingbaarheid van die oorblywende terme en kondisies te beïnvloed.

c. Geen term of voorwaarde van hierdie Openbare Lisensie sal opgehef word nie en geen versuim om te voldoen sal toegelaat word tensy uitdruklik ooreengekom deur die Lisensiehouer.

d. Niks in hierdie Openbare Lisensie vorm of mag geïnterpreteer word as 'n beperking op, of afstand van, enige voorregte en immuniteite wat van toepassing is op die Lisensiehouer of U nie, insluitend van die regsprosesse van enige jurisdiksie of gesag.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
{% hint style="success" %}
Leer & oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
