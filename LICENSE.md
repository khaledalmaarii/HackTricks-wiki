<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Kopiereg © Carlos Polop 2021. Behalwe waar anders gespesifiseer (die eksterne inligting wat in die boek gekopieer is, behoort aan die oorspronklike outeurs), is die teks op <a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a> deur Carlos Polop gelisensieer onder die <a href="https://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)</a>.

Lisensie: Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)<br>
Mensleesbare Lisensie: https://creativecommons.org/licenses/by-nc/4.0/<br>
Volledige Regsterme: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
Formattering: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# kreatiewe gemeenskap

# Attribution-NonCommercial 4.0 International

Creative Commons Corporation ("Creative Commons") is nie 'n regspraktyk nie en verskaf nie regsadvies of regsdiens nie. Verspreiding van Creative Commons openbare lisensies skep nie 'n regsverhouding tussen regspraktisyn en kliënt of enige ander verhouding nie. Creative Commons maak sy lisensies en verwante inligting beskikbaar "soos dit is". Creative Commons gee geen waarborge met betrekking tot sy lisensies, enige materiaal wat onder die voorwaardes daarvan gelisensieer is, of enige verwante inligting nie. Creative Commons verwerp alle aanspreeklikheid vir skade wat voortspruit uit die gebruik daarvan tot die volle omvang moontlik.

## Gebruik van Creative Commons Openbare Lisensies

Creative Commons openbare lisensies bied 'n standaardstel voorwaardes wat skeppers en ander reghebbendes kan gebruik om oorspronklike werke van outeurskap en ander materiaal wat onderhewig is aan kopiereg en sekere ander regte soos gespesifiseer in die openbare lisensie hieronder, te deel. Die volgende oorwegings is slegs vir inligtingsdoeleindes, is nie uitputtend nie, en vorm nie deel van ons lisensies nie.

* __Oorwegings vir lisensiegevers:__ Ons openbare lisensies is bedoel vir gebruik deur diegene wat gemagtig is om die publiek toestemming te gee om materiaal op maniere te gebruik wat andersins deur kopiereg en sekere ander regte beperk word. Ons lisensies is onherroeplik. Lisensiegevers moet die terme en voorwaardes van die lisensie wat hulle kies, lees en verstaan voordat hulle dit toepas. Lisensiegevers moet ook alle regte verseker voordat hulle ons lisensies toepas, sodat die publiek die materiaal kan hergebruik soos verwag. Lisensiegevers moet enige materiaal wat nie onderhewig is aan die lisensie nie, duidelik merk. Dit sluit ander CC-gelisensieerde materiaal in, of materiaal wat onder 'n uitsondering of beperking tot kopiereg gebruik word. [Meer oorwegings vir lisensiegevers](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __Oorwegings vir die publiek:__ Deur een van ons openbare lisensies te gebruik, gee 'n lisensiegever die publiek toestemming om die gelisensieerde materiaal te gebruik onder gespesifiseerde terme en voorwaardes. As die toestemming van die lisensiegever nie nodig is om enige rede nie – byvoorbeeld as gevolg van enige toepaslike uitsondering of beperking tot kopiereg – word daardie gebruik nie deur die lisensie gereguleer nie. Ons lisensies verleen slegs toestemmings onder kopiereg en sekere ander regte waaroor 'n lisensiegever magtig is om toestemming te gee. Die gebruik van die gelisensieerde materiaal kan nog steeds beperk word om ander redes, insluitend omdat ander kopiereg of ander regte in die materiaal het. 'n Lisensiegever mag spesiale versoeke maak, soos om te vra dat alle veranderinge gemerk of beskryf word. Alhoewel dit nie deur ons lisensies vereis word nie, word jy aangemoedig om daardie versoeke te respekteer waar dit redelik is. [Meer oorwegings vir die publiek](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# Creative Commons Attribution-NonCommercial 4.0 International Openbare Lisensie

Deur die Gelisensieerde Regte (hieronder gedefinieer) uit te oefen, aanvaar en stem jy in om gebonde te wees aan die terme en voorwaardes van hierdie Creative Commons Attribution-NonCommercial 4.0 International Openbare Lisensie ("Openbare Lisensie"). Vir sover hierdie Openbare Lisensie as 'n kontrak geïnterpreteer kan word, word die Gelisensieerde Regte aan jou verleen in oorweging van jou aanvaarding van hierdie terme en voorwaardes, en die Lisensiegever verleen jou sulke regte in oorweging van die voordele wat die Lisensiegever ontvang deur die Gelisensieerde Materiaal beskikbaar te stel onder hierdie terme en voorwaardes.

## Artikel 1 – Definisies.

a. __Aangepaste Materiaal__ beteken materiaal wat onderhewig is aan Kopiereg en Soortgelyke Regte en wat afgelei is van of gebaseer is op die Gelisensieerde Materiaal en waarin die Gelisensieerde Materiaal vertaal, verander, gereël, verander, of andersins gewysig word op 'n wyse wat toestemming vereis onder die Kopiereg en Soortgelyke Regte wat deur die Lisensiegever gehou word. Vir doeleindes van hierdie Openbare Lisensie word Aangepaste Materiaal altyd geproduseer waar die Gelisensieerde Materiaal gesinkroniseer word met 'n bewegende beeld.

b. __Lisensie van die Aanpasser__ beteken die lisensie wat jy toepas op jou Kopiereg en Soortgelyke Regte in jou bydraes tot Aangepaste Materiaal in ooreenstem
## Artikel 2 - Omvang.

a. ___Lisensieverlening.___

1. Onderworpe aan die bepalings en voorwaardes van hierdie Openbare Lisensie, verleen die Lisensiehouer hiermee aan U 'n wêreldwye, vry van lisensiefooi, nie-onderlisensieerbare, nie-uitsluitlike, onherroeplike lisensie om die Gelisensieerde Regte in die Gelisensieerde Materiaal uit te oefen om:

A. die Gelisensieerde Materiaal, geheel of gedeeltelik, vir nie-kommersiële doeleindes slegs te verveelvoudig en te deel; en

B. Aangepaste Materiaal te produseer, te verveelvoudig en te deel vir nie-kommersiële doeleindes slegs.

2. __Uitsonderings en Beperkings.__ Vir die vermyding van twyfel, waar Uitsonderings en Beperkings van toepassing is op U gebruik, is hierdie Openbare Lisensie nie van toepassing nie, en U hoef nie aan sy bepalings en voorwaardes te voldoen nie.

3. __Termyn.__ Die termyn van hierdie Openbare Lisensie word gespesifiseer in Artikel 6(a).

4. __Media en formate; tegniese wysigings toegelaat.__ Die Lisensiehouer gee U toestemming om die Gelisensieerde Regte in alle media en formate uit te oefen, hetsy nou bekend of hierna geskep, en om tegniese wysigings te maak wat nodig is om dit te doen. Die Lisensiehouer doen afstand van en/of stem daarmee saam om enige reg of gesag te ontken om U te verbied om tegniese wysigings te maak wat nodig is om die Gelisensieerde Regte uit te oefen, insluitend tegniese wysigings wat nodig is om Effektiewe Tegnologiese Maatreëls te omseil. Vir doeleindes van hierdie Openbare Lisensie, produseer die eenvoudige maak van wysigings wat deur hierdie Artikel 2(a)(4) gemagtig word nooit Aangepaste Materiaal nie.

5. __Ontvangers van stroomaf.__

A. __Aanbod van die Lisensiehouer - Gelisensieerde Materiaal.__ Elke ontvanger van die Gelisensieerde Materiaal ontvang outomaties 'n aanbod van die Lisensiehouer om die Gelisensieerde Regte uit te oefen onder die bepalings en voorwaardes van hierdie Openbare Lisensie.

B. __Geen stroomafbeperkings nie.__ U mag geen addisionele of verskillende terme of voorwaardes aanbied of opleg op die Gelisensieerde Materiaal nie, as dit die uitoefening van die Gelisensieerde Regte deur enige ontvanger van die Gelisensieerde Materiaal beperk nie.

6. __Geen goedkeuring.__ Niks in hierdie Openbare Lisensie stel of mag beskou word as toestemming om te beweer of te impliseer dat U, of dat U gebruik van die Gelisensieerde Materiaal, verband hou met, of gesponsoreer, ondersteun, of amptelike status verleen deur, die Lisensiehouer of ander persone wat aangewys is om erkenning te ontvang soos voorsien in Artikel 3(a)(1)(A)(i).

b. ___Ander regte.___

1. Morele regte, soos die reg op integriteit, word nie onder hierdie Openbare Lisensie gelisensieer nie, en ook nie publisiteit, privaatheid, en/of ander soortgelyke persoonlikheidsregte nie; egter, vir sover moontlik, doen die Lisensiehouer afstand van en/of stem daarmee saam om enige sulke regte wat deur die Lisensiehouer gehou word, tot die beperkte mate wat nodig is om U in staat te stel om die Gelisensieerde Regte uit te oefen, maar andersins nie.

2. Patent- en handelsmerkregte word nie onder hierdie Openbare Lisensie gelisensieer nie.

3. Vir sover moontlik, doen die Lisensiehouer afstand van enige reg om koninklike te erf van U vir die uitoefening van die Gelisensieerde Regte, hetsy direk of deur 'n inwinninggenootskap onder enige vrywillige of afstanddoenbare statutêre of verpligte lisensiëringskema. In alle ander gevalle behou die Lisensiehouer uitdruklik enige reg voor om sulke koninklike in te samel, insluitend wanneer die Gelisensieerde Materiaal gebruik word vir nie-kommersiële doeleindes nie.

## Artikel 3 - Lisensievoorwaardes.

U uitoefening van die Gelisensieerde Regte is uitdruklik onderhewig aan die volgende voorwaardes.

a. ___Toekennings.___

1. As U die Gelisensieerde Materiaal deel (insluitend in gewysigde vorm), moet U:

A. die volgende behou as dit deur die Lisensiehouer saam met die Gelisensieerde Materiaal voorsien word:

i. identifikasie van die skepper(s) van die Gelisensieerde Materiaal en enige ander persone wat aangewys is om erkenning te ontvang, op enige redelike wyse wat deur die Lisensiehouer versoek word (insluitend deur skuilnaam as dit aangewys word);

ii. 'n kopieregkennisgewing;

iii. 'n kennisgewing wat na hierdie Openbare Lisensie verwys;

iv. 'n kennisgewing wat na die vrywaring van waarborge verwys;

v. 'n URI of skakel na die Gelisensieerde Materiaal, vir sover dit redelik uitvoerbaar is;

B. aandui of U die Gelisensieerde Materiaal gewysig het en 'n aanduiding van enige vorige wysigings behou; en

C. aandui dat die Gelisensieerde Materiaal gelisensieer is onder hierdie Openbare Lisensie, en die teks van, of die URI of skakel na, hierdie Openbare Lisensie insluit.

2. U kan aan die voorwaardes in Artikel 3(a)(1) voldoen op enige redelike wyse gebaseer op die medium, middels, en konteks waarin U die Gelisensieerde Materiaal deel. Byvoorbeeld, dit mag redelik wees om aan die voorwaardes te voldoen deur 'n URI of skakel na 'n hulpbron te voorsien wat die vereiste inligting insluit.

3. Indien versoek deur die Lisensiehouer, moet U enige van die inligting wat vereis word deur Artikel 3(a)(1)(A) verwyder, vir sover dit redelik uitvoerbaar is.

4. As U Aangepaste Materiaal wat U produseer deel, mag die Lisensie van die Aanpasser wat U toepas, nie ontvangers van die Aangepaste Materiaal verhoed om aan hierdie Openbare Lisensie te voldoen nie.

## Artikel 4 - Sui Generis Databasisregte.

Waar die Gelisensieerde Regte Sui Generis Databasisregte insluit wat van toepassing is op U gebruik van die Gelisensieerde Materiaal:

a. vir die vermyding van twyfel, verleen Artikel 2(a)(1) U die reg om al of 'n aansienlike gedeelte van die inhoud van die databasis te onttrek, hergebruik, verveelvoudig, en te deel vir nie-kommersiële doeleindes slegs;

b. as U al of 'n aansienlike gedeelte van die inhoud van die databasis insluit in 'n databasis waarin U Sui Generis Databasisregte het, dan is die databasis waarin U Sui Generis Databasisregte het (maar nie sy individuele inhoud nie) Aangepaste Materiaal; en

c. U moet voldoen aan die voorwaardes in Artikel 3(a) as U al of 'n aansienlike gedeelte van die inhoud van die databasis deel.

Vir die vermyding van twyfel, vul
## Artikel 7 - Ander Voorwaardes en Bepalings.

a. Die Lisensiehouer sal nie gebonde wees aan enige bykomende of verskillende terme of voorwaardes wat deur U gekommunikeer word tensy uitdruklik ooreengekom.

b. Enige reëlings, verstandhoudings of ooreenkomste met betrekking tot die Gelisensieerde Materiaal wat nie hierin vermeld word nie, is afsonderlik van en onafhanklik van die terme en voorwaardes van hierdie Openbare Lisensie.

## Artikel 8 - Interpretasie.

a. Ten einde twyfel te voorkom, verminder hierdie Openbare Lisensie nie, en mag nie geïnterpreteer word om, die gebruik van die Gelisensieerde Materiaal te beperk, beperk, beperk of voorwaardes op te lê wat wettiglik sonder toestemming onder hierdie Openbare Lisensie gemaak kan word nie.

b. Vir sover moontlik, as enige bepaling van hierdie Openbare Lisensie as onafdwingbaar beskou word, sal dit outomaties hervorm word tot die minimum mate wat nodig is om dit afdwingbaar te maak. As die bepaling nie hervorm kan word nie, sal dit van hierdie Openbare Lisensie afgesny word sonder om die afdwingbaarheid van die oorblywende terme en voorwaardes te beïnvloed.

c. Geen term of voorwaarde van hierdie Openbare Lisensie sal afgesien word nie en geen versuim om te voldoen sal toegestem word tensy uitdruklik ooreengekom deur die Lisensiehouer.

d. Niks in hierdie Openbare Lisensie stel 'n beperking op, of afstand van, enige voorregte en immuniteite wat van toepassing is op die Lisensiehouer of U nie, insluitend van die regsprosesse van enige jurisdiksie of gesag.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
