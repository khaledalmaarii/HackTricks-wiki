# Sub-GHz RF

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Motorhuis Deure

Motorhuisdeuropeners werk tipies op frekwensies in die 300-190 MHz-reeks, met die mees algemene frekwensies wat 300 MHz, 310 MHz, 315 MHz en 390 MHz is. Hierdie frekwensiereeks word dikwels gebruik vir motorhuisdeuropeners omdat dit minder besig is as ander frekwensiebande en minder waarskynlik is om interferensie van ander toestelle te ervaar.

## Motorvoertuig Deure

Die meeste motor sleutel fobs werk op entoesias 315 MHz of 433 MHz. Dit is beide radiofrekwensies, en hulle word in 'n verskeidenheid verskillende toepassings gebruik. Die grootste verskil tussen die twee frekwensies is dat 433 MHz 'n langer reikwydte as 315 MHz het. Dit beteken dat 433 MHz beter is vir toepassings wat 'n langer reikwydte vereis, soos afstandbeheerde sleutellose toegang.\
In Europa word 433.92MHz algemeen gebruik en in die V.S. en Japan is dit die 315MHz.

## **Brute-krag Aanval**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

As jy in plaas daarvan elke kode 5 keer stuur (soos dit gestuur word om seker te maak dat die ontvanger dit kry) dit net een keer stuur, word die tyd verminder tot 6 minute:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

en as jy **die 2 ms wagperiode tussen seine verwyder** kan jy die tyd tot 3 minute **verminder**.

Verder, deur die De Bruijn-sekwensie te gebruik ( 'n manier om die aantal bits wat nodig is om al die potensiële binêre getalle te stuur om te krag te verminder) word hierdie **tyd net tot 8 sekondes verminder**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Voorbeeld van hierdie aanval is geïmplementeer in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Die **vereiste van 'n preamble sal die De Bruijn-sekwensie**-optimalisering vermy en **rollende kodes sal hierdie aanval voorkom** (onder die aanname dat die kode lank genoeg is om nie te kragbaar te wees nie).

## Sub-GHz Aanval

Om hierdie seine met Flipper Zero aan te val, kyk na:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Rollende Kodes Beskerming

Outomatiese motorhuisdeuropeners gebruik tipies 'n draadlose afstandbeheer om die motorhuisdeur oop en toe te maak. Die afstandbeheer **stuur 'n radiofrekwensie (RF) sein** na die motorhuisdeuropener, wat die motor aktiveer om die deur oop of toe te maak.

Dit is moontlik vir iemand om 'n toestel genaamd 'n kodegrabbelaar te gebruik om die RF-sein te onderskep en dit vir latere gebruik op te neem. Dit staan bekend as 'n **herhaalaanval**. Om hierdie tipe aanval te voorkom, gebruik baie moderne motorhuisdeuropeners 'n meer veilige versleutelingsmetode wat bekend staan as 'n **rollende kode**-sisteem.

Die **RF-sein word tipies oorgedra deur 'n rollende kode**, wat beteken dat die kode met elke gebruik verander. Dit maak dit **moeilik** vir iemand om die sein te **onderskep** en dit te gebruik om **onbevoegde** toegang tot die motorhuis te verkry.

In 'n rollende kode-sisteem het die afstandbeheer en die motorhuisdeuropener 'n **gesamentlike algoritme** wat elke keer 'n nuwe kode **genereer wanneer die afstandbeheer gebruik word**. Die motorhuisdeuropener sal slegs reageer op die **korrekte kode**, wat dit baie moeiliker maak vir iemand om onbevoegde toegang tot die motorhuis te verkry deur net 'n kode vas te vang.

### **Ontbrekende Skakel Aanval**

Basies, jy luister vir die knoppie en **vang die sein terwyl die afstandbeheer buite die reikwydte** van die toestel is (sê die motor of motorhuis). Jy beweeg dan na die toestel en **gebruik die vasgevangde kode om dit oop te maak**.

### Volle Skakel Stoorsignaal Aanval

'n Aanvaller kan die sein naby die voertuig of ontvanger **stoorsignaal** sodat die **ontvanger eintlik nie die kode kan 'hoor' nie**, en sodra dit gebeur kan jy eenvoudig die kode **vasvang en herhaal** wanneer jy ophou met stoorsignaal.

Die slagoffer sal op 'n stadium die **sleutels gebruik om die motor te sluit**, maar dan sal die aanval genoeg "sluit deur" kodes opgeneem het wat hopelik weer gestuur kan word om die deur oop te maak ( 'n **frekwensieverandering mag nodig wees** aangesien daar motors is wat dieselfde kodes gebruik om oop en toe te maak, maar luister na beide bevele in verskillende frekwensies).

{% hint style="warning" %}
**Stoorsignaal werk**, maar dit is opvallend as die **persoon wat die motor sluit eenvoudig die deure toets** om te verseker dat hulle gesluit is, sal hulle agterkom dat die motor oop is. Daarbenewens, as hulle bewus was van sulke aanvalle, kon hulle selfs luister na die feit dat die deure nooit die sluit **geluid** gemaak het of die motor se **ligte** nooit geflits het toe hulle die ‘sluit’-knoppie gedruk het.
{% endhint %}

### **Kodegrabbelaanval (ook bekend as ‘RollJam’)**

Dit is 'n meer **steels Stoorsignaal tegniek**. Die aanvaller sal die sein stoorsignaal, sodat wanneer die slagoffer probeer om die deur te sluit, dit nie sal werk nie, maar die aanvaller sal **hierdie kode opneem**. Dan sal die slagoffer **weer probeer om die motor te sluit** deur op die knoppie te druk en die motor sal **hierdie tweede kode opneem**.\
Onmiddellik hierna kan die **aanvaller die eerste kode stuur** en die **motor sal sluit** (die slagoffer sal dink die tweede druk het dit gesluit). Dan sal die aanvaller in staat wees om die tweede gesteelde kode te **stuur om die motor oop te maak** (onder die aanname dat 'n **"sluit motor" kode ook gebruik kan word om dit oop te maak**). 'n Frekwensieverandering mag nodig wees (aangesien daar motors is wat dieselfde kodes gebruik om oop en toe te maak, maar luister na beide bevele in verskillende frekwensies).

Die aanvaller kan **die motorontvanger stoorsignaal en nie sy ontvanger** nie omdat as die motorontvanger byvoorbeeld in 'n 1MHz-breedband luister, sal die aanvaller nie **die presiese frekwensie wat deur die afstandbeheer gebruik word nie** stoorsignaal nie, maar **'n naby een in daardie spektrum** terwyl die **aanvaller se ontvanger in 'n kleiner reeks sal luister** waar hy die afstandbeheersein kan hoor **sonder die stoorsignaal**.

{% hint style="warning" %}
Ander implementasies wat in spesifikasies gesien word, wys dat die **rollende kode 'n gedeelte** van die totale kode wat gestuur word. Dit wil sê die kode wat gestuur word is 'n **24-bit sleutel** waarvan die eerste **12 die rollende kode is**, die **tweede 8 is die bevel** (soos sluit of maak oop) en die laaste 4 is die **kontrolesom**. Voertuie wat hierdie tipe implementeer, is ook natuurlik vatbaar omdat die aanvaller bloot die rollende kode-segment hoef te vervang om in staat te wees om **enige rollende kode op beide frekwensies te gebruik**.
{% endhint %}

{% hint style="danger" %}
Let daarop dat as die slagoffer 'n derde kode stuur terwyl die aanvaller die eerste een stuur, sal die eerste en tweede kode ongeldig wees.
{% endhint %}
### Alarm Sounding Jamming Attack

Die toetsing teen 'n aftermarket rollende kode-sisteem wat op 'n motor geïnstalleer is, **deur dieselfde kode twee keer te stuur** het dadelik die alarm en immobiliseerder geaktiveer wat 'n unieke **ontkenning van diens**-geleentheid bied. Ironies genoeg was die manier om die alarm en immobiliseerder te **deaktiveer** om die **afstandbeheer** te **druk**, wat 'n aanvaller die vermoë gee om **voortdurend 'n DoS-aanval uit te voer**. Of meng hierdie aanval met die **vorige een om meer kodes te verkry** aangesien die slagoffer graag die aanval so spoedig moontlik wil stop.

## Verwysings

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
