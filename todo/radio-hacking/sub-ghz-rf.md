# Sub-GHz RF

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Motorhuisdeure

Motorhuisdeur-oopmakers werk gewoonlik op frekwensies in die 300-190 MHz-reeks, met die mees algemene frekwensies wat 300 MHz, 310 MHz, 315 MHz en 390 MHz is. Hierdie frekwensiereeks word algemeen gebruik vir motorhuisdeur-oopmakers omdat dit minder besig is as ander frekwensiebande en minder waarskynlik is om interferensie van ander toestelle te ondervind.

## Motorvoertuigdeure

Die meeste motorvoertuig-sleutelhangers werk op entoesiasme van **315 MHz of 433 MHz**. Dit is albei radiofrekwensies en word in verskillende toepassings gebruik. Die grootste verskil tussen die twee frekwensies is dat 433 MHz 'n langer reikafstand het as 315 MHz. Dit beteken dat 433 MHz beter is vir toepassings wat 'n langer reikafstand vereis, soos afstandsbediening vir sleutelloze toegang.\
In Europa word 433.92 MHz algemeen gebruik en in die V.S. en Japan is dit 315 MHz.

## **Brute-force-aanval**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

As jy in plaas daarvan elke kode 5 keer stuur (so gestuur om seker te maak dat die ontvanger dit kry), stuur jy dit net een keer, dan word die tyd verminder tot 6 minute:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

en as jy **die 2 ms wagtyd** tussen seine verwyder, kan jy **die tyd tot 3 minute verminder**.

Verder, deur die gebruik van die De Bruijn-sekwensie ( 'n manier om die aantal benodigde bits te verminder om al die potensiële binêre getalle te stuur vir brute force), word hierdie **tyd verminder tot net 8 sekondes**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

'N Voorbeeld van hierdie aanval is geïmplementeer in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Die vereiste van **'n preambule sal die De Bruijn-sekwensie**-optimalisering vermy en **rolkodes sal hierdie aanval voorkom** (onder die aanname dat die kode lank genoeg is om nie brute force te wees nie).

## Sub-GHz-aanval

Om hierdie seine met Flipper Zero aan te val, kyk na:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Rolkodesbeskerming

Outomatiese motorhuisdeur-oopmakers gebruik gewoonlik 'n draadlose afstandsbediening om die motorhuisdeur oop of toe te maak. Die afstandsbediening **stuur 'n radiofrekwensie (RF) sein** na die motorhuisdeur-oopmaker, wat die motor aktiveer om die deur oop of toe te maak.

Dit is moontlik vir iemand om 'n toestel genaamd 'n kodegrabbelaar te gebruik om die RF-sein te onderskep en dit vir latere gebruik op te neem. Dit staan bekend as 'n **herhaalaanval**. Om hierdie tipe aanval te voorkom, gebruik baie moderne motorhuisdeur-oopmakers 'n meer veilige versleutelingsmetode wat bekend staan as 'n **rolkode**-sisteem.

Die **RF-sein word tipies oorgedra deur middel van 'n rolkode**, wat beteken dat die kode met elke gebruik verander. Dit maak dit **moeilik** vir iemand om die sein te **onderskep** en dit te gebruik om **onbevoegde** toegang tot die motorhuis te verkry.

In 'n rolkode-sisteem het die afstandsbediening en die motorhuisdeur-oopmaker 'n **gemeenskaplike algoritme** wat elke keer as die afstandsbediening gebruik word, 'n nuwe kode genereer. Die motorhuisdeur-oopmaker sal slegs op die **korrekte kode** reageer, wat dit baie moeiliker maak vir iemand om onbevoegde toegang tot die motorhuis te verkry deur net 'n kode vas te vang.

### **Ontbrekende skakelaanval**

Basies luister jy vir die knoppie en **vang die sein terwyl die afstandsbediening buite die bereik** van die toestel is (sê die motor of motorhuis). Jy beweeg dan na die toestel en **gebruik die vasgevangde kode om dit oop te maak**.

### Volledige skakelversteuringaanval

'n Aanvaller kan die sein naby die voertuig of ontvanger **versteur** sodat die **ontvanger die kode eintlik nie 'hoor' nie**, en sodra dit gebeur het, kan jy eenvoudig die kode **vasvang en herhaal** wanneer jy ophou versteur.

Die slagoffer sal op 'n stadium die **sleutels gebruik om die motor te sluit**, maar dan sal die aanval genoeg "sluit deur" -kodes opgeneem het wat hopelik weer gestuur kan word om die deur oop te maak ( 'n **frekwensieverandering mag nodig wees** omdat daar motors is wat dieselfde kodes gebruik om oop en toe te maak, maar na beide opdragte in verskillende frekwensies luister).

{% hint style="warning" %}
**Versteuring werk**, maar dit is merkbaar as die **persoon wat die motor sluit eenvoudig die deure toets** om seker te maak dat hulle gesluit is, sal hulle agterkom dat die motor oop is. As hulle bewus was van sulke aanvalle, kon hulle selfs luister na die feit dat die deure nooit die sluit **klank** gemaak het of die motor se **ligte** het nooit geflits toe hulle die 'sluit'-knoppie gedruk het nie.
{% endhint %}

### **Kodegrabbelaanval (ook bekend as 'RollJam')**

Dit is 'n meer **stealth-versteuringstegniek**. Die aanvaller sal die sein versteur, sodat wanneer die slagoffer probeer om die deur te sluit, dit nie sal werk nie, maar die aanvaller sal **hierdie kode opneem**. Dan sal die slagoffer **probeer om die motor weer te sluit** deur op die knoppie te druk en die motor sal **hierdie tweede kode opneem**.\
Onmiddellik hierna kan die **aanvaller die eerste kode stuur** en die **motor sal sluit** (die slagoffer sal dink die tweede druk het dit gesluit). Dan sal die aanvaller in staat wees om die tweede gesteelde kode te stuur om die motor oop
### Alarm Sounding Jamming Aanval

Toetsing teen 'n aftermarket-rolkode-sisteem wat op 'n motor geïnstalleer is, het **die stuur van dieselfde kode twee keer** onmiddellik die alarm en immobiliseerder **geaktiveer**, wat 'n unieke **ontkenning van diens** geleentheid bied. Ironies genoeg was die manier om die alarm en immobiliseerder **uit te skakel** om die **afstandbeheer** te **druk**, wat 'n aanvaller die vermoë gee om **voortdurend 'n DoS-aanval** uit te voer. Of meng hierdie aanval met die **vorige een om meer kodes te verkry**, aangesien die slagoffer graag die aanval so spoedig moontlik wil stop.

## Verwysings

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
