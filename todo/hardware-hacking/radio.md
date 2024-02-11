# Radio

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)is 'n gratis digitale seinanaliseerder vir GNU/Linux en macOS, ontwerp om inligting van onbekende radiosignale te onttrek. Dit ondersteun 'n verskeidenheid SDR-toestelle deur SoapySDR, en maak verstelbare demodulasie van FSK-, PSK- en ASK-signale moontlik, ontsifreer analoogvideo, analiseer stootsgewyse seine en luister na analoogstemkanale (alles in werklike tyd).

### Basiese konfigurasie

Nadat dit geïnstalleer is, is daar 'n paar dinge wat jy kan oorweeg om te konfigureer.\
In die instellings (die tweede tabbladknoppie) kan jy die **SDR-toestel** kies of 'n **lêer kies** om te lees en watter frekwensie om te sinchroniseer en die monsterfrekwensie (aanbeveel tot 2.56Msps as jou rekenaar dit ondersteun)\\

![](<../../.gitbook/assets/image (655) (1).png>)

In die GUI-gedrag word dit aanbeveel om 'n paar dinge te aktiveer as jou rekenaar dit ondersteun:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
As jy besef dat jou rekenaar nie dinge vasvang nie, probeer om OpenGL uit te skakel en die monsterfrekwensie te verlaag.
{% endhint %}

### Gebruike

* Net om 'n tydperk van 'n sein vas te vang en dit te analiseer, hou die knoppie "Druk om vas te vang" so lank as wat jy nodig het.

![](<../../.gitbook/assets/image (631).png>)

* Die **Tuner** van SigDigger help om **betere seine vas te vang** (maar dit kan dit ook verswak). Begin idealiter met 0 en maak dit groter totdat jy vind dat die geraas wat ingevoer word, groter is as die verbetering van die sein wat jy nodig het).

![](<../../.gitbook/assets/image (658).png>)

### Sinchroniseer met radiokanaal

Met [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sinchroniseer met die kanaal wat jy wil hoor, konfigureer die "Baseband-audiovoorbeeld" opsie, konfigureer die bandwydte om al die inligting wat gestuur word, te kry en stel dan die Tuner in op die vlak voordat die geraas regtig begin toeneem:

![](<../../.gitbook/assets/image (389).png>)

## Interessante truuks

* Wanneer 'n toestel stote van inligting stuur, sal die **eerste deel waarskynlik 'n preambule wees**, sodat jy **nie hoef te bekommer nie** as jy **nie inligting daar vind nie** of as daar foute is.
* In inligtingsrame moet jy gewoonlik **verskillende rame vind wat goed uitgelyn is**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Nadat jy die bits herstel het, moet jy dit dalk op een of ander manier verwerk**. Byvoorbeeld, in Manchester-kodering sal 'n op+af 'n 1 of 0 wees en 'n af+op sal die ander wees. So pare van 1's en 0's (op en af) sal 'n werklike 1 of 'n werklike 0 wees.
* Selfs as 'n sein Manchester-kodering gebruik (dit is onmoontlik om meer as twee 0's of 1's agter mekaar te vind), kan jy **veral 1's of 0's saam in die preambule vind**!

### Ontdek modulasietipe met IQ

Daar is 3 maniere om inligting in seine te stoor: Deur die **amplitude**, **frekwensie** of **fase** te moduleer.\
As jy 'n sein ondersoek, is daar verskillende maniere om te probeer uitvind wat gebruik word om inligting te stoor (vind meer maniere hieronder), maar 'n goeie een is om na die IQ-grafiek te kyk.

![](<../../.gitbook/assets/image (630).png>)

* **AM opspoor**: As daar byvoorbeeld in die IQ-grafiek **2 sirkels** verskyn (waarskynlik een by 0 en die ander by 'n verskillende amplitude), kan dit beteken dat dit 'n AM-sein is. Dit is omdat in die IQ-grafiek die afstand tussen die 0 en die sirkel die amplitude van die sein is, so dit is maklik om verskillende amplitudes te visualiseer wat gebruik word.
* **PM opspoor**: Soos in die vorige prentjie, as jy klein sirkels vind wat nie met mekaar verband hou nie, beteken dit waarskynlik dat 'n fase-modulasie gebruik word. Dit is omdat in die IQ-grafiek die hoek tussen die punt en die 0,0 die fase van die sein is, so dit beteken dat 4 verskillende fases gebruik word.
* Let daarop dat as die inligting weggesteek is in die feit dat 'n fase verander en nie in die fase self nie, sal jy nie verskillende fases duidelik onderskei nie.
* **FM opspoor**: IQ het nie 'n veld om frekwensies te identifiseer (afstand tot sentrum is amplitude en hoek is fase).\
Daarom moet jy om FM te identifiseer **basies net 'n sirkel sien** in hierdie grafiek.\
Verder word 'n verskillende frekwensie "voorgestel" deur die IQ-grafiek deur 'n **spoedversnelling oor die sirkel** (so in SysDigger, as jy die sein kies, word die IQ-grafiek gevul, as jy 'n versnelling of verandering van rigting in die geskepte sirkel vind, kan dit beteken dat dit FM is):

## AM-voorbeeld

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AM ontbloot

#### Die omslag nagaan

Deur AM-inligting met [**SigDigger** ](https://github.com/BatchDrake/SigDigger)te ondersoek en net na die **omslag** te kyk, kan jy verskillende duidelike amplitudevlakke sien. Die gebruikte sein stuur pulsskote met inligting in AM, so lyk een puls:

![](<../../.gitbook/assets/image (636).png>)

En so lyk 'n deel van die simbool met die golfvorm:

![](<../../.gitbook/assets/image (650) (1).png>)

#### Die histogram nagaan

Jy kan die **hele sein** waarin die inligting geleë is, kies, kies **Amplitude**-modus en **Selection** en klik op **Histogram**. Jy kan sien dat daar slegs 2 duidelike vlakke gevind word

![](<../../.gitbook/assets/image (647) (1) (1).png>)

Byvoorbeeld, as jy Frekwensie in pla
#### Met IQ

In hierdie voorbeeld kan jy sien hoe daar 'n **groot sirkel** is, maar ook **baie punte in die middel**.

![](<../../.gitbook/assets/image (640).png>)

### Kry Simboolsnelheid

#### Met een simbool

Kies die kleinste simbool wat jy kan vind (sodat jy seker is dis net 1) en kyk na die "Selection freq". In hierdie geval sal dit 1.013kHz wees (dus 1kHz).

![](<../../.gitbook/assets/image (638) (1).png>)

#### Met 'n groep simbole

Jy kan ook aandui hoeveel simbole jy gaan kies en SigDigger sal die frekwensie van 1 simbool bereken (hoe meer simbole gekies word, hoe beter waarskynlik). In hierdie scenario het ek 10 simbole gekies en die "Selection freq" is 1.004 Khz:

![](<../../.gitbook/assets/image (635).png>)

### Kry Bits

Nadat jy gevind het dat dit 'n **AM-gemoduleerde** sein is en die **simboolsnelheid** (en wetende dat in hierdie geval iets bo beteken 1 en iets onder beteken 0), is dit baie maklik om die **bits** wat in die sein gekodeer is, te **kry**. Kies dus die sein met inligting en stel die bemonstering en besluitneming in en druk op bemonstering (kontroleer dat **Amplitude** gekies is, die ontdekte **Simboolsnelheid** ingestel is en die **Gadner-klokherstel** gekies is):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sync to selection intervals** beteken dat as jy voorheen intervals gekies het om die simboolsnelheid te vind, daardie simboolsnelheid gebruik sal word.
* **Manual** beteken dat die aangeduide simboolsnelheid gebruik sal word
* In **Fixed interval selection** dui jy die aantal intervals aan wat gekies moet word en dit bereken die simboolsnelheid daaruit
* **Gadner-klokherstel** is gewoonlik die beste opsie, maar jy moet steeds 'n benaderde simboolsnelheid aandui.

Deur op bemonstering te druk, verskyn dit:

![](<../../.gitbook/assets/image (659).png>)

Nou, om SigDigger te laat verstaan **waar die reeks** van die vlak wat inligting dra, is, moet jy op die **laer vlak** klik en dit vasgehou hou tot by die grootste vlak:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

As daar byvoorbeeld **4 verskillende vlakke van amplitude** was, sou jy die **Bits per simbool to 2** moes instel en van die kleinste tot die grootste kies.

Uiteindelik, deur die **Zoom te verhoog** en die **Ry-grootte te verander**, kan jy die bits sien (en jy kan alles kies en kopieer om al die bits te kry):

![](<../../.gitbook/assets/image (649) (1).png>)

As die sein meer as 1 bit per simbool het (byvoorbeeld 2), het SigDigger **geen manier om te weet watter simbool** 00, 01, 10, 11 is nie, dus sal dit verskillende **gryskaal** gebruik om elkeen voor te stel (en as jy die bits kopieer, sal dit **getalle van 0 tot 3** gebruik, jy sal hulle moet hanteer).

Gebruik ook **koderings** soos **Manchester**, en **op+af** kan **1 of 0** wees en 'n af+op kan 'n 1 of 0 wees. In daardie gevalle moet jy die verkryde op's (1) en af's (0) **hanteer om die pare 01 of 10 as 0's of 1's te vervang**.

## FM Voorbeeld

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FM Ontbloot

#### Kontroleer die frekwensies en golfvorm

Voorbeeldsein wat inligting gestuur word deur middel van FM-gemoduleerde sein:

![](<../../.gitbook/assets/image (661) (1).png>)

In die vorige beeld kan jy redelik goed sien dat **2 frekwensies gebruik word**, maar as jy na die **golfvorm** kyk, sal jy dalk **nie in staat wees om die 2 verskillende frekwensies korrek te identifiseer** nie:

![](<../../.gitbook/assets/image (653).png>)

Dit is omdat ek die sein in beide frekwensies vasgevang het, dus is een ongeveer die ander in negatief:

![](<../../.gitbook/assets/image (656).png>)

As die gesinkroniseerde frekwensie **nader aan een frekwensie as aan die ander** is, kan jy maklik die 2 verskillende frekwensies sien:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Kontroleer die histogram

Deur die frekwensiehistogram van die sein met inligting te kontroleer, kan jy maklik 2 verskillende seine sien:

![](<../../.gitbook/assets/image (657).png>)

In hierdie geval sal jy, as jy die **Amplitudehistogram** kontroleer, **slegs een amplitude** vind, dus **kan dit nie AM wees nie** (as jy baie amplitudes vind, kan dit wees omdat die sein krag verloor het langs die kanaal):

![](<../../.gitbook/assets/image (646).png>)

En dit sou die fasehistogram wees (wat baie duidelik maak dat die sein nie in fase gemoduleer is nie):

![](<../../.gitbook/assets/image (201) (2).png>)

#### Met IQ

IQ het nie 'n veld om frekwensies te identifiseer nie (afstand tot sentrum is amplitude en hoek is fase).\
Daarom, om FM te identifiseer, moet jy in hierdie grafiek **basies net 'n sirkel sien**.\
Verder word 'n verskillende frekwensie "voorgestel" deur die IQ-grafiek deur 'n **spoedversnelling oor die sirkel** (so in SysDigger, as jy die sein kies, word die IQ-grafiek gevul, as jy 'n versnelling of verandering van rigting in die geskepte sirkel vind, kan dit beteken dat dit FM is):

![](<../../.gitbook/assets/image (643) (1).png>)

### Kry Simboolsnelheid

Jy kan dieselfde tegniek gebruik as die een wat in die AM-voorbeeld gebruik is om die simboolsnelheid te kry nadat jy die frekwensies wat simbole dra, gevind het.

### Kry Bits

Jy kan dieselfde tegniek gebruik as die een wat in die AM-voorbeeld gebruik is om die bits te kry nadat jy gevind het dat die sein in frekwensie gemoduleer is en die simboolsnelheid.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
