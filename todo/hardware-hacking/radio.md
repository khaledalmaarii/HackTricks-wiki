# Radio

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)is 'n gratis digitale seinanaliseerder vir GNU/Linux en macOS, ontwerp om inligting van onbekende radiosignale te onttrek. Dit ondersteun 'n verskeidenheid SDR-toestelle deur SoapySDR, en maak verstelbare demodulasie van FSK, PSK en ASK seine moontlik, ontsluit analoogvideo, analiseer stootsein en luister na analoogstemkanale (alles in werklike tyd).

### Basiese Konfigurasie

Nadat dit geïnstalleer is, is daar 'n paar dinge wat jy kan oorweeg om te konfigureer.\
In instellings (die tweede lêerknoppie) kan jy die **SDR-toestel** kies of 'n lêer kies om te lees en watter frekwensie om te sintoneer en die monsterkoers (aanbeveel tot 2.56Msps as jou rekenaar dit ondersteun)\\

![](<../../.gitbook/assets/image (245).png>)

In die GUI-gedrag word dit aanbeveel om 'n paar dinge te aktiveer as jou rekenaar dit ondersteun:

![](<../../.gitbook/assets/image (472).png>)

{% hint style="info" %}
As jy besef dat jou rekenaar nie dinge vasvang nie, probeer om OpenGL uit te skakel en die monsterkoers te verlaag.
{% endhint %}

### Gebruike

* Net om **'n tydperk van 'n sein vas te vang en te analiseer** hou net die knoppie "Druk om vas te vang" so lank as wat jy nodig het.

![](<../../.gitbook/assets/image (960).png>)

* Die **Afstemmer** van SigDigger help om **beter seine vas te vang** (maar dit kan dit ook verswak). Dit is ideaal om met 0 te begin en aan te hou **vergroot totdat** jy vind dat die **geraas** wat ingevoer word **groter** is as die **verbetering van die sein** wat jy benodig).

![](<../../.gitbook/assets/image (1099).png>)

### Sinchroniseer met radiokanaal

Met [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sinkroniseer met die kanaal wat jy wil hoor, konfigureer "Basisband-audiovoorskou" opsie, konfigureer die bandwydte om al die inligting wat gestuur word te kry en stel dan die Afstemmer in op die vlak voordat die geraas regtig begin toeneem:

![](<../../.gitbook/assets/image (585).png>)

## Interessante truuks

* Wanneer 'n toestel stote van inligting stuur, is die **eerste deel gewoonlik 'n preambule** sodat jy **nie** hoef te **bekommer** as jy **nie inligting** daarin **vind nie of as daar foute is**.
* Inligtingsrame behoort gewoonlik **verskillende rame goed uitgelyn tussen hulle te vind**:

![](<../../.gitbook/assets/image (1076).png>)

![](<../../.gitbook/assets/image (597).png>)

* **Nadat jy die bietjies herstel het, moet jy dit dalk op 'n manier verwerk**. Byvoorbeeld, in Manchester-kodering sal 'n op+af 'n 1 of 0 wees en 'n af+op sal die ander wees. So pare van 1's en 0's (ops en af) sal 'n werklike 1 of 'n werklike 0 wees.
* Selfs as 'n sein Manchester-kodering gebruik (dit is onmoontlik om meer as twee 0's of 1's agtermekaar te vind), kan jy **veral 1's of 0's saam in die preambule vind**!

### Ontdek modulasietipe met IQ

Daar is 3 maniere om inligting in seine te stoor: Deur die **amplitude**, **frekwensie** of **fase** te moduleer.\
As jy 'n sein nagaan, is daar verskillende maniere om te probeer uitvind wat gebruik word om inligting te stoor (vind meer maniere hieronder) maar 'n goeie een is om na die IQ-grafiek te kyk.

![](<../../.gitbook/assets/image (788).png>)

* **AM opspoor**: As in die IQ-grafiek byvoorbeeld **2 sirkels** verskyn (waarskynlik een in 0 en die ander in 'n verskillende amplitude), kan dit beteken dat dit 'n AM-sein is. Dit is omdat in die IQ-grafiek die afstand tussen die 0 en die sirkel die amplitude van die sein is, so dit is maklik om te visualiseer dat verskillende amplitudes gebruik word.
* **PM opspoor**: Soos in die vorige beeld, as jy klein sirkels vind wat nie met mekaar verband hou nie, beteken dit waarskynlik dat fase-modulasie gebruik word. Dit is omdat in die IQ-grafiek die hoek tussen die punt en die 0,0 die fase van die sein is, so dit beteken dat 4 verskillende fases gebruik word.
* Let daarop dat as die inligting weggesteek is in die feit dat 'n fase verander word en nie in die fase self nie, sal jy nie verskillende fases duidelik onderskei nie.
* **FM opspoor**: IQ het nie 'n veld om frekwensies te identifiseer (afstand tot sentrum is amplitude en hoek is fase).\
Daarom, om FM te identifiseer, moet jy **hoofsaaklik net 'n sirkel** in hierdie grafiek sien.\
Verder word 'n verskillende frekwensie "voorgestel" deur die IQ-grafiek deur 'n **spoedversnelling oor die sirkel** (so in SysDigger as jy die sein kies, word die IQ-grafiek gevul, as jy 'n versnelling of rigtingsverandering in die geskepte sirkel vind, kan dit beteken dat dit FM is):

## AM Voorbeeld

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AM Ontdek

#### Kontroleer die omslag

Deur AM-inligting met [**SigDigger** ](https://github.com/BatchDrake/SigDigger)te ondersoek en net na die **omslag** te kyk, kan jy verskillende duidelike amplitudevlakke sien. Die gebruikte sein stuur pulse met inligting in AM, dit is hoe een puls lyk:

![](<../../.gitbook/assets/image (590).png>)

En dit is hoe 'n deel van die simbool lyk met die golfvorm:

![](<../../.gitbook/assets/image (734).png>)

#### Kontroleer die Histogram

Jy kan die **hele sein** waar die inligting geleë is, kies, **Amplitude**-modus en **Seleksie** kies en op **Histogram** klik. Jy kan sien dat 2 duidelike vlakke gevind word

![](<../../.gitbook/assets/image (264).png>)

Byvoorbeeld, as jy Frekwensie in plaas van Amplitude in hierdie AM-sein kies, vind jy net 1 frekwensie (geen manier waarop inligting gemoduleer in frekwensie net een frekwensie gebruik nie).

![](<../../.gitbook/assets/image (732).png>)

As jy baie frekwensies vind, sal dit waarskynlik nie 'n FM wees nie, moontlik is die seinfrekwensie net verander as gevolg van die kanaal.
#### Met IQ

In hierdie voorbeeld kan jy sien hoe daar 'n **groot sirkel** is, maar ook **'n baie punte in die middel.**

![](<../../.gitbook/assets/image (222).png>)

### Kry Simbool Tempo

#### Met een simbool

Kies die kleinste simbool wat jy kan vind (sodat jy seker is dis net 1) en kyk na die "Seleksie frekwensie". In hierdie geval sou dit 1.013kHz wees (dus 1kHz).

![](<../../.gitbook/assets/image (78).png>)

#### Met 'n groep simbole

Jy kan ook aandui hoeveel simbole jy gaan kies en SigDigger sal die frekwensie van 1 simbool bereken (hoe meer simbole wat gekies word, hoe beter waarskynlik). In hierdie scenario het ek 10 simbole gekies en die "Seleksie frekwensie" is 1.004 Khz:

![](<../../.gitbook/assets/image (1008).png>)

### Kry Bits

Nadat jy gevind het dat dit 'n **AM gemoduleerde** sein is en die **simbool tempo** (en weet dat in hierdie geval iets bo beteken 1 en iets onder beteken 0), is dit baie maklik om die **bits** wat in die sein gekodeer is, te **kry**. So, kies die sein met inligting en stel die monstering en besluit in en druk op monster (kontroleer dat **Amplitude** gekies is, die ontdekte **Simbool tempo** ingestel is en die **Gadner-klokherwinning** gekies is):

![](<../../.gitbook/assets/image (965).png>)

* **Sinkroniseer na seleksie-intervalle** beteken dat as jy voorheen intervals gekies het om die simbool tempo te vind, sal daardie simbool tempo gebruik word.
* **Handmatig** beteken dat die aangeduide simbool tempo gebruik gaan word
* In **Vaste interval seleksie** dui jy die aantal intervals aan wat gekies moet word en dit bereken die simbool tempo daaruit
* **Gadner-klokherwinning** is gewoonlik die beste opsie, maar jy moet steeds 'n benaderde simbool tempo aandui.

Deur op monster te druk, verskyn dit:

![](<../../.gitbook/assets/image (644).png>)

Nou, om SigDigger te laat verstaan **waar die reeks** van die vlak wat inligting dra, is, moet jy op die **laer vlak** klik en vasgehou hou tot by die grootste vlak:

![](<../../.gitbook/assets/image (439).png>)

As daar byvoorbeeld **4 verskillende vlakke van amplitude** was, sou jy die **Bits per simbool na 2** moes instel en van die kleinste tot die grootste kies.

Uiteindelik deur die **Zoom te verhoog** en die **Ry-grootte te verander** kan jy die bits sien (en jy kan almal kies en kopieer om al die bits te kry):

![](<../../.gitbook/assets/image (276).png>)

As die sein meer as 1 bit per simbool het (byvoorbeeld 2), het SigDigger **geen manier om te weet watter simbool is** 00, 01, 10, 11 nie, dus sal dit verskillende **gryskaal** gebruik om elkeen te verteenwoordig (en as jy die bits kopieer, sal dit **getalle van 0 tot 3** gebruik, jy sal hulle moet hanteer).

Gebruik ook **koderings** soos **Manchester**, en **op+af** kan **1 of 0** wees en 'n af+op kan 'n 1 of 0 wees. In daardie gevalle moet jy die verkryde op's (1) en af's (0) **behandel** om die pare van 01 of 10 as 0's of 1's te vervang.

## FM Voorbeeld

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FM Ontbloot

#### Kontroleer die frekwensies en golfvorm

Seinvoorbeeld wat inligting gemoduleer in FM stuur:

![](<../../.gitbook/assets/image (725).png>)

In die vorige beeld kan jy redelik goed sien dat **2 frekwensies gebruik word**, maar as jy die **golfvorm** **waarn**eem, mag jy **nie in staat wees om die 2 verskillende frekwensies korrek te identifiseer** nie:

![](<../../.gitbook/assets/image (717).png>)

Dit is omdat ek die sein in beide frekwensies vasgevang het, daarom is een ongeveer die ander in negatief:

![](<../../.gitbook/assets/image (942).png>)

As die gesinkroniseerde frekwensie **nader aan een frekwensie as aan die ander** is, kan jy maklik die 2 verskillende frekwensies sien:

![](<../../.gitbook/assets/image (422).png>)

![](<../../.gitbook/assets/image (488).png>)

#### Kontroleer die histogram

Deur die frekwensiehistogram van die sein met inligting te kontroleer, kan jy maklik 2 verskillende seine sien:

![](<../../.gitbook/assets/image (871).png>)

In hierdie geval, as jy die **Amplitudehistogram** nagaan, sal jy slegs een amplitude vind, dus **kan dit nie AM wees** (as jy baie amplitudes vind, kan dit wees omdat die sein krag verloor het langs die kanaal):

![](<../../.gitbook/assets/image (817).png>)

En dit is die fasehistogram (wat baie duidelik maak dat die sein nie in fase gemoduleer is nie):

![](<../../.gitbook/assets/image (996).png>)

#### Met IQ

IQ het nie 'n veld om frekwensies te identifiseer (afstand tot die middelpunt is amplitude en die hoek is fase).\
Daarom, om FM te identifiseer, moet jy **eintlik net 'n sirkel** in hierdie grafiek sien.\
Verder word 'n verskillende frekwensie "voorgestel" deur die IQ-grafiek deur 'n **spoedversnelling oor die sirkel** (so in SysDigger wat die sein kies, word die IQ-grafiek gevul, as jy 'n versnelling of rigtingsverandering in die geskepte sirkel vind, kan dit beteken dat dit FM is):

![](<../../.gitbook/assets/image (81).png>)

### Kry Simbool Tempo

Jy kan dieselfde tegniek as die een wat in die AM-voorbeeld gebruik is, gebruik om die simbool tempo te kry sodra jy die frekwensies wat simbole dra, gevind het.

### Kry Bits

Jy kan dieselfde tegniek as die een wat in die AM-voorbeeld gebruik is, gebruik om die bits te kry sodra jy gevind het dat die sein in frekwensie gemoduleer is en die simbool tempo.
