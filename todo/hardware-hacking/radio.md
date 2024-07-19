# Radio

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)is 'n gratis digitale seinanaliseerder vir GNU/Linux en macOS, ontwerp om inligting van onbekende radiosignale te onttrek. Dit ondersteun 'n verskeidenheid SDR-toestelle deur SoapySDR, en laat aanpasbare demodulasie van FSK, PSK en ASK seine toe, dekodeer analoog video, analiseer burstige seine en luister na analoog stemkanale (alles in werklike tyd).

### Basiese Konfigurasie

Na die installasie is daar 'n paar dinge wat jy kan oorweeg om te konfigureer.\
In instellings (die tweede tabknoppie) kan jy die **SDR-toestel** kies of **'n lêer** kies om te lees en watter frekwensie om te sintoniseer en die monster tempo (aanbeveel tot 2.56Msps as jou rekenaar dit ondersteun)\\

![](<../../.gitbook/assets/image (245).png>)

In die GUI gedrag is dit aanbeveel om 'n paar dinge in te skakel as jou rekenaar dit ondersteun:

![](<../../.gitbook/assets/image (472).png>)

{% hint style="info" %}
As jy besef dat jou rekenaar nie dinge opneem nie, probeer om OpenGL te deaktiveer en die monster tempo te verlaag.
{% endhint %}

### Gebruik

* Net om **'n bietjie van 'n sein te vang en dit te analiseer** hou net die knoppie "Druk om te vang" ingedruk solank as wat jy nodig het.

![](<../../.gitbook/assets/image (960).png>)

* Die **Tuner** van SigDigger help om **beter seine te vang** (maar dit kan ook hulle vererger). Ideaal gesproke begin met 0 en hou **dit groter maak totdat** jy die **ruis** wat ingevoer word groter is as die **verbetering van die sein** wat jy nodig het).

![](<../../.gitbook/assets/image (1099).png>)

### Sinchroniseer met radio kanaal

Met [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sinchroniseer met die kanaal wat jy wil hoor, konfigureer die "Baseband audio preview" opsie, konfigureer die bandwydte om al die inligting wat gestuur word te kry en stel dan die Tuner in op die vlak voordat die ruis regtig begin toeneem:

![](<../../.gitbook/assets/image (585).png>)

## Interessante truuks

* Wanneer 'n toestel inligting in stoots stuur, is die **eerste deel gewoonlik 'n preamble**, so jy **hoef nie** te **sorg** as jy **nie inligting** daar vind **of as daar 'n paar foute** daar is nie.
* In rame van inligting behoort jy gewoonlik **verskillende rame goed uitgelijnd tussen hulle** te vind:

![](<../../.gitbook/assets/image (1076).png>)

![](<../../.gitbook/assets/image (597).png>)

* **Nadat jy die bits herstel het, moet jy dit op een of ander manier verwerk**. Byvoorbeeld, in Manchester-kodering sal 'n op+af 'n 1 of 0 wees en 'n af+op sal die ander een wees. So pare van 1s en 0s (op en af) sal 'n werklike 1 of 'n werklike 0 wees.
* Selfs as 'n sein Manchester-kodering gebruik (dit is onmoontlik om meer as twee 0s of 1s agtereenvolgens te vind), kan jy **verskeie 1s of 0s saam in die preamble** vind!

### Ontdek modulasietipe met IQ

Daar is 3 maniere om inligting in seine te stoor: Modulasie van die **amplitude**, **frekwensie** of **fase**.\
As jy 'n sein nagaan, is daar verskillende maniere om te probeer uit te vind wat gebruik word om inligting te stoor (vind meer maniere hieronder) maar 'n goeie een is om die IQ-grafiek na te gaan.

![](<../../.gitbook/assets/image (788).png>)

* **AM opsporing**: As daar in die IQ-grafiek byvoorbeeld **2 sirkels** verskyn (waarskynlik een in 0 en een in 'n ander amplitude), kan dit beteken dat dit 'n AM-sein is. Dit is omdat in die IQ-grafiek die afstand tussen die 0 en die sirkel die amplitude van die sein is, so dit is maklik om verskillende amplitudes wat gebruik word te visualiseer.
* **PM opsporing**: Soos in die vorige beeld, as jy klein sirkels vind wat nie met mekaar verband hou nie, beteken dit waarskynlik dat 'n fase-modulasie gebruik word. Dit is omdat in die IQ-grafiek, die hoek tussen die punt en die 0,0 die fase van die sein is, so dit beteken dat 4 verskillende fases gebruik word.
* Let daarop dat as die inligting versteek is in die feit dat 'n fase verander en nie in die fase self nie, jy nie verskillende fases duidelik gedifferensieer sal sien nie.
* **FM opsporing**: IQ het nie 'n veld om frekwensies te identifiseer nie (afstand tot sentrum is amplitude en hoek is fase).\
Daarom, om FM te identifiseer, moet jy **basies net 'n sirkel** in hierdie grafiek sien.\
Boonop word 'n ander frekwensie "verteenwoordig" deur die IQ-grafiek deur 'n **spoedversnelling oor die sirkel** (so in SysDigger, wanneer jy die sein kies, word die IQ-grafiek bevolk, as jy 'n versnelling of rigtingverandering in die geskepte sirkel vind, kan dit beteken dat dit FM is):

## AM Voorbeeld

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Ontdek AM

#### Kontroleer die omhulsel

Kontroleer AM-inligting met [**SigDigger** ](https://github.com/BatchDrake/SigDigger)en net deur na die **omhulsel** te kyk kan jy verskillende duidelike amplitude vlakke sien. Die gebruikte sein stuur pulse met inligting in AM, so lyk een puls:

![](<../../.gitbook/assets/image (590).png>)

En so lyk 'n deel van die simbool met die golfvorm:

![](<../../.gitbook/assets/image (734).png>)

#### Kontroleer die Histogram

Jy kan **die hele sein** waar die inligting geleë is, kies, **Amplitude** modus en **Keuse** kies en op **Histogram** klik. Jy kan waarneem dat 2 duidelike vlakke net gevind word

![](<../../.gitbook/assets/image (264).png>)

Byvoorbeeld, as jy Frekwensie kies in plaas van Amplitude in hierdie AM-sein vind jy net 1 frekwensie (geen manier dat inligting wat in frekwensie gemoduleer is net 1 frekwensie gebruik).

![](<../../.gitbook/assets/image (732).png>)

As jy 'n baie frekwensies vind, sal dit waarskynlik nie 'n FM wees nie, waarskynlik is die seinfrekwensie net gewysig as gevolg van die kanaal.

#### Met IQ

In hierdie voorbeeld kan jy sien hoe daar 'n **groot sirkel** is, maar ook **baie punte in die sentrum.**

![](<../../.gitbook/assets/image (222).png>)

### Kry Simbool Tempo

#### Met een simbool

Kies die kleinste simbool wat jy kan vind (sodat jy seker is dit is net 1) en kyk na die "Keuse frekwensie". In hierdie geval sou dit 1.013kHz wees (so 1kHz).

![](<../../.gitbook/assets/image (78).png>)

#### Met 'n groep simbole

Jy kan ook die aantal simbole wat jy gaan kies, aandui en SigDigger sal die frekwensie van 1 simbool bereken (hoe meer simbole gekies, hoe beter waarskynlik). In hierdie scenario het ek 10 simbole gekies en die "Keuse frekwensie" is 1.004 Khz:

![](<../../.gitbook/assets/image (1008).png>)

### Kry Bits

Aangesien dit 'n **AM-gemoduleerde** sein is en die **simbooltempo** (en wetende dat in hierdie geval iets op beteken 1 en iets af beteken 0), is dit baie maklik om die **bits** wat in die sein gekodeer is, te **verkry**. So, kies die sein met inligting en konfigureer die monster en besluit en druk monster (kyk dat **Amplitude** gekies is, die ontdekte **Simbooltempo** is geconfigureer en die **Gadner klokherstel** is gekies):

![](<../../.gitbook/assets/image (965).png>)

* **Sinkroniseer met keuse-intervalle** beteken dat as jy voorheen intervalle gekies het om die simbooltempo te vind, daardie simbooltempo sal gebruik word.
* **Handmatig** beteken dat die aangeduide simbooltempo gaan gebruik word
* In **Vaste intervalkeuse** dui jy die aantal intervalle aan wat gekies moet word en dit bereken die simbooltempo daaruit
* **Gadner klokherstel** is gewoonlik die beste opsie, maar jy moet steeds 'n paar benaderde simbooltempo aandui.

Wanneer jy op monster druk, verskyn dit:

![](<../../.gitbook/assets/image (644).png>)

Nou, om SigDigger te laat verstaan **waar die reeks** van die vlak wat inligting dra is, moet jy op die **lae vlak** klik en ingedruk hou totdat die grootste vlak:

![](<../../.gitbook/assets/image (439).png>)

As daar byvoorbeeld **4 verskillende vlakke van amplitude** was, sou jy die **Bits per simbool op 2** moes konfigureer en van die kleinste na die grootste kies.

Laastens **verhoog** die **Zoom** en **verander die Ry grootte** kan jy die bits sien (en jy kan alles kies en kopieer om al die bits te kry):

![](<../../.gitbook/assets/image (276).png>)

As die sein meer as 1 bit per simbool het (byvoorbeeld 2), het SigDigger **geen manier om te weet watter simbool is** 00, 01, 10, 11 nie, so dit sal verskillende **grys skale** gebruik om elkeen te verteenwoordig (en as jy die bits kopieer, sal dit **nommers van 0 tot 3** gebruik, jy sal dit moet verwerk).

Gebruik ook **kodifikasies** soos **Manchester**, en **op+af** kan **1 of 0** wees en 'n af+op kan 'n 1 of 0 wees. In daardie gevalle moet jy die **verkryde op (1) en af (0)** verwerk om die pare van 01 of 10 as 0s of 1s te vervang.

## FM Voorbeeld

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Ontdek FM

#### Kontroleer die frekwensies en golfvorm

Seinvoorbeeld wat inligting gemoduleer in FM stuur:

![](<../../.gitbook/assets/image (725).png>)

In die vorige beeld kan jy redelik goed waarneem dat **2 frekwensies gebruik word**, maar as jy die **golfvorm** waarneem, mag jy **nie in staat wees om die 2 verskillende frekwensies korrek te identifiseer nie**:

![](<../../.gitbook/assets/image (717).png>)

Dit is omdat ek die sein in beide frekwensies opgeneem het, daarom is een ongeveer die ander in negatief:

![](<../../.gitbook/assets/image (942).png>)

As die gesinchroniseerde frekwensie **naby aan een frekwensie is as aan die ander**, kan jy maklik die 2 verskillende frekwensies sien:

![](<../../.gitbook/assets/image (422).png>)

![](<../../.gitbook/assets/image (488).png>)

#### Kontroleer die histogram

Deur die frekwensie histogram van die sein met inligting te kontroleer, kan jy maklik 2 verskillende seine sien:

![](<../../.gitbook/assets/image (871).png>)

In hierdie geval, as jy die **Amplitude histogram** kontroleer, sal jy **slegs een amplitude** vind, so dit **kan nie AM wees nie** (as jy 'n baie amplitudes vind, kan dit wees omdat die sein krag verloor het langs die kanaal):

![](<../../.gitbook/assets/image (817).png>)

En dit sou die fase histogram wees (wat baie duidelik maak dat die sein nie in fase gemoduleer is nie):

![](<../../.gitbook/assets/image (996).png>)

#### Met IQ

IQ het nie 'n veld om frekwensies te identifiseer nie (afstand tot sentrum is amplitude en hoek is fase).\
Daarom, om FM te identifiseer, moet jy **basies net 'n sirkel** in hierdie grafiek sien.\
Boonop word 'n ander frekwensie "verteenwoordig" deur die IQ-grafiek deur 'n **spoedversnelling oor die sirkel** (so in SysDigger, wanneer jy die sein kies, word die IQ-grafiek bevolk, as jy 'n versnelling of rigtingverandering in die geskepte sirkel vind, kan dit beteken dat dit FM is):

![](<../../.gitbook/assets/image (81).png>)

### Kry Simbool Tempo

Jy kan die **dieselfde tegniek as die een wat in die AM voorbeeld gebruik is** gebruik om die simbooltempo te kry sodra jy die frekwensies wat simbole dra, gevind het.

### Kry Bits

Jy kan die **dieselfde tegniek as die een wat in die AM voorbeeld gebruik is** gebruik om die bits te kry sodra jy **gevind het dat die sein in frekwensie gemoduleer is** en die **simbooltempo**. 

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
