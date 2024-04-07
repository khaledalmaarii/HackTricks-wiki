# Infrarooi

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Hoe die Infrarooi Werk <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarooi lig is onsigbaar vir mense**. IR-golflengte is van **0.7 tot 1000 mikron**. Huishoudelike afstandbeheerders gebruik 'n IR-sein vir data-oordrag en werk in die golflengte-reeks van 0.75..1.4 mikron. 'n Mikrokontroleerder in die afstandbeheerder laat 'n infrarooi LED met 'n spesifieke frekwensie knipper, wat die digitale sein in 'n IR-sein omskakel.

Om IR-seine te ontvang, word 'n **fotontvanger** gebruik. Dit **skakel IR-licht in voltpulse om**, wat reeds **digitale seine** is. Gewoonlik is daar 'n **donkerligfilter binne die ontvanger**, wat slegs **die gewenste golflengte deurlaat** en geraas uitsny.

### Verskeidenheid IR-Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR-protokolle verskil in 3 faktore:

* bit-kodering
* datastruktuur
* draerfrekwensie — dikwels in die reeks 36..38 kHz

#### Maniere van bit-kodering <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulsaflandkodering**

Bits word gekodeer deur die duur van die spasie tussen pulke te moduleer. Die wydte van die puls self is konstant.

<figure><img src="../../.gitbook/assets/image (292).png" alt=""><figcaption></figcaption></figure>

**2. Pulswydkodering**

Bits word gekodeer deur modulasie van die puls wydte. Die wydte van die spasie na die pulsreeks is konstant.

<figure><img src="../../.gitbook/assets/image (279).png" alt=""><figcaption></figcaption></figure>

**3. Fasekodering**

Dit staan ook bekend as Manchester-kodering. Die logiese waarde word bepaal deur die polariteit van die oorgang tussen die pulsreeks en spasie. "Spasie na pulsreeks" dui logika "0" aan, "pulsreeks na spasie" dui logika "1" aan.

<figure><img src="../../.gitbook/assets/image (631).png" alt=""><figcaption></figcaption></figure>

**4. Kombinasie van voriges en ander eksotiese**

{% hint style="info" %}
Daar is IR-protokolle wat **probeer om universeel te word** vir verskeie tipes toestelle. Die bekendste is RC5 en NEC. Ongelukkig beteken die bekendste **nie noodwendig die mees algemene nie**. In my omgewing het ek net twee NEC-afstandbeheerders ontmoet en geen RC5-afstandbeheerders nie.

Vervaardigers hou daarvan om hul eie unieke IR-protokolle te gebruik, selfs binne dieselfde reeks toestelle (byvoorbeeld, TV-bokse). Daarom kan afstandbeheerders van verskillende maatskappye en soms van verskillende modelle van dieselfde maatskappy, nie werk met ander toestelle van dieselfde tipe nie.
{% endhint %}

### Verkenning van 'n IR-sein

Die betroubaarste manier om te sien hoe die afstandbeheerder se IR-sein lyk, is om 'n ossilloskoop te gebruik. Dit demoduleer of keer die ontvangssein nie om nie, dit word net "soos dit is" vertoon. Dit is nuttig vir toetsing en foutopsporing. Ek sal die verwagte sein toon aan die hand van die NEC IR-protokol.

<figure><img src="../../.gitbook/assets/image (232).png" alt=""><figcaption></figcaption></figure>

Gewoonlik is daar 'n voorspel aan die begin van 'n gekodeerde pakkie. Dit laat die ontvanger toe om die vlak van wins en agtergrond te bepaal. Daar is ook protokolle sonder voorspel, byvoorbeeld, Sharp.

Dan word data oorgedra. Die struktuur, voorspel, en bit-koderingsmetode word bepaal deur die spesifieke protokol.

Die **NEC IR-protokol** bevat 'n kort bevel en 'n herhaalkode, wat gestuur word terwyl die knoppie ingedruk word. Beide die bevel en die herhaalkode het dieselfde voorspel aan die begin.

NEC **bevel**, behalwe die voorspel, bestaan uit 'n adresbyte en 'n bevelnommerbyte, waarmee die toestel verstaan wat gedoen moet word. Adres- en bevelnommerbytes word gedupliseer met inversiewaardes, om die integriteit van die oordrag te toets. Daar is 'n bykomende stopbit aan die einde van die bevel.

Die **herhaalkode** het 'n "1" na die voorspel, wat 'n stopbit is.

Vir **logika "0" en "1"** gebruik NEC Pulsaflandkodering: eers word 'n pulsreeks oorgedra, waarna daar 'n pouse is, die lengte daarvan stel die waarde van die bit.

### Lugversorgers

In teenstelling met ander afstandbeheerders, **stuur lugversorgers nie net die kode van die ingedrukte knoppie nie**. Hulle **stuur ook al die inligting** wanneer 'n knoppie ingedruk word om te verseker dat die **lugversorger en die afstandbeheerder gesinkroniseer is**.\
Dit sal voorkom dat 'n masjien wat op 20ºC ingestel is, met een afstandbeheerder na 21ºC verhoog word, en dan wanneer 'n ander afstandbeheerder, wat nog steeds die temperatuur as 20ºC het, gebruik word om die temperatuur verder te verhoog, dit dit na 21ºC "verhoog" (en nie na 22ºC dink dat dit in 21ºC is nie).

### Aanvalle

Jy kan Infrarooi aanval met Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Verwysings

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
