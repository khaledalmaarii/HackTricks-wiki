# Infrarooi

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

## Hoe die Infrarooi Werk <a href="#hoe-die-infrarooi-poort-werk" id="hoe-die-infrarooi-poort-werk"></a>

**Infrarooi lig is onsigbaar vir mense**. IR-golflengte is van **0.7 tot 1000 mikrone**. Huishoudelike afstandbeheerders gebruik 'n IR-sein vir datatransmissie en werk in die golflengtebereik van 0.75..1.4 mikrone. 'n Mikrokontroleerder in die afstandbeheerder laat 'n infrarooi LED met 'n spesifieke frekwensie knipper, wat die digitale sein in 'n IR-sein omskakel.

Om IR-seine te ontvang, word 'n **fotoreseiver** gebruik. Dit **skakel IR-lig om in voltpulse**, wat reeds **digitale seine** is. Gewoonlik is daar 'n **donkerligfilter binne die ontvanger**, wat slegs die gewenste golflengte deurlaat en geraas uitsny.

### Verskeidenheid IR-Protokolle <a href="#verskeidenheid-ir-protokolle" id="verskeidenheid-ir-protokolle"></a>

IR-protokolle verskil in 3 faktore:

* bitkodering
* datastruktuur
* draerfrekwensie - dikwels in die reeks 36..38 kHz

#### Maniere van bitkodering <a href="#maniere-van-bitkodering" id="maniere-van-bitkodering"></a>

**1. Pulsaftandkodering**

Bits word gekodeer deur die duur van die ruimte tussen pulsskote te moduleer. Die breedte van die puls self is konstant.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Pulsbreedtekodering**

Bits word gekodeer deur modulasie van die puls breedte. Die breedte van die ruimte na die pulsskoot is konstant.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Fasekodering**

Dit staan ook bekend as Manchester-kodering. Die logiese waarde word bepaal deur die polariteit van die oorgang tussen pulsskoot en ruimte. "Ruimte na pulsskoot" dui logika "0" aan, "pulsskoot na ruimte" dui logika "1" aan.

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Kombinasie van voriges en ander eksotiese protokolle**

{% hint style="info" %}
Daar is IR-protokolle wat **universeel probeer word** vir verskeie tipes toestelle. Die bekendste is RC5 en NEC. Ongelukkig beteken die bekendste **nie die mees algemene nie**. In my omgewing het ek net twee NEC-afstandbeheerders en geen RC5-afstandbeheerders ontmoet nie.

Vervaardigers hou daarvan om hul eie unieke IR-protokolle te gebruik, selfs binne dieselfde reeks toestelle (byvoorbeeld TV-bokse). Daarom kan afstandbeheerders van verskillende maatskappye en soms van verskillende modelle van dieselfde maatskappy nie met ander toestelle van dieselfde tipe werk nie.
{% endhint %}

### Verkenning van 'n IR-sein

Die betroubaarste manier om te sien hoe die afstandbeheerder se IR-sein lyk, is om 'n oscilloskoop te gebruik. Dit demoduleer of keer die ontvangste sein nie om nie, dit word net "soos dit is" vertoon. Dit is nuttig vir toetsing en foutopsporing. Ek sal die verwagte sein toon aan die hand van die NEC IR-protokol.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Gewoonlik is daar 'n preamble aan die begin van 'n gekodeerde pakkie. Dit stel die ontvanger in staat om die vlak van wins en agtergrond te bepaal. Daar is ook protokolle sonder preamble, byvoorbeeld Sharp.

Dan word data oorgedra. Die struktuur, preamble en bitkoderingsmetode word deur die spesifieke protokol bepaal.

Die **NEC IR-protokol** bevat 'n kort bevel en 'n herhaalkode wat gestuur word terwyl die knoppie ingedruk word. Beide die bevel en die herhaalkode het dieselfde preamble aan die begin.

NEC **bevel**, naas die preamble, bestaan uit 'n adresbyte en 'n bevelnommerbyte, waarmee die toestel verstaan wat gedoen moet word. Adres- en bevelnommerbyte word gedupliseer met inverse waardes om die integriteit van die oordrag te toets. Daar is 'n bykomende stopbit aan die einde van die bevel.

Die **herhaalkode** het 'n "1" na die preamble, wat 'n stopbit is.

Vir **logika "0" en "1"** gebruik NEC Pulsaftandkodering: Eerstens word 'n pulsskoot oorgedra, waarna daar 'n onderbreking is, waarvan die lengte die waarde van die bit bepaal.

### Lugversorgers

In teenstelling met ander afstandbeheerders, **stuur lugversorgers nie net die kode van die ingedrukte knoppie nie**. Hulle stuur ook **alle inligting** oor wanneer 'n knoppie ingedruk word om te verseker dat die **lugversorgingsmasjien en die afstandbeheerder gesinkroniseer is**.\
Dit sal voorkom dat 'n masjien wat as 20ºC ingestel is, met een afstandbeheerder na 21ºC verhoog word, en dan wanneer 'n ander afstandbeheerder, wat die temperatuur steeds as 20ºC het, gebruik word om die temperatuur verder te verhoog, dit na 21ºC "verhoog" (en nie na 22ºC dink dat dit in 21ºC is).

### Aanvalle

Jy kan Infrarooi aanval met Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Verwysings

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass
