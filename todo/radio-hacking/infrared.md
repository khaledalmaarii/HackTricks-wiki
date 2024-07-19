# Infrared

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

## Hoe die Infrarooi Werk <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Infrarooi lig is onsigbaar vir mense**. IR golflengte is van **0.7 tot 1000 mikron**. Huishoudelike afstandsbedienings gebruik 'n IR sein vir datatransmissie en werk in die golflengte-reeks van 0.75..1.4 mikron. 'n Mikrocontroller in die afstandsbediening laat 'n infrarooi LED flikker met 'n spesifieke frekwensie, wat die digitale sein in 'n IR sein omskakel.

Om IR seine te ontvang, word 'n **fotoreceiver** gebruik. Dit **omskakel IR lig in spanning pulsies**, wat reeds **digitale seine** is. Gewoonlik is daar 'n **donker ligfilter binne die ontvanger**, wat **slegs die gewenste golflengte deurlaat** en geraas uitsny.

### Verskeidenheid van IR Protokolle <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokolle verskil in 3 faktore:

* bit kodering
* datastruktuur
* draerfrekwensie — dikwels in die reeks 36..38 kHz

#### Bit kodering maniere <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulsafstand Kodering**

Bits word gekodeer deur die duur van die spasie tussen pulsies te moduler. Die breedte van die puls self is konstant.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulsbreedte Kodering**

Bits word gekodeer deur modulasie van die pulsbreedte. Die breedte van die spasie na die pulsuitbarsting is konstant.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Fase Kodering**

Dit is ook bekend as Manchester kodering. Die logiese waarde word gedefinieer deur die polariteit van die oorgang tussen pulsuitbarsting en spasie. "Spasie na pulsuitbarsting" dui logika "0" aan, "pulsuitbarsting na spasie" dui logika "1" aan.

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinasie van vorige en ander eksotiese**

{% hint style="info" %}
Daar is IR protokolle wat **probeer om universeel te word** vir verskeie tipes toestelle. Die bekendste is RC5 en NEC. Ongelukkig beteken die bekendste **nie die mees algemene** nie. In my omgewing het ek net twee NEC afstandsbedienings ontmoet en geen RC5 nie.

Fabrikante hou daarvan om hul eie unieke IR protokolle te gebruik, selfs binne dieselfde reeks toestelle (byvoorbeeld, TV-doosies). Daarom kan afstandsbedienings van verskillende maatskappye en soms van verskillende modelle van dieselfde maatskappy, nie met ander toestelle van dieselfde tipe werk nie.
{% endhint %}

### Verken 'n IR sein

Die mees betroubare manier om te sien hoe die afstandsbediening se IR sein lyk, is om 'n oscilloskoop te gebruik. Dit demoduleer of keer nie die ontvangde sein om nie, dit word net "soos dit is" vertoon. Dit is nuttig vir toetsing en foutopsporing. Ek sal die verwagte sein op die voorbeeld van die NEC IR protokol wys.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Gewoonlik is daar 'n preamble aan die begin van 'n gekodeerde pakket. Dit laat die ontvanger toe om die vlak van versterking en agtergrond te bepaal. Daar is ook protokolle sonder preamble, byvoorbeeld, Sharp.

Dan word data oorgedra. Die struktuur, preamble, en bit kodering metode word deur die spesifieke protokol bepaal.

**NEC IR protokol** bevat 'n kort opdrag en 'n herhalingskode, wat gestuur word terwyl die knoppie ingedruk word. Beide die opdrag en die herhalingskode het dieselfde preamble aan die begin.

NEC **opdrag**, benewens die preamble, bestaan uit 'n adresbyte en 'n opdrag-nommer byte, waardeur die toestel verstaan wat gedoen moet word. Adres en opdrag-nommer bytes word gedupliseer met omgekeerde waardes, om die integriteit van die transmissie te kontroleer. Daar is 'n bykomende stopbit aan die einde van die opdrag.

Die **herhalingskode** het 'n "1" na die preamble, wat 'n stopbit is.

Vir **logika "0" en "1"** gebruik NEC Pulsafstand Kodering: eerstens word 'n pulsuitbarsting oorgedra waarna daar 'n pouse is, waarvan die lengte die waarde van die bit bepaal.

### Lugversorgers

In teenstelling met ander afstandsbedienings, **stuur lugversorgers nie net die kode van die ingedrukte knoppie nie**. Hulle **stuur ook al die inligting** wanneer 'n knoppie ingedruk word om te verseker dat die **lugversorgingsmasjien en die afstandsbediening gesinchroniseer is**.\
Dit sal verhoed dat 'n masjien wat op 20ºC ingestel is, verhoog word na 21ºC met een afstandsbediening, en dan wanneer 'n ander afstandsbediening, wat steeds die temperatuur as 20ºC het, gebruik word om die temperatuur verder te verhoog, dit "verhoog" na 21ºC (en nie na 22ºC nie, dink dit is op 21ºC).

### Aanvalle

Jy kan Infrarooi aanval met Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Verwysings

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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
