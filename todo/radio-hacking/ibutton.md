# iButton

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Utangulizi

iButton ni jina la kawaida kwa funguo ya kitambulisho ya elektroniki iliyopakwa katika **chombo cha umbo la sarafu**. Pia inaitwa **Dallas Touch** Memory au kumbukumbu ya mawasiliano. Ingawa mara nyingi inaitwa vibaya kama funguo "magnetiki", hakuna kitu **cha kuvuta umeme** ndani yake. Kwa kweli, kuna chip ndogo kamili inayofanya kazi kwa itifaki ya dijiti iliyofichwa ndani.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### Ni nini iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Kawaida, iButton inamaanisha umbo la kimwili la funguo na kusoma - sarafu ya pande zote na mawasiliano mawili. Kwa fremu inayozunguka, kuna mabadiliko mengi kutoka kwa kawaida ya kawaida ya plastiki na shimo hadi pete, mapambo, nk.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

Funguo inapofikia kusoma, **mawasiliano yanagusa** na funguo inapata nguvu ya **kupeleka** kitambulisho chake. Mara nyingi funguo **haikusomwa** mara moja kwa sababu **PSD ya mawasiliano ya intercom ni kubwa** kuliko inavyopaswa kuwa. Kwa hivyo mipaka ya nje ya funguo na kusoma haiwezi kugusa. Ikiwa ndivyo ilivyo, utalazimika kubonyeza funguo juu ya moja ya kuta za kusoma.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **Itifaki ya 1-Wire** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Funguo za Dallas hubadilishana data kwa kutumia itifaki ya 1-wire. Kwa kuwa na mawasiliano moja tu kwa uhamisho wa data (!!) kwa pande zote, kutoka kwa bwana kwenda kwa mtumwa na kinyume chake. Itifaki ya 1-wire inafanya kazi kulingana na mfano wa Bwana-Mtumwa. Katika muundo huu, Bwana daima huanzisha mawasiliano na Mtumwa anafuata maagizo yake.

Funguo (Mtumwa) inapowasiliana na intercom (Bwana), chip ndani ya funguo huzinduliwa, ikipata nguvu kutoka kwa intercom, na funguo huanzishwa. Baada ya hapo, intercom inaomba kitambulisho cha funguo. Baadaye, tutachunguza mchakato huu kwa undani zaidi.

Flipper inaweza kufanya kazi kama Bwana na Mtumwa. Katika hali ya kusoma funguo, Flipper hufanya kazi kama kusoma hii ni kusema inafanya kazi kama Bwana. Na katika hali ya kuiga funguo, flipper inajifanya kuwa funguo, iko katika hali ya Mtumwa.

### Funguo za Dallas, Cyfral & Metakom

Kwa habari juu ya jinsi funguo hizi zinafanya kazi, angalia ukurasa [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Mashambulizi

Funguo za iButton zinaweza kushambuliwa na Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Marejeo

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
