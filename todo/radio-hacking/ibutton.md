# iButton

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Utangulizi

iButton ni jina la kawaida la ufunguo wa utambulisho wa elektroniki uliowekwa kwenye **chombo cha metali chenye umbo la sarafu**. Pia huitwa **Dallas Touch** Memory au kumbukumbu ya mawasiliano. Ingawa mara nyingi huitwa kimakosa kama ufunguo "wenye sumaku", hakuna **kitu cha sumaku** ndani yake. Kwa kweli, kuna **chipu kamili** inayofanya kazi kwa itifaki ya dijiti iliyofichwa ndani yake.

<figure><img src="../../.gitbook/assets/image (912).png" alt=""><figcaption></figcaption></figure>

### Ni nini iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Kawaida, iButton inamaanisha umbo la kimwili la ufunguo na msomaji - sarafu ya mviringo yenye mawasiliano mawili. Kwa fremu inayomzunguka, kuna mabadiliko mengi kutoka kwa kizuizi cha plastiki cha kawaida chenye shimo hadi pete, vipendanti, n.k.

<figure><img src="../../.gitbook/assets/image (1075).png" alt=""><figcaption></figcaption></figure>

Wakati ufunguo unapofika kwa msomaji, **mawasiliano hukutana** na ufunguo hupata nguvu ya **kuhamisha** kitambulisho chake. Mara nyingine ufunguo **hausomwi** mara moja kwa sababu **PSD ya mawasiliano ya intercom ni kubwa** kuliko inavyopaswa kuwa. Kwa hivyo mipaka ya nje ya ufunguo na msomaji haziwezi kugusana. Ikiwa ndivyo, utalazimika kubonyeza ufunguo juu ya moja ya kuta za msomaji.

<figure><img src="../../.gitbook/assets/image (287).png" alt=""><figcaption></figcaption></figure>

### **Itifaki ya 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Vifunguo vya Dallas hubadilishana data kwa kutumia itifaki ya 1-wire. Kwa mawasiliano ya data (!!) kwa pande zote mbili, kutoka kwa bwana kwenda kwa mtumwa na kinyume chake, kwa kutumia mawasiliano moja tu. Itifaki ya 1-wire hufanya kazi kulingana na mfano wa Bwana-Mtumwa. Katika mtandao huu, Bwana daima huanzisha mawasiliano na Mtumwa anafuata maagizo yake.

Wakati ufunguo (Mtumwa) unapowasiliana na intercom (Bwana), chipu ndani ya ufunguo huzimwa, ikipata nguvu kutoka kwa intercom, na ufunguo huanzishwa. Baada ya hapo intercom inaomba kitambulisho cha ufunguo. Kisha tutachunguza mchakato huu kwa undani zaidi.

Flipper inaweza kufanya kazi kama Bwana au Mtumwa. Katika hali ya kusoma ufunguo, Flipper hufanya kazi kama msomaji yaani inafanya kazi kama Bwana. Na katika hali ya kujifanya ufunguo, flipper inajifanya kuwa ufunguo, iko katika hali ya Mtumwa.

### Vifunguo vya Dallas, Cyfral & Metakom

Kwa habari kuhusu jinsi vifunguo hivi vinavyofanya kazi angalia ukurasa [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Mashambulizi

iButtons wanaweza kushambuliwa na Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## Marejeo

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) 

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
