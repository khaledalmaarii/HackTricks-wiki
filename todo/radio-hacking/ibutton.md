# iButton

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## Intro

iButton ni jina la jumla kwa funguo za kitambulisho za kielektroniki zilizowekwa ndani ya **konteina ya chuma yenye umbo la sarafu**. Pia inaitwa **Dallas Touch** Memory au kumbukumbu ya mawasiliano. Ingawa mara nyingi inaitwa kwa makosa kama funguo “za sumaku”, hakuna **kitu chochote cha sumaku** ndani yake. Kwa kweli, **microchip** kamili inayofanya kazi kwenye itifaki ya kidijitali imefichwa ndani.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Kawaida, iButton inamaanisha umbo la kimwili la funguo na msomaji - sarafu ya mviringo yenye mawasiliano mawili. Kwa ajili ya fremu inayozunguka, kuna tofauti nyingi kutoka kwa holder ya plastiki yenye shimo hadi pete, mapambo, n.k.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Wakati funguo inafika kwa msomaji, **mawasiliano yanagusa** na funguo inapata nguvu ili **kupeleka** kitambulisho chake. Wakati mwingine funguo **haiwezi kusomwa** mara moja kwa sababu **PSD ya mawasiliano ya intercom ni kubwa** kuliko inavyopaswa kuwa. Hivyo, mipaka ya nje ya funguo na msomaji haiwezi kugusa. Ikiwa ndivyo ilivyo, itabidi ubonyeze funguo juu ya moja ya kuta za msomaji.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Funguo za Dallas hubadilishana data kwa kutumia itifaki ya 1-wire. Kwa mawasiliano moja tu ya uhamishaji wa data (!!) katika pande zote mbili, kutoka kwa bwana hadi mtumwa na kinyume chake. Itifaki ya 1-wire inafanya kazi kulingana na mfano wa Bwana-Mtumwa. Katika topolojia hii, Bwana daima huanzisha mawasiliano na Mtumwa anafuata maagizo yake.

Wakati funguo (Mtumwa) inagusa intercom (Bwana), chip ndani ya funguo inawashwa, ikipata nguvu kutoka kwa intercom, na funguo inaanzishwa. Baada ya hapo, intercom inaomba kitambulisho cha funguo. Kisha, tutaangalia mchakato huu kwa undani zaidi.

Flipper inaweza kufanya kazi katika hali za Bwana na Mtumwa. Katika hali ya kusoma funguo, Flipper inafanya kazi kama msomaji hii inamaanisha inafanya kazi kama Bwana. Na katika hali ya kuiga funguo, flipper inajifanya kuwa funguo, iko katika hali ya Mtumwa.

### Dallas, Cyfral & Metakom keys

Kwa maelezo kuhusu jinsi funguo hizi zinavyofanya kazi angalia ukurasa [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacks

iButtons zinaweza kushambuliwa kwa Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## References

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
