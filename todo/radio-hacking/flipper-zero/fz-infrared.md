# FZ - Mionzi

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikionyeshwa kwenye HackTricks**? au unataka kupata toleo **jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Utangulizi <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kwa habari zaidi kuhusu jinsi Mionzi Infrared inavyofanya kazi angalia:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Kipokezi cha Ishara ya IR katika Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper hutumia kipokezi wa ishara ya IR ya dijiti TSOP, ambayo **inaruhusu kudaka ishara kutoka kwa vidhibiti vya IR**. Kuna **simu za mkononi** kama Xiaomi, ambazo pia zina bandari ya IR, lakini kumbuka kwamba **zaidi yao wanaweza tu kutuma** ishara na hawawezi **kuzipokea**.

Kipokezi cha mionzi ya Flipper ni **nyeti sana**. Unaweza hata **kudaka ishara** ukiwa **mahali fulani kati** ya kiremote na TV. Kuashiria kiremote moja kwa moja kwenye bandari ya IR ya Flipper sio lazima. Hii inakuja kwa manufaa wakati mtu anabadilisha vituo wakati amesimama karibu na TV, na wewe na Flipper mko mbali kidogo.

Kwa kuwa **uchambuzi wa ishara ya infrared** unatokea upande wa **programu**, Flipper Zero inaweza kusaidia **mapokezi na utangazaji wa nambari yoyote ya kiremote ya IR**. Katika kesi ya **itifaki zisizojulikana** ambazo hazingeweza kutambuliwa - ina **rekodi na kucheza** tena ishara ghafi kama ilivyopokelewa.

## Vitendo

### Vidhibiti vya Ulimwengu

Flipper Zero inaweza kutumika kama **kidhibiti cha ulimwengu kudhibiti TV yoyote, kiyoyozi, au kituo cha media**. Katika hali hii, Flipper **inabomoa** **nambari zote zinazojulikana** za watengenezaji wote wanaoungwa mkono **kulingana na kamusi kutoka kwa kadi ya SD**. Hauitaji kuchagua kiremote fulani kuzima TV ya mgahawa.

Inatosha kubonyeza kitufe cha nguvu katika hali ya Kidhibiti cha Ulimwengu, na Flipper itatuma **amri za "Kuzima"** za televisheni zote inazojua kwa mpangilio: Sony, Samsung, Panasonic... na kadhalika. Televisheni inapopokea ishara yake, itajibu na kuzima.

Kama kuvunja nguvu kuchukua muda. Kamusi ikiwa kubwa, itachukua muda mrefu kumaliza. Haiwezekani kujua ni ishara ipi hasa televisheni iliyotambua kwani hakuna maoni kutoka kwa televisheni.

### Jifunze Kiremote Kipya

Inawezekana **kudaka ishara ya infrared** na Flipper Zero. Ikiwa **inapata ishara katika database** Flipper itajua moja kwa moja **kifaa hiki ni kipi** na itakuruhusu kuingiliana nacho.\
Ikiwa haitapata, Flipper inaweza **kuhifadhi** **ishara** na itakuruhusu **kuicheza** tena.

## Marejeo

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
