# FZ - Infrared

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Utangulizi <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kwa habari zaidi kuhusu jinsi Infrared inavyofanya kazi, angalia:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Kipokezi cha Ishara ya IR katika Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper hutumia kipokezi cha ishara ya IR ya dijiti TSOP, ambayo **inaruhusu kukamata ishara kutoka kwa vidhibiti vya IR**. Kuna **simu za mkononi** kama Xiaomi, ambazo pia zina bandari ya IR, lakini kumbuka kuwa **nyingi yao zinaweza tu kutuma** ishara na **hazina uwezo wa kupokea**.

Kipokezi cha infrared cha Flipper ni **nyeti sana**. Unaweza hata **kukamata ishara** wakati uko **mahali popote kati** ya kiremote na TV. Hakuna haja ya kulenga kiremote moja kwa moja kwenye bandari ya IR ya Flipper. Hii inakuwa muhimu wakati mtu anabadilisha vituo wakati amesimama karibu na TV, na wewe na Flipper mko mbali kidogo.

Kwa kuwa **uwekaji wa ishara ya infrared** hufanyika upande wa **programu**, Flipper Zero inaweza kuunga mkono **upokeaji na utumaji wa nambari yoyote ya kiremote ya IR**. Katika kesi ya itifaki **isiojulikana** ambayo haiwezi kutambuliwa - ina **rekodi na kucheza** ishara safi kama ilivyopokelewa.

## Vitendo

### Vidhibiti vya Universal

Flipper Zero inaweza kutumika kama **kidhibiti cha kawaida kudhibiti TV yoyote, kiyoyozi, au kituo cha media**. Katika hali hii, Flipper **inajaribu nguvu** **nambari zote zinazojulikana** za watengenezaji wote wanaoungwa mkono **kulingana na kamusi kutoka kwenye kadi ya SD**. Hauhitaji kuchagua kiremote kimoja maalum kuizima TV ya mgahawa.

Inatosha kubonyeza kitufe cha nguvu katika hali ya Kidhibiti cha Universal, na Flipper itatuma **amri za "Kuzima"** kwa mfululizo kwa TV zote inazojua: Sony, Samsung, Panasonic... na kadhalika. Wakati TV inapokea ishara yake, itajibu na kuzima.

Udhibiti huu wa nguvu unachukua muda. Kamusi kubwa, ndivyo itakavyochukua muda mrefu kumaliza. Haiwezekani kujua ni ishara ipi hasa TV iliyotambua kwani hakuna mrejesho kutoka kwa TV.

### Jifunze Kiremote Kipya

Inawezekana **kukamata ishara ya infrared** na Flipper Zero. Ikiwa **inapata ishara katika database** Flipper itajua moja kwa moja **kifaa hiki ni kipi** na itakuruhusu kuingiliana nacho.\
Ikiwa haipati, Flipper inaweza **kuhifadhi** **ishara** na kukuruhusu **kuicheza tena**.

## Marejeo

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
