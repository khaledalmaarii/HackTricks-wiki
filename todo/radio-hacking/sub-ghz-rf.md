# Sub-GHz RF

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Garage Doors

Vifaa vya kufungua milango ya garaji kwa kawaida vinatumia masafa katika anuwai ya 300-190 MHz, ambapo masafa ya kawaida ni 300 MHz, 310 MHz, 315 MHz, na 390 MHz. Anuwai hii ya masafa inatumika sana kwa sababu ni ya chini zaidi ikilinganishwa na bendi nyingine za masafa na ina uwezekano mdogo wa kukutana na usumbufu kutoka kwa vifaa vingine.

## Car Doors

Vifaa vingi vya funguo za magari vinatumia **315 MHz au 433 MHz**. Hizi ni masafa ya redio, na zinatumika katika matumizi mbalimbali tofauti. Tofauti kuu kati ya masafa haya mawili ni kwamba 433 MHz ina anuwai ndefu zaidi kuliko 315 MHz. Hii inamaanisha kwamba 433 MHz ni bora kwa matumizi yanayohitaji anuwai ndefu, kama vile kuingia bila funguo.\
Katika Ulaya 433.92MHz inatumika sana na nchini Marekani na Japani ni 315MHz.

## **Brute-force Attack**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

Ikiwa badala ya kutuma kila msimbo mara 5 (tumewekwa hivi ili kuhakikisha mpokeaji anaupata) unatumia kutuma mara moja tu, muda unakuwa wa dakika 6:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

na ikiwa **unafuta kipindi cha kusubiri cha 2 ms** kati ya ishara unaweza **kupunguza muda hadi dakika 3.**

Zaidi ya hayo, kwa kutumia Mfuatano wa De Bruijn (njia ya kupunguza idadi ya bits zinazohitajika kutuma nambari zote za binary zinazoweza kutumika kwa brute force) **muda huu unakuwa wa sekunde 8 tu**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Mfano wa shambulio hili ulitekelezwa katika [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Kuhitaji **preamble kutazuia uboreshaji wa Mfuatano wa De Bruijn** na **nambari zinazozunguka zitalinda shambulio hili** (ikiwa nambari ni ndefu vya kutosha ili isiweze kufanywa brute force).

## Sub-GHz Attack

Ili kushambulia ishara hizi kwa Flipper Zero angalia:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Rolling Codes Protection

Vifaa vya kufungua milango ya garaji kwa kawaida vinatumia kidhibiti cha mbali cha wireless kufungua na kufunga mlango wa garaji. Kidhibiti cha mbali **kinatuma ishara ya masafa ya redio (RF)** kwa kifaa cha kufungua mlango wa garaji, ambacho kinaanzisha motor kufungua au kufunga mlango.

Inawezekana kwa mtu kutumia kifaa kinachojulikana kama code grabber kukamata ishara ya RF na kuirekodi kwa matumizi ya baadaye. Hii inajulikana kama **replay attack**. Ili kuzuia aina hii ya shambulio, vifaa vingi vya kisasa vya kufungua milango ya garaji vinatumia njia salama zaidi ya usimbaji inayoitwa **rolling code**.

**Ishara ya RF kwa kawaida inatumika kwa kutumia nambari inayozunguka**, ambayo inamaanisha kwamba nambari hubadilika kila wakati inapotumika. Hii inafanya iwe **ngumu** kwa mtu **kukamata** ishara na **kuitumia** kupata **ufikiaji usioidhinishwa** kwa garaji.

Katika mfumo wa nambari zinazozunguka, kidhibiti cha mbali na kifaa cha kufungua mlango wa garaji vina **algorithms zinazoshirikiwa** ambazo **zinaunda nambari mpya** kila wakati kidhibiti kinapotumika. Kifaa cha kufungua mlango wa garaji kitajibu tu kwa **nambari sahihi**, na kufanya iwe ngumu zaidi kwa mtu kupata ufikiaji usioidhinishwa kwa garaji kwa kukamata nambari tu.

### **Missing Link Attack**

Kimsingi, unakusikia kwa kitufe na **kukamata ishara wakati kidhibiti kiko nje ya anuwai** ya kifaa (kama gari au garaji). Kisha unahamia kwenye kifaa na **kutumia nambari iliyokamatwa kufungua**.

### Full Link Jamming Attack

Mshambuliaji anaweza **kuzuia ishara karibu na gari au mpokeaji** ili **mpokeaji asisikilize nambari**, na mara hiyo ikitokea unaweza tu **kukamata na kurudisha** nambari wakati umesitisha kuzuiwa.

Mtu aliyeathirika kwa wakati fulani atatumia **funguo kufunga gari**, lakini kisha shambulio litakuwa **limerekodi nambari za "fungua mlango"** ambazo kwa matumaini zinaweza kutumwa tena kufungua mlango (**mabadiliko ya masafa yanaweza kuhitajika** kwani kuna magari yanayotumia nambari sawa kufungua na kufunga lakini yanakusikiliza amri zote mbili katika masafa tofauti).

{% hint style="warning" %}
**Kuzuiwa kunafanya kazi**, lakini kuna dalili kwani ikiwa **mtu anayefunga gari anajaribu milango** ili kuhakikisha zimefungwa wangeona gari likiwa wazi. Zaidi ya hayo, ikiwa wangejua kuhusu mashambulizi kama haya wangeweza hata kusikia ukweli kwamba milango hazikutoa **sauti** ya kufunga au **mwanga** wa magari haukudunda wakati walipobonyeza kitufe cha ‘fungua’.
{% endhint %}

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Hii ni **mbinu ya kuzuiwa ya siri zaidi**. Mshambuliaji atazuiya ishara, hivyo wakati mtu aliyeathirika anajaribu kufunga mlango haitafanya kazi, lakini mshambuliaji atarekodi **nambari hii**. Kisha, mtu aliyeathirika atajaribu **kufunga gari tena** kwa kubonyeza kitufe na gari litarekodi **nambari hii ya pili**.\
Mara moja baada ya hii **mshambuliaji anaweza kutuma nambari ya kwanza** na **gari litafungwa** (mtu aliyeathirika atadhani kubonyeza pili kumefunga). Kisha, mshambuliaji ataweza **kutuma nambari ya pili iliyoporwa kufungua** gari (ikiwa **"nambari ya kufunga gari" inaweza pia kutumika kufungua**). Mabadiliko ya masafa yanaweza kuhitajika (kama kuna magari yanayotumia nambari sawa kufungua na kufunga lakini yanakusikiliza amri zote mbili katika masafa tofauti).

Mshambuliaji anaweza **kuzuiya mpokeaji wa gari na si mpokeaji wake** kwa sababu ikiwa mpokeaji wa gari unasikiliza kwa mfano katika broadband ya 1MHz, mshambuliaji hata **zuiya** masafa halisi yanayotumiwa na kidhibiti lakini **masafa ya karibu katika anuwai hiyo** wakati **mpokeaji wa mshambuliaji utakuwa unasikiliza katika anuwai ndogo** ambapo anaweza kusikia ishara ya kidhibiti **bila ishara ya kuzuiwa**.

{% hint style="warning" %}
Utekelezaji mwingine ulioonekana katika maelezo unaonyesha kwamba **nambari inayozunguka ni sehemu** ya jumla ya nambari inayotumwa. Yaani, nambari inayotumwa ni **funguo ya 24 bit** ambapo **12 za kwanza ni nambari inayozunguka**, **8 za pili ni amri** (kama kufunga au kufungua) na **4 za mwisho ni** **checksum**. Magari yanayotekeleza aina hii pia yanahatarishwa kwa sababu mshambuliaji anahitaji tu kubadilisha sehemu ya nambari inayozunguka ili aweze **kutumia nambari yoyote inayozunguka katika masafa yote mawili**.
{% endhint %}

{% hint style="danger" %}
Kumbuka kwamba ikiwa mtu aliyeathirika atatuma nambari ya tatu wakati mshambuliaji anatuma ya kwanza, nambari ya kwanza na ya pili zitakuwa batili.
{% endhint %}

### Alarm Sounding Jamming Attack

Kujaribu dhidi ya mfumo wa nambari zinazozunguka uliowekwa kwenye gari, **kutuma nambari ile ile mara mbili** mara moja **kulizindua alamu** na immobiliser ikitoa fursa ya kipekee ya **kukataa huduma**. Kwa bahati mbaya, njia ya **kuzimisha alamu** na immobiliser ilikuwa **kubonyeza** **kidhibiti**, ikimpa mshambuliaji uwezo wa **kufanya shambulio la DoS mara kwa mara**. Au changanya shambulio hili na **la awali ili kupata nambari zaidi** kwani mtu aliyeathirika angependa kusitisha shambulio haraka iwezekanavyo.

## References

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
