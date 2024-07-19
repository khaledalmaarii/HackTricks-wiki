# Infrared

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

## How the Infrared Works <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Mwanga wa infrared hauonekani kwa wanadamu**. Urefu wa mawimbi ya IR ni kutoka **0.7 hadi 1000 microns**. Remote za nyumbani hutumia ishara ya IR kwa ajili ya uhamasishaji wa data na zinafanya kazi katika wigo wa mawimbi wa 0.75..1.4 microns. Microcontroller katika remote inafanya LED ya infrared kung'ara kwa mzunguko maalum, ikigeuza ishara ya dijitali kuwa ishara ya IR.

Ili kupokea ishara za IR, **photoreceiver** hutumiwa. In **abadilisha mwanga wa IR kuwa mapigo ya voltage**, ambayo tayari ni **ishara za dijitali**. Kawaida, kuna **filter ya mwanga mweusi ndani ya mpokeaji**, ambayo inaruhusu **tu urefu wa mawimbi unaotakiwa kupita** na kuondoa kelele.

### Variety of IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Protokali za IR zinatofautiana katika mambo 3:

* uandishi wa bit
* muundo wa data
* mzunguko wa kubeba — mara nyingi katika wigo wa 36..38 kHz

#### Bit encoding ways <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bits zinaandikwa kwa kubadilisha muda wa nafasi kati ya mapigo. Upana wa pigo lenyewe ni thabiti.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bits zinaandikwa kwa kubadilisha upana wa pigo. Upana wa nafasi baada ya mlipuko wa pigo ni thabiti.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Inajulikana pia kama uandishi wa Manchester. Thamani ya mantiki inafafanuliwa na polarity ya mpito kati ya mlipuko wa pigo na nafasi. "Nafasi hadi mlipuko wa pigo" inaashiria mantiki "0", "mlipuko wa pigo hadi nafasi" inaashiria mantiki "1".

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combination of previous ones and other exotics**

{% hint style="info" %}
Kuna protokali za IR ambazo **zinajaribu kuwa za ulimwengu mzima** kwa aina kadhaa za vifaa. Zile maarufu ni RC5 na NEC. Kwa bahati mbaya, maarufu zaidi **haimaanishi za kawaida zaidi**. Katika mazingira yangu, nilikutana na remote mbili za NEC na hakuna RC5.

Watengenezaji wanapenda kutumia protokali zao za IR za kipekee, hata ndani ya safu moja ya vifaa (kwa mfano, TV-boxes). Kwa hivyo, remotes kutoka kampuni tofauti na wakati mwingine kutoka mifano tofauti kutoka kampuni moja, hazina uwezo wa kufanya kazi na vifaa vingine vya aina hiyo.
{% endhint %}

### Exploring an IR signal

Njia ya kuaminika zaidi ya kuona jinsi ishara ya IR ya remote inavyoonekana ni kutumia oscilloscope. Haifanyi demodulation au kugeuza ishara iliyopokelewa, inonyeshwa tu "kama ilivyo". Hii ni muhimu kwa ajili ya kupima na kutatua matatizo. Nitaonyesha ishara inayotarajiwa kwa mfano wa protokali ya NEC IR.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Kawaida, kuna preamble mwanzoni mwa pakiti iliyowekwa. Hii inaruhusu mpokeaji kubaini kiwango cha gain na mandharinyuma. Pia kuna protokali bila preamble, kwa mfano, Sharp.

Kisha data inatumwa. Muundo, preamble, na njia ya uandishi wa bit zinatambulishwa na protokali maalum.

**Protokali ya NEC IR** ina amri fupi na nambari ya kurudia, ambayo inatumwa wakati kifungo kinashinikizwa. Zote amri na nambari ya kurudia zina preamble sawa mwanzoni.

**Amri ya NEC**, mbali na preamble, ina byte ya anwani na byte ya nambari ya amri, ambayo kifaa kinaelewa kinachohitajika kutekelezwa. Byte za anwani na nambari ya amri zinajirudia kwa thamani za kinyume, ili kuangalia uadilifu wa uhamasishaji. Kuna bit ya kusitisha ya ziada mwishoni mwa amri.

**Nambari ya kurudia** ina "1" baada ya preamble, ambayo ni bit ya kusitisha.

Kwa **mantiki "0" na "1"** NEC inatumia Pulse Distance Encoding: kwanza, mlipuko wa pigo unatumwa baada ya hapo kuna mapumziko, urefu wake unakamilisha thamani ya bit.

### Air Conditioners

Tofauti na remotes nyingine, **viyoyozi havitumii tu nambari ya kifungo kilichoshinikizwa**. Pia **hutoa taarifa zote** wakati kifungo kinashinikizwa ili kuhakikisha kwamba **kifaa cha viyoyozi na remote vinapatana**.\
Hii itazuia kwamba mashine iliyowekwa kama 20ºC inainuliwa hadi 21ºC kwa remote moja, na kisha wakati remote nyingine, ambayo bado ina joto kama 20ºC, inatumika kuongeza zaidi joto, itakuwa "inaongeza" hadi 21ºC (na si 22ºC ikidhani iko katika 21ºC).

### Attacks

You can attack Infrared with Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## References

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

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
