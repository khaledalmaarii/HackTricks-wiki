# FZ - Infrared

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

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kwa maelezo zaidi kuhusu jinsi Infrared inavyofanya kazi angalia:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper inatumia mpokeaji wa ishara za dijitali za IR TSOP, ambayo **inaruhusu kukamata ishara kutoka kwa IR remotes**. Kuna baadhi ya **smartphones** kama Xiaomi, ambazo pia zina bandari ya IR, lakini kumbuka kwamba **zaidi ya hizo zinaweza tu kutuma** ishara na **hazina uwezo wa kupokea** hizo.

Mpokeaji wa infrared wa Flipper **ni nyeti sana**. Unaweza hata **kukamata ishara** wakati uko **mahali fulani kati** ya remote na TV. Kuelekeza remote moja kwa moja kwenye bandari ya IR ya Flipper si lazima. Hii ni muhimu wakati mtu anabadilisha vitu wakati anasimama karibu na TV, na wewe na Flipper mko mbali kidogo.

Kadri **ufafanuzi wa ishara za infrared** unavyofanyika upande wa **programu**, Flipper Zero ina uwezo wa kuunga mkono **kupokea na kutuma nambari zozote za IR remote**. Katika kesi ya **protokali zisizojulikana** ambazo hazikuweza kutambuliwa - inarekodi na kurudisha **ishara safi kama ilivyopokelewa**.

## Actions

### Universal Remotes

Flipper Zero inaweza kutumika kama **remote ya ulimwengu kuendesha TV yoyote, kiyoyozi, au kituo cha media**. Katika hali hii, Flipper **inajaribu** nambari zote **zinazojulikana** za wazalishaji wote wanaoungwa mkono **kulingana na kamusi kutoka kwenye kadi ya SD**. Huna haja ya kuchagua remote maalum ili kuzima TV ya mgahawa.

Inatosha kubonyeza kitufe cha nguvu katika hali ya Universal Remote, na Flipper itatuma **kwa mpangilio amri za "Power Off"** za TV zote inazozijua: Sony, Samsung, Panasonic... na kadhalika. Wakati TV inapokea ishara yake, itajibu na kuzima.

Hii brute-force inachukua muda. Kadri kamusi inavyokuwa kubwa, ndivyo itachukua muda mrefu kumaliza. Haiwezekani kujua ni ishara ipi hasa TV ilitambua kwani hakuna mrejesho kutoka kwa TV.

### Learn New Remote

Inawezekana **kukamata ishara ya infrared** na Flipper Zero. Ikiwa **inatambua ishara katika hifadhidata** Flipper itajua moja kwa moja **ni kifaa gani hiki** na itakuruhusu kuingiliana nacho.\
Ikiwa haitambui, Flipper inaweza **kuhifadhi** **ishara** na itakuruhusu **kuirudisha**.

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
