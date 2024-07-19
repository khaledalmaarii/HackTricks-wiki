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
{% endhint %}


# Kutambua binaries zilizopakizwa

* **ukosefu wa nyuzi**: Ni kawaida kukutana na binaries zilizopakizwa ambazo hazina karibu nyuzi yoyote
* Nyuzi nyingi **zisizotumika**: Pia, wakati malware inatumia aina fulani ya pakka ya kibiashara ni kawaida kukutana na nyuzi nyingi zisizo na marejeo. Hata kama nyuzi hizi zipo, hiyo haimaanishi kwamba binary haijapakizwa.
* Unaweza pia kutumia zana fulani kujaribu kubaini ni pakka ipi ilitumika kupakia binary:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Mapendekezo Msingi

* **Anza** kuchambua binary iliyopakizwa **kutoka chini katika IDA na panda juu**. Unpackers huondoka mara tu msimbo ulioondolewa unapoondoka, hivyo ni vigumu kwa unpacker kuhamasisha utekelezaji kwa msimbo ulioondolewa mwanzoni.
* Tafuta **JMP's** au **CALLs** kwa **registers** au **mikoa** ya **kumbukumbu**. Pia tafuta **kazi zinazoweka hoja na mwelekeo wa anwani kisha kuita `retn`**, kwa sababu kurudi kwa kazi katika kesi hiyo kunaweza kuita anwani iliyowekwa tu kwenye stack kabla ya kuitwa.
* Weka **breakpoint** kwenye `VirtualAlloc` kwani hii inatoa nafasi katika kumbukumbu ambapo programu inaweza kuandika msimbo ulioondolewa. "enda kwa msimbo wa mtumiaji" au tumia F8 ili **kupata thamani ndani ya EAX** baada ya kutekeleza kazi na "**fuata anwani hiyo katika dump**". Hujui kama hiyo ndiyo mkoa ambapo msimbo ulioondolewa utaokolewa.
* **`VirtualAlloc`** ikiwa na thamani "**40**" kama hoja inamaanisha Soma+Andika+Tekeleza (msimbo fulani unaohitaji utekelezaji utawekwa hapa).
* **Wakati wa kuondoa** msimbo ni kawaida kukutana na **simu kadhaa** kwa **operesheni za hesabu** na kazi kama **`memcopy`** au **`Virtual`**`Alloc`. Ikiwa unajikuta katika kazi ambayo kwa wazi inafanya tu operesheni za hesabu na labda `memcopy`, mapendekezo ni kujaribu **kupata mwisho wa kazi** (labda JMP au simu kwa register fulani) **au** angalau **simu kwa kazi ya mwisho** na uende huko kwani msimbo si wa kuvutia.
* Wakati wa kuondoa msimbo **kumbuka** kila wakati unapobadilisha **mkoa wa kumbukumbu** kwani mabadiliko ya mkoa wa kumbukumbu yanaweza kuashiria **kuanza kwa msimbo wa kuondoa**. Unaweza kwa urahisi dump mkoa wa kumbukumbu ukitumia Process Hacker (mchakato --> mali --> kumbukumbu).
* Wakati wa kujaribu kuondoa msimbo njia nzuri ya **kujua kama tayari unafanya kazi na msimbo ulioondolewa** (hivyo unaweza tu kuudondoa) ni **kuangalia nyuzi za binary**. Ikiwa katika wakati fulani unafanya jump (labda kubadilisha mkoa wa kumbukumbu) na unagundua kwamba **nyuzi nyingi zaidi zimeongezwa**, basi unaweza kujua **unafanya kazi na msimbo ulioondolewa**.\
Hata hivyo, ikiwa pakka tayari ina nyuzi nyingi unaweza kuona ni nyuzi ngapi zina neno "http" na kuona ikiwa nambari hii inaongezeka.
* Unapodondoa executable kutoka mkoa wa kumbukumbu unaweza kurekebisha baadhi ya vichwa kwa kutumia [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

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
</details>
{% endhint %}
