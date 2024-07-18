# Uingizaji wa Chromium kwenye macOS

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Taarifa Msingi

Vivinjari vilivyojengwa kwenye Chromium kama Google Chrome, Microsoft Edge, Brave, na vinginevyo. Vivinjari hivi vimejengwa kwenye mradi wa chanzo wazi wa Chromium, maana yake vinashiriki msingi wa pamoja na, kwa hivyo, vinafanana kwa kazi na chaguo za watengenezaji.

#### Bendera ya `--load-extension`

Bendera ya `--load-extension` hutumiwa wakati wa kuanzisha kivinjari kilichojengwa kwenye Chromium kutoka kwenye mstari wa amri au skripti. Bendera hii inaruhusu **kupakia moja au zaidi ya nyongeza moja kwa moja** kwenye kivinjari wakati wa kuanzisha.

#### Bendera ya `--use-fake-ui-for-media-stream`

Bendera ya `--use-fake-ui-for-media-stream` ni chaguo lingine la mstari wa amri linaloweza kutumika kuanzisha vivinjari vilivyotegemea Chromium. Bendera hii imeundwa **kupuuza maombi ya kawaida ya mtumiaji yanayotaka idhini ya kupata mitiririko ya media kutoka kamera na mikrofoni**. Wakati bendera hii inapotumiwa, kivinjari kinatoa idhini moja kwa moja kwa wavuti au programu yoyote inayotaka kupata kamera au mikrofoni.

### Zana

* [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
* [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Mfano
```bash
# Intercept traffic
voodoo intercept -b chrome
```
## Marejeo

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{% hint style="success" %}
Jifunze na zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks kwa Wataalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks kwa Wataalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
