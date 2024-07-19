# macOS AppleFS

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** ni mfumo wa kisasa wa faili ulioandaliwa ili kubadilisha Mfumo wa Faili wa Kihierarkia Plus (HFS+). Maendeleo yake yalichochewa na hitaji la **kuboresha utendaji, usalama, na ufanisi**.

Baadhi ya vipengele muhimu vya APFS ni pamoja na:

1. **Kushiriki Nafasi**: APFS inaruhusu volumu nyingi **kushiriki hifadhi ya bure ya msingi** kwenye kifaa kimoja cha kimwili. Hii inaruhusu matumizi bora ya nafasi kwani volumu zinaweza kukua na kupungua kwa njia ya kidijitali bila haja ya kubadilisha ukubwa au kugawanya upya.
1. Hii inamaanisha, ikilinganishwa na sehemu za jadi katika diski za faili, **kwamba katika APFS sehemu tofauti (volumu) zinashiriki nafasi yote ya diski**, wakati sehemu ya kawaida mara nyingi ilikuwa na ukubwa wa kudumu.
2. **Snapshots**: APFS inasaidia **kuunda snapshots**, ambazo ni **za kusoma tu**, matukio ya wakati wa mfumo wa faili. Snapshots zinaruhusu nakala za haraka na urahisi wa kurudi nyuma kwa mfumo, kwani zinatumia hifadhi ya ziada kidogo na zinaweza kuundwa au kurejeshwa haraka.
3. **Clones**: APFS inaweza **kuunda clones za faili au saraka zinazoshiriki hifadhi ile ile** kama ya asili hadi clone au faili ya asili ibadilishwe. Kipengele hiki kinatoa njia bora ya kuunda nakala za faili au saraka bila kuiga nafasi ya hifadhi.
4. **Ushirikiano**: APFS **inasaidia kwa asili usimbaji wa diski nzima** pamoja na usimbaji wa faili na saraka, ikiongeza usalama wa data katika matumizi tofauti.
5. **Ulinzi wa Ajali**: APFS inatumia **mpango wa metadata wa nakala-katika-k写 ambao unahakikisha uthabiti wa mfumo wa faili** hata katika matukio ya kupoteza nguvu ghafla au ajali za mfumo, ikipunguza hatari ya uharibifu wa data.

Kwa ujumla, APFS inatoa mfumo wa faili wa kisasa, rahisi, na wenye ufanisi kwa vifaa vya Apple, ukiwa na mkazo wa kuboresha utendaji, uaminifu, na usalama.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

The `Data` volume is mounted in **`/System/Volumes/Data`** (you can check this with `diskutil apfs list`).

Orodha ya firmlinks inaweza kupatikana katika faili ya **`/usr/share/firmlinks`**.
```bash
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
