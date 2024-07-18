# Mbinu za ZIPs

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

**Zana za mstari wa amri** kwa ajili ya kusimamia **faili za zip** ni muhimu kwa kugundua, kurekebisha, na kuvunja faili za zip. Hapa kuna baadhi ya zana muhimu:

- **`unzip`**: Inaonyesha kwa nini faili ya zip huenda isifunguke.
- **`zipdetails -v`**: Inatoa uchambuzi wa kina wa uga wa muundo wa faili ya zip.
- **`zipinfo`**: Inaorodhesha maudhui ya faili ya zip bila kuzitoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Jaribu kurekebisha faili za zip zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana ya kuvunja nguvu ya nywila za zip, yenye ufanisi kwa nywila zenye herufi karibu 7.

[Specifikesheni ya muundo wa faili ya Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) hutoa maelezo kamili kuhusu muundo na viwango vya faili za zip.

Ni muhimu kutambua kwamba faili za zip zilizolindwa kwa nywila **hazifanyi faili za jina au ukubwa wa faili** ndani yake, kasoro ya usalama ambayo haishirikiwa na faili za RAR au 7z ambazo hulinda habari hii. Zaidi ya hayo, faili za zip zilizolindwa kwa njia ya ZipCrypto ya zamani ziko hatarini kwa **shambulio la maandishi wazi** ikiwa nakala isiyolindwa ya faili iliyosimbwa ipo. Shambulio hili hutumia yaliyomo kujaribu kuvunja nywila ya zip, kasoro iliyoelezwa kwa undani katika [makala ya HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) na kufafanuliwa zaidi katika [karatasi hii ya kisayansi](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Hata hivyo, faili za zip zilizolindwa na **AES-256** ziko salama dhidi ya shambulio hili la maandishi wazi, ikionyesha umuhimu wa kuchagua njia salama za kusimbua data nyeti.

## Marejeo
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/) 

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks ya Mtaalam wa Timu Nyekundu ya GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>unga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
