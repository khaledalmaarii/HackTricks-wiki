# Mbinu za ZIPs

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Zana za mstari wa amri** kwa kusimamia **faili za zip** ni muhimu kwa kugundua, kurekebisha, na kuvunja faili za zip. Hapa kuna zana muhimu:

- **`unzip`**: Inaonyesha kwa nini faili ya zip inaweza kutofautisha.
- **`zipdetails -v`**: Inatoa uchambuzi wa kina wa uga wa muundo wa faili ya zip.
- **`zipinfo`**: Inaorodhesha maudhui ya faili ya zip bila kuzitoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Jaribu kurekebisha faili za zip zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana ya kuvunja nguvu ya nywila za zip, yenye ufanisi kwa nywila hadi karibu wahusika 7.

[Specifikesheni ya muundo wa faili ya Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) hutoa maelezo kamili juu ya muundo na viwango vya faili za zip.

Ni muhimu kutambua kuwa faili za zip zilizolindwa kwa nywila **hazifichi majina ya faili au ukubwa wa faili** ndani yake, kasoro ya usalama ambayo haishirikiwa na faili za RAR au 7z ambazo huchifua habari hii. Zaidi ya hayo, faili za zip zilizolindwa na njia ya zamani ya ZipCrypto ziko hatarini kwa **shambulio la maandishi wazi** ikiwa nakala isiyochifua ya faili iliyosongeshwa inapatikana. Shambulio hili linatumia yaliyomo yanayojulikana kuvunja nywila ya zip, udhaifu ulioelezewa kwa undani katika [makala ya HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) na kufafanuliwa zaidi katika [karatasi hii ya kisayansi](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Hata hivyo, faili za zip zilizolindwa na **AES-256** ziko salama kutokana na shambulio hili la maandishi wazi, ikionyesha umuhimu wa kuchagua njia salama za kuchifua data nyeti.

## Marejeo
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
