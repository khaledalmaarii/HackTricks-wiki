# Mbinu za ZIPs

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Zana za amri** za kusimamia **faili za zip** ni muhimu kwa kuchunguza, kurekebisha, na kudukua faili za zip. Hapa kuna zana muhimu:

- **`unzip`**: Inaonyesha sababu kwa nini faili ya zip haiwezi kufunguliwa.
- **`zipdetails -v`**: Hutoa uchambuzi wa kina wa uwanja wa muundo wa faili ya zip.
- **`zipinfo`**: Inaorodhesha maudhui ya faili ya zip bila kuyatoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Jaribu kurekebisha faili za zip zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana ya kudukua nywila za zip kwa kutumia nguvu ya kubashiri, inafaa kwa nywila zenye herufi hadi takriban 7.

[Maelezo ya muundo wa faili ya zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) hutoa maelezo kamili juu ya muundo na viwango vya faili za zip.

Ni muhimu kuzingatia kuwa faili za zip zilizolindwa kwa nywila **hazifichii majina ya faili au ukubwa wa faili** ndani yake, ni dosari ya usalama ambayo haishirikiwa na faili za RAR au 7z ambazo huficha habari hii kwa kuzificha. Zaidi ya hayo, faili za zip zilizolindwa kwa njia ya ZipCrypto ya zamani ziko hatarini kwa **shambulio la maandishi wazi** ikiwa nakala isiyolindwa ya faili iliyopunguzwa ipo. Shambulio hili linatumia yaliyomo yanayojulikana kudukua nywila ya zip, dosari ambayo imeelezewa kwa undani katika [makala ya HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) na kufafanuliwa zaidi katika [karatasi hii ya kisayansi](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf). Walakini, faili za zip zilizolindwa kwa **AES-256** ziko salama dhidi ya shambulio hili la maandishi wazi, ikionyesha umuhimu wa kuchagua njia salama za kusimbua data nyeti.

## Marejeo
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
