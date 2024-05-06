# Uchambuzi wa faili za Ofisi

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii za **juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

Kwa habari zaidi angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Hii ni muhtasari tu:

Microsoft imeunda muundo wa hati nyingi za ofisi, na aina mbili kuu ni **muundo wa OLE** (kama RTF, DOC, XLS, PPT) na **muundo wa Office Open XML (OOXML)** (kama DOCX, XLSX, PPTX). Muundo huu unaweza kuwa na macros, hivyo kuwa malengo ya udukuzi na zisizo. Faili za OOXML zimepangiliwa kama mifuko ya zip, kuruhusu uchunguzi kupitia kufungua, kufunua faili na muundo wa folda na maudhui ya faili za XML.

Kuchunguza muundo wa faili za OOXML, amri ya kufungua faili na muundo wa matokeo zimetolewa. Mbinu za kuficha data katika faili hizi zimeandikwa, ikionyesha ubunifu unaendelea katika kuficha data katika changamoto za CTF.

Kwa uchambuzi, **oletools** na **OfficeDissector** hutoa seti kamili za zana za kuangalia hati za OLE na OOXML. Zana hizi husaidia katika kutambua na kuchambua macros zilizowekwa, ambazo mara nyingi hutumika kama njia za kusambaza zisizo, kwa kawaida kupakua na kutekeleza malipo mabaya zaidi. Uchambuzi wa macros za VBA unaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, ambayo inaruhusu kwa kutatua matatizo na kuangalia mabadiliko.

Usanidi na matumizi ya **oletools** ni rahisi, na amri zimetolewa kwa ajili ya kusakinisha kupitia pip na kutoa macros kutoka kwa hati. Utekelezaji wa moja kwa moja wa macros unachochea na kazi kama vile `AutoOpen`, `AutoExec`, au `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
