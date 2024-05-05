# Uchambuzi wa faili za Ofisi

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii za **juu zaidi** ulimwenguni.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Kwa habari zaidi angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Hii ni muhtasari tu:

Microsoft imeunda muundo wa hati za ofisi nyingi, na aina mbili kuu ni **muundo wa OLE** (kama RTF, DOC, XLS, PPT) na **muundo wa Office Open XML (OOXML)** (kama DOCX, XLSX, PPTX). Muundo huu unaweza kuwa na macros, hivyo kuwa malengo ya udukuzi na zisizo. Faili za OOXML zimepangiliwa kama mifuko ya zip, kuruhusu uchunguzi kwa kufungua, kufunua muundo wa faili na folda na maudhui ya faili za XML.

Kuchunguza muundo wa faili za OOXML, amri ya kufungua faili na muundo wa matokeo hutolewa. Mbinu za kuficha data katika faili hizi zimeandikwa, ikionyesha ubunifu unaendelea katika kuficha data ndani ya changamoto za CTF.

Kwa uchambuzi, **oletools** na **OfficeDissector** hutoa seti kamili za zana za kuangalia hati za OLE na OOXML. Zana hizi husaidia katika kutambua na kuchambua macros zilizowekwa, ambazo mara nyingi hutumika kama njia za kusambaza zisizo, kawaida kupakua na kutekeleza malipo mabaya zaidi. Uchambuzi wa macros za VBA unaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, ambayo inaruhusu kwa kutatua matatizo na kuangalia mabadiliko.

Usanidi na matumizi ya **oletools** ni rahisi, na amri zimetolewa kwa usanidi kupitia pip na kutoa macros kutoka kwa hati. Utekelezaji wa moja kwa moja wa macros unachochea na kazi kama `AutoOpen`, `AutoExec`, au `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kujenga na **kutumia workflows** kwa urahisi zinazotumia zana za jamii **za juu zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
