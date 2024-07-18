# Uchambuzi wa faili za Ofisi

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) kujenga na **kujiendesha kiotomatiki** kwa urahisi kwa kutumia zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

Kwa maelezo zaidi angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Hii ni muhtasari tu:

Microsoft imeunda aina nyingi za hati za ofisi, ambapo aina mbili kuu ni **OLE formats** (kama RTF, DOC, XLS, PPT) na **Office Open XML (OOXML) formats** (kama DOCX, XLSX, PPTX). Aina hizi zinaweza kujumuisha macros, na kuifanya kuwa malengo ya phishing na malware. Faili za OOXML zimeundwa kama vyombo vya zip, kuruhusu ukaguzi kupitia kufungua, kuonyesha muundo wa faili na folda na maudhui ya faili ya XML.

Ili kuchunguza muundo wa faili za OOXML, amri ya kufungua hati na muundo wa matokeo zimepewa. Mbinu za kuficha data katika faili hizi zimeandikwa, zikionyesha uvumbuzi unaoendelea katika kuficha data ndani ya changamoto za CTF.

Kwa uchambuzi, **oletools** na **OfficeDissector** hutoa seti kamili za zana za kuchunguza hati za OLE na OOXML. Zana hizi husaidia katika kutambua na kuchambua macros zilizojumuishwa, ambazo mara nyingi hutumikia kama njia za usambazaji wa malware, kwa kawaida zinapakua na kutekeleza mzigo mbaya wa ziada. Uchambuzi wa macros za VBA unaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, ambayo inaruhusu ufuatiliaji kwa kutumia alama za kuvunja na kutazama mabadiliko.

Usakinishaji na matumizi ya **oletools** ni rahisi, huku amri zikitolewa kwa usakinishaji kupitia pip na kutoa macros kutoka kwa hati. Utendaji wa kiotomatiki wa macros unachochewa na kazi kama `AutoOpen`, `AutoExec`, au `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) kujenga na **kujiendesha** kazi kwa urahisi zenye nguvu za zana za jamii **za kisasa zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
