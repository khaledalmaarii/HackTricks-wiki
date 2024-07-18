# Analiza Office datoteka

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim **alatima** zajednice.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

Za više informacija proverite [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:

Microsoft je kreirao mnoge formate Office dokumenata, pri čemu su dva glavna tipa **OLE formati** (kao što su RTF, DOC, XLS, PPT) i **Office Open XML (OOXML) formati** (kao što su DOCX, XLSX, PPTX). Ovi formati mogu uključivati makroe, što ih čini metama za phishing i malware. OOXML datoteke su strukturirane kao zip kontejneri, što omogućava inspekciju kroz raspakivanje, otkrivajući hijerarhiju datoteka i foldera i sadržaj XML datoteka.

Da bi se istražile strukture OOXML datoteka, data je komanda za raspakivanje dokumenta i struktura izlaza. Tehnike za skrivanje podataka u ovim datotekama su dokumentovane, što ukazuje na kontinuiranu inovaciju u skrivanju podataka unutar CTF izazova.

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne alate za ispitivanje kako OLE tako i OOXML dokumenata. Ovi alati pomažu u identifikaciji i analizi ugrađenih makroa, koji često služe kao vektori za isporuku malware-a, obično preuzimajući i izvršavajući dodatne zlonamerne pakete. Analiza VBA makroa može se izvršiti bez Microsoft Office-a korišćenjem Libre Office-a, koji omogućava debagovanje sa tačkama prekida i posmatranim promenljivama.

Instalacija i korišćenje **oletools** su jednostavni, sa komandama za instalaciju putem pip-a i vađenje makroa iz dokumenata. Automatsko izvršavanje makroa se pokreće funkcijama kao što su `AutoOpen`, `AutoExec` ili `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=office-file-analysis) da lako izgradite i **automatizujete radne tokove** pokretane od strane **najnaprednijih** alata zajednice.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=office-file-analysis" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
