# Analiza Office fajlova

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** uz pomoć najnaprednijih alata zajednice.\
Danas dobijte pristup:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}


Za dalje informacije proverite [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:


Microsoft je kreirao mnogo formata za office dokumente, pri čemu su dva glavna tipa **OLE formati** (kao što su RTF, DOC, XLS, PPT) i **Office Open XML (OOXML) formati** (kao što su DOCX, XLSX, PPTX). Ovi formati mogu sadržati makroe, što ih čini metama za phishing i malver. OOXML fajlovi su strukturirani kao zip kontejneri, što omogućava inspekciju kroz dekompresiju, otkrivajući hijerarhiju fajlova i foldera i sadržaj XML fajlova.

Za istraživanje struktura OOXML fajlova, daje se komanda za dekompresiju dokumenta i struktura izlaza. Tehnike za skrivanje podataka u ovim fajlovima su dokumentovane, što ukazuje na kontinuiranu inovaciju u prikrivanju podataka u okviru CTF izazova.

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne alate za ispitivanje kako OLE, tako i OOXML dokumenata. Ovi alati pomažu u identifikaciji i analizi ugrađenih makroa, koji često služe kao vektori za isporuku malvera, obično preuzimanje i izvršavanje dodatnih zlonamernih payloada. Analiza VBA makroa može se izvršiti bez Microsoft Office-a korišćenjem Libre Office-a, koji omogućava debagovanje sa prekidnim tačkama i promenljivim vrednostima.

Instalacija i korišćenje **oletools**-a su jednostavni, sa pruženim komandama za instalaciju putem pip-a i izdvajanje makroa iz dokumenata. Automatsko izvršavanje makroa pokreće se funkcijama poput `AutoOpen`, `AutoExec` ili `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** podržane najnaprednijim alatima zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
