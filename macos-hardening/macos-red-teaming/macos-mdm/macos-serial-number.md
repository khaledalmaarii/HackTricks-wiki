# Numéro de série macOS

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Les appareils Apple fabriqués après 2010 ont généralement des numéros de série **alphanumériques de 12 caractères**, avec les **trois premiers chiffres représentant le lieu de fabrication**, les **deux suivants** indiquant l'**année** et la **semaine** de fabrication, les **trois chiffres suivants** fournissant un **identifiant unique**, et les **quatre derniers chiffres représentant le numéro de modèle**.

Exemple de numéro de série : **C02L13ECF8J2**

### **3 - Lieux de fabrication**

| Code           | Usine                                        |
| -------------- | -------------------------------------------- |
| FC             | Fountain Colorado, USA                       |
| F              | Fremont, Californie, USA                     |
| XA, XB, QP, G8 | USA                                          |
| RN             | Mexique                                      |
| CK             | Cork, Irlande                                |
| VM             | Foxconn, Pardubice, République tchèque       |
| SG, E          | Singapour                                    |
| MB             | Malaisie                                     |
| PT, CY         | Corée                                        |
| EE, QT, UV     | Taïwan                                       |
| FK, F1, F2     | Foxconn – Zhengzhou, Chine                   |
| W8             | Shanghai Chine                               |
| DL, DM         | Foxconn – Chine                              |
| DN             | Foxconn, Chengdu, Chine                      |
| YM, 7J         | Hon Hai/Foxconn, Chine                       |
| 1C, 4H, WQ, F7 | Chine                                        |
| C0             | Tech Com – Filiale de Quanta Computer, Chine |
| C3             | Foxxcon, Shenzhen, Chine                     |
| C7             | Pentragon, Changhai, Chine                   |
| RM             | Reconditionné/remis à neuf                   |

### 1 - Année de fabrication

| Code | Sortie               |
| ---- | -------------------- |
| C    | 2010/2020 (1er semestre) |
| D    | 2010/2020 (2e semestre)  |
| F    | 2011/2021 (1er semestre) |
| G    | 2011/2021 (2e semestre)  |
| H    | 2012/... (1er semestre)  |
| J    | 2012 (2e semestre)       |
| K    | 2013 (1er semestre)      |
| L    | 2013 (2e semestre)       |
| M    | 2014 (1er semestre)      |
| N    | 2014 (2e semestre)       |
| P    | 2015 (1er semestre)      |
| Q    | 2015 (2e semestre)       |
| R    | 2016 (1er semestre)      |
| S    | 2016 (2e semestre)       |
| T    | 2017 (1er semestre)      |
| V    | 2017 (2e semestre)       |
| W    | 2018 (1er semestre)      |
| X    | 2018 (2e semestre)       |
| Y    | 2019 (1er semestre)      |
| Z    | 2019 (2e semestre)       |

### 1 - Semaine de fabrication

Le cinquième caractère représente la semaine pendant laquelle l'appareil a été fabriqué. Il y a 28 caractères possibles à cet endroit : **les chiffres 1-9 sont utilisés pour représenter les première à neuvième semaines**, et les **caractères C à Y**, **à l'exception** des voyelles A, E, I, O, et U, et de la lettre S, représentent les **dixième à vingt-septième semaines**. Pour les appareils fabriqués dans la **seconde moitié de l'année, ajoutez 26** au nombre représenté par le cinquième caractère du numéro de série. Par exemple, un produit dont les quatrième et cinquième chiffres du numéro de série sont “JH” a été fabriqué la 40ème semaine de 2012.

### 3 - Code Unique

Les trois chiffres suivants sont un code identifiant qui **sert à différencier chaque appareil Apple du même modèle** fabriqué au même endroit et pendant la même semaine de la même année, garantissant que chaque appareil a un numéro de série différent.

### 4 - Numéro de série

Les quatre derniers chiffres du numéro de série représentent le **modèle du produit**.

### Référence

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
