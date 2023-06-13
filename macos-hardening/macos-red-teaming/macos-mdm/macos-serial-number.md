<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Les appareils Apple fabriqués après 2010 ont généralement des numéros de série alphanumériques de **12 caractères**, les **trois premiers chiffres représentant l'emplacement de fabrication**, les **deux suivants indiquant l'année** et la **semaine** de fabrication, les **trois suivants fournissant un identifiant unique**, et les **quatre derniers chiffres représentant le numéro de modèle**.

Exemple de numéro de série : **C02L13ECF8J2**

## **3 - Lieux de fabrication**

| Code | Usine |
| :--- | :--- |
| FC | Fountain Colorado, USA |
| F | Fremont, Californie, USA |
| XA, XB, QP, G8 | USA |
| RN | Mexique |
| CK | Cork, Irlande |
| VM | Foxconn, Pardubice, République tchèque |
| SG, E | Singapour |
| MB | Malaisie |
| PT, CY | Corée |
| EE, QT, UV | Taïwan |
| FK, F1, F2 | Foxconn - Zhengzhou, Chine |
| W8 | Shanghai Chine |
| DL, DM | Foxconn - Chine |
| DN | Foxconn, Chengdu, Chine |
| YM, 7J | Hon Hai/Foxconn, Chine |
| 1C, 4H, WQ, F7 | Chine |
| C0 | Tech Com - Filiale de Quanta Computer, Chine |
| C3 | Foxxcon, Shenzhen, Chine |
| C7 | Pentagone, Changhai, Chine |
| RM | Remis à neuf/remanufacturé |

## 1 - Année de fabrication

| Code | Sortie |
| :--- | :--- |
| C | 2010/2020 \(1ère moitié\) |
| D | 2010/2020 \(2ème moitié\) |
| F | 2011/2021 \(1ère moitié\) |
| G | 2011/2021 \(2ème moitié\) |
| H | 2012/... \(1ère moitié\) |
| J | 2012 \(2ème moitié\) |
| K | 2013 \(1ère moitié\) |
| L | 2013 \(2ème moitié\) |
| M | 2014 \(1ère moitié\) |
| N | 2014 \(2ème moitié\) |
| P | 2015 \(1ère moitié\) |
| Q | 2015 \(2ème moitié\) |
| R | 2016 \(1ère moitié\) |
| S | 2016 \(2ème moitié\) |
| T | 2017 \(1ère moitié\) |
| V | 2017 \(2ème moitié\) |
| W | 2018 \(1ère moitié\) |
| X | 2018 \(2ème moitié\) |
| Y | 2019 \(1ère moitié\) |
| Z | 2019 \(2ème moitié\) |

## 1 - Semaine de fabrication

Le cinquième caractère représente la semaine de fabrication de l'appareil. Il y a 28 caractères possibles à cet endroit : **les chiffres de 1 à 9 sont utilisés pour représenter les neuf premières semaines**, et les **caractères C à Y**, **à l'exception** des voyelles A, E, I, O et U, et de la lettre S, représentent les **dixième à vingt-septième semaines**. Pour les appareils fabriqués dans la **deuxième moitié de l'année, ajoutez 26** au nombre représenté par le cinquième caractère du numéro de série. Par exemple, un produit dont les quatrième et cinquième chiffres sont "JH" a été fabriqué dans la 40ème semaine de 2012.

## 3 - Code unique

Les trois chiffres suivants sont un code d'identification qui **sert à différencier chaque appareil Apple du même modèle** qui est fabriqué dans le même lieu et pendant la même semaine de la même année, en veillant à ce que chaque appareil ait un numéro de série différent.

## 4 - Numéro de série

Les quatre derniers chiffres du numéro de série représentent le **modèle du produit**.

## Référence

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

</details>
