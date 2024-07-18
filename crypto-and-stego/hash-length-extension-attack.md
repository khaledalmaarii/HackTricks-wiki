# Hash Length Extension Attack

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark-web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **malwares voleurs**.

Leur objectif principal avec WhiteIntel est de lutter contre les prises de contrôle de comptes et les attaques par ransomware résultant de malwares de vol d'informations.

Vous pouvez consulter leur site web et essayer leur moteur **gratuitement** à :

{% embed url="https://whiteintel.io" %}

***

## Résumé de l'attaque

Imaginez un serveur qui **signe** certaines **données** en **ajoutant** un **secret** à des données en clair connues, puis en hachant ces données. Si vous savez :

* **La longueur du secret** (cela peut également être bruteforcé à partir d'une plage de longueurs donnée)
* **Les données en clair**
* **L'algorithme (et il est vulnérable à cette attaque)**
* **Le remplissage est connu**
* En général, un défaut est utilisé, donc si les 3 autres exigences sont remplies, cela l'est aussi
* Le remplissage varie en fonction de la longueur du secret + données, c'est pourquoi la longueur du secret est nécessaire

Alors, il est possible pour un **attaquant** d'**ajouter** des **données** et de **générer** une **signature** valide pour les **données précédentes + données ajoutées**.

### Comment ?

Fondamentalement, les algorithmes vulnérables génèrent les hachages en **hachant d'abord un bloc de données**, puis, **à partir** du **hachage précédemment** créé (état), ils **ajoutent le prochain bloc de données** et **le hachent**.

Ensuite, imaginez que le secret est "secret" et que les données sont "data", le MD5 de "secretdata" est 6036708eba0d11f6ef52ad44e8b74d5b.\
Si un attaquant veut ajouter la chaîne "append", il peut :

* Générer un MD5 de 64 "A"
* Changer l'état du hachage précédemment initialisé en 6036708eba0d11f6ef52ad44e8b74d5b
* Ajouter la chaîne "append"
* Terminer le hachage et le hachage résultant sera un **valide pour "secret" + "data" + "padding" + "append"**

### **Outil**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Références

Vous pouvez trouver cette attaque bien expliquée sur [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) est un moteur de recherche alimenté par le **dark-web** qui offre des fonctionnalités **gratuites** pour vérifier si une entreprise ou ses clients ont été **compromis** par des **malwares voleurs**.

Leur objectif principal avec WhiteIntel est de lutter contre les prises de contrôle de comptes et les attaques par ransomware résultant de malwares de vol d'informations.

Vous pouvez consulter leur site web et essayer leur moteur **gratuitement** à :

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
