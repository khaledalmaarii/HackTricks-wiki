# Large Recherche de Code Source

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

L'objectif de cette page est d'énumérer **les plateformes qui permettent de rechercher du code** (littéral ou regex) à travers des milliers/millions de dépôts sur une ou plusieurs plateformes.

Cela aide dans plusieurs occasions à **rechercher des informations divulguées** ou des **modèles de vulnérabilités**.

* [**SourceGraph**](https://sourcegraph.com/search) : Recherchez dans des millions de dépôts. Il existe une version gratuite et une version entreprise (avec 15 jours gratuits). Il prend en charge les regex.
* [**Recherche Github**](https://github.com/search) : Recherchez sur Github. Il prend en charge les regex.
* Peut-être qu'il est également utile de vérifier [**Recherche de Code Github**](https://cs.github.com/).
* [**Recherche Avancée Gitlab**](https://docs.gitlab.com/ee/user/search/advanced\_search.html) : Recherchez dans les projets Gitlab. Prend en charge les regex.
* [**SearchCode**](https://searchcode.com/) : Recherchez du code dans des millions de projets.

{% hint style="warning" %}
Lorsque vous recherchez des fuites dans un dépôt et exécutez quelque chose comme `git log -p`, n'oubliez pas qu'il pourrait y avoir **d'autres branches avec d'autres commits** contenant des secrets !
{% endhint %}

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
