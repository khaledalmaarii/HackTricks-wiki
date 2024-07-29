# Weaponizing Distroless

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## Qu'est-ce que Distroless

Un conteneur distroless est un type de conteneur qui **contient uniquement les dépendances nécessaires pour exécuter une application spécifique**, sans aucun logiciel ou outil supplémentaire qui ne soit pas requis. Ces conteneurs sont conçus pour être aussi **légers** et **sécurisés** que possible, et ils visent à **minimiser la surface d'attaque** en supprimant tout composant inutile.

Les conteneurs distroless sont souvent utilisés dans des **environnements de production où la sécurité et la fiabilité sont primordiales**.

Quelques **exemples** de **conteneurs distroless** sont :

* Fournis par **Google** : [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Fournis par **Chainguard** : [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

L'objectif de l'armement d'un conteneur distroless est de pouvoir **exécuter des binaires et des charges utiles arbitraires même avec les limitations** imposées par **distroless** (absence de binaires communs dans le système) et également des protections couramment trouvées dans les conteneurs telles que **lecture seule** ou **non-exécution** dans `/dev/shm`.

### À travers la mémoire

À venir à un moment donné de 2023...

### Via des binaires existants

#### openssl

****[**Dans cet article,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) il est expliqué que le binaire **`openssl`** est fréquemment trouvé dans ces conteneurs, potentiellement parce qu'il est **nécessaire** par le logiciel qui va s'exécuter à l'intérieur du conteneur.


{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
