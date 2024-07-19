# macOS AppleFS

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Système de fichiers propriétaire d'Apple (APFS)

**Le système de fichiers d'Apple (APFS)** est un système de fichiers moderne conçu pour remplacer le système de fichiers hiérarchique Plus (HFS+). Son développement a été motivé par le besoin d'**améliorer les performances, la sécurité et l'efficacité**.

Certaines caractéristiques notables de l'APFS incluent :

1. **Partage d'espace** : L'APFS permet à plusieurs volumes de **partager le même espace de stockage libre sous-jacent** sur un seul appareil physique. Cela permet une utilisation plus efficace de l'espace, car les volumes peuvent croître et rétrécir dynamiquement sans avoir besoin de redimensionnement ou de repartitionnement manuel.
1. Cela signifie, par rapport aux partitions traditionnelles dans les disques de fichiers, **qu'en APFS, différentes partitions (volumes) partagent tout l'espace disque**, tandis qu'une partition classique avait généralement une taille fixe.
2. **Instantanés** : L'APFS prend en charge **la création d'instantanés**, qui sont des instances **en lecture seule** et à un moment donné du système de fichiers. Les instantanés permettent des sauvegardes efficaces et des retours en arrière faciles, car ils consomment un espace de stockage supplémentaire minimal et peuvent être créés ou annulés rapidement.
3. **Clones** : L'APFS peut **créer des clones de fichiers ou de répertoires qui partagent le même stockage** que l'original jusqu'à ce que le clone ou le fichier original soit modifié. Cette fonctionnalité offre un moyen efficace de créer des copies de fichiers ou de répertoires sans dupliquer l'espace de stockage.
4. **Chiffrement** : L'APFS **prend en charge nativement le chiffrement de disque complet** ainsi que le chiffrement par fichier et par répertoire, renforçant la sécurité des données dans différents cas d'utilisation.
5. **Protection contre les pannes** : L'APFS utilise un **schéma de métadonnées de copie sur écriture qui garantit la cohérence du système de fichiers** même en cas de perte soudaine de puissance ou de crash système, réduisant le risque de corruption des données.

Dans l'ensemble, l'APFS offre un système de fichiers plus moderne, flexible et efficace pour les appareils Apple, avec un accent sur l'amélioration des performances, de la fiabilité et de la sécurité.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Le volume `Data` est monté dans **`/System/Volumes/Data`** (vous pouvez vérifier cela avec `diskutil apfs list`).

La liste des firmlinks peut être trouvée dans le fichier **`/usr/share/firmlinks`**.
```bash
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
