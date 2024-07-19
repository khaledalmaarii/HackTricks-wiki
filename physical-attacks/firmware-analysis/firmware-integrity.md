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

## Intégrité du Firmware

Le **firmware personnalisé et/ou les binaires compilés peuvent être téléchargés pour exploiter les failles d'intégrité ou de vérification de signature**. Les étapes suivantes peuvent être suivies pour la compilation d'un shell de liaison backdoor :

1. Le firmware peut être extrait en utilisant firmware-mod-kit (FMK).
2. L'architecture et l'endianness du firmware cible doivent être identifiées.
3. Un compilateur croisé peut être construit en utilisant Buildroot ou d'autres méthodes appropriées pour l'environnement.
4. La backdoor peut être construite en utilisant le compilateur croisé.
5. La backdoor peut être copiée dans le répertoire /usr/bin du firmware extrait.
6. Le binaire QEMU approprié peut être copié dans le rootfs du firmware extrait.
7. La backdoor peut être émulée en utilisant chroot et QEMU.
8. La backdoor peut être accessible via netcat.
9. Le binaire QEMU doit être supprimé du rootfs du firmware extrait.
10. Le firmware modifié peut être reconditionné en utilisant FMK.
11. Le firmware avec backdoor peut être testé en l'émulant avec l'outil d'analyse de firmware (FAT) et en se connectant à l'IP et au port de la backdoor cible en utilisant netcat.

Si un shell root a déjà été obtenu par analyse dynamique, manipulation du bootloader ou test de sécurité matériel, des binaires malveillants précompilés tels que des implants ou des shells inversés peuvent être exécutés. Des outils de charge utile/implant automatisés comme le framework Metasploit et 'msfvenom' peuvent être utilisés en suivant les étapes suivantes :

1. L'architecture et l'endianness du firmware cible doivent être identifiées.
2. Msfvenom peut être utilisé pour spécifier la charge utile cible, l'IP de l'hôte attaquant, le numéro de port d'écoute, le type de fichier, l'architecture, la plateforme et le fichier de sortie.
3. La charge utile peut être transférée à l'appareil compromis et s'assurer qu'elle a les permissions d'exécution.
4. Metasploit peut être préparé pour gérer les demandes entrantes en démarrant msfconsole et en configurant les paramètres selon la charge utile.
5. Le shell inversé meterpreter peut être exécuté sur l'appareil compromis.
6. Les sessions meterpreter peuvent être surveillées à mesure qu'elles s'ouvrent.
7. Des activités post-exploitation peuvent être effectuées.

Si possible, des vulnérabilités dans les scripts de démarrage peuvent être exploitées pour obtenir un accès persistant à un appareil à travers les redémarrages. Ces vulnérabilités surviennent lorsque les scripts de démarrage font référence, [lient symboliquement](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ou dépendent de code situé dans des emplacements montés non fiables tels que des cartes SD et des volumes flash utilisés pour stocker des données en dehors des systèmes de fichiers racines.

## Références
* Pour plus d'informations, consultez [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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
