<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Intégrité du firmware

Les **firmwares personnalisés et/ou les binaires compilés peuvent être téléchargés pour exploiter des failles d'intégrité ou de vérification de signature**. Les étapes suivantes peuvent être suivies pour la compilation d'un backdoor bind shell :

1. Le firmware peut être extrait à l'aide de firmware-mod-kit (FMK).
2. L'architecture du firmware cible et l'endianness doivent être identifiées.
3. Un compilateur croisé peut être construit en utilisant Buildroot ou d'autres méthodes adaptées à l'environnement.
4. Le backdoor peut être construit en utilisant le compilateur croisé.
5. Le backdoor peut être copié dans le répertoire /usr/bin du firmware extrait.
6. Le binaire QEMU approprié peut être copié dans le rootfs du firmware extrait.
7. Le backdoor peut être émulé en utilisant chroot et QEMU.
8. Le backdoor peut être accédé via netcat.
9. Le binaire QEMU doit être supprimé du rootfs du firmware extrait.
10. Le firmware modifié peut être reconditionné en utilisant FMK.
11. Le firmware backdooré peut être testé en l'émulant avec l'outil d'analyse de firmware (FAT) et en se connectant à l'IP et au port du backdoor cible en utilisant netcat.

Si un shell root a déjà été obtenu par le biais d'une analyse dynamique, d'une manipulation de bootloader ou de tests de sécurité matérielle, des binaires malveillants précompilés tels que des implants ou des reverse shells peuvent être exécutés. Des outils automatisés de charge utile/implant tels que le framework Metasploit et 'msfvenom' peuvent être exploités en suivant les étapes suivantes :

1. L'architecture du firmware cible et l'endianness doivent être identifiées.
2. Msfvenom peut être utilisé pour spécifier la charge utile cible, l'IP de l'attaquant, le numéro de port d'écoute, le type de fichier, l'architecture, la plateforme et le fichier de sortie.
3. La charge utile peut être transférée vers le périphérique compromis et il faut s'assurer qu'elle a les autorisations d'exécution.
4. Metasploit peut être préparé pour gérer les demandes entrantes en démarrant msfconsole et en configurant les paramètres selon la charge utile.
5. Le shell inversé meterpreter peut être exécuté sur le périphérique compromis.
6. Les sessions meterpreter peuvent être surveillées au fur et à mesure de leur ouverture.
7. Des activités de post-exploitation peuvent être effectuées.

Si possible, les vulnérabilités dans les scripts de démarrage peuvent être exploitées pour obtenir un accès persistant à un périphérique à travers les redémarrages. Ces vulnérabilités surviennent lorsque les scripts de démarrage font référence, [créent des liens symboliques](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ou dépendent du code situé dans des emplacements montés non fiables tels que les cartes SD et les volumes flash utilisés pour stocker des données en dehors des systèmes de fichiers racine.

## Références
* Pour plus d'informations, consultez [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
