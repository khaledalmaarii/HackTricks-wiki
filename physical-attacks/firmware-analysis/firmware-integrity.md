```markdown
<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Intégrité du Firmware

Le **firmware personnalisé et/ou les binaires compilés peuvent être téléchargés pour exploiter des failles de vérification d'intégrité ou de signature**. Les étapes suivantes peuvent être suivies pour la compilation d'un backdoor bind shell :

1. Le firmware peut être extrait en utilisant firmware-mod-kit (FMK).
2. L'architecture et l'endianness du firmware cible doivent être identifiées.
3. Un compilateur croisé peut être construit en utilisant Buildroot ou d'autres méthodes adaptées à l'environnement.
4. Le backdoor peut être construit en utilisant le compilateur croisé.
5. Le backdoor peut être copié dans le répertoire /usr/bin du firmware extrait.
6. Le binaire QEMU approprié peut être copié dans le rootfs du firmware extrait.
7. Le backdoor peut être émulé en utilisant chroot et QEMU.
8. Le backdoor peut être accédé via netcat.
9. Le binaire QEMU doit être retiré du rootfs du firmware extrait.
10. Le firmware modifié peut être reconditionné en utilisant FMK.
11. Le firmware avec backdoor peut être testé en l'émulant avec le firmware analysis toolkit (FAT) et en se connectant à l'IP et au port du backdoor cible en utilisant netcat.

Si un shell root a déjà été obtenu par analyse dynamique, manipulation du bootloader ou tests de sécurité matérielle, des binaires malveillants précompilés tels que des implants ou des reverse shells peuvent être exécutés. Des outils automatisés de payload/implant comme le framework Metasploit et 'msfvenom' peuvent être utilisés en suivant les étapes suivantes :

1. L'architecture et l'endianness du firmware cible doivent être identifiées.
2. Msfvenom peut être utilisé pour spécifier le payload cible, l'IP de l'attaquant, le numéro de port d'écoute, le type de fichier, l'architecture, la plateforme et le fichier de sortie.
3. Le payload peut être transféré sur l'appareil compromis et il faut s'assurer qu'il a les permissions d'exécution.
4. Metasploit peut être préparé pour gérer les requêtes entrantes en démarrant msfconsole et en configurant les paramètres selon le payload.
5. Le reverse shell meterpreter peut être exécuté sur l'appareil compromis.
6. Les sessions meterpreter peuvent être surveillées à leur ouverture.
7. Des activités post-exploitation peuvent être effectuées.

Si possible, les vulnérabilités au sein des scripts de démarrage peuvent être exploitées pour obtenir un accès persistant à un appareil à travers les redémarrages. Ces vulnérabilités surviennent lorsque les scripts de démarrage font référence, [symboliquement lient](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ou dépendent de code situé dans des emplacements montés non fiables tels que des cartes SD et des volumes flash utilisés pour stocker des données en dehors des systèmes de fichiers racine.

# Références
* Pour plus d'informations, consultez [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PRs aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
