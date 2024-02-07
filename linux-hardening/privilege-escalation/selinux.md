<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>


# SELinux dans les conteneurs

[Introduction et exemple des documents de Red Hat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) est un **système d'étiquetage**. Chaque **processus** et chaque objet du **système de fichiers** ont une **étiquette**. Les politiques SELinux définissent des règles sur ce qu'une **étiquette de processus est autorisée à faire avec toutes les autres étiquettes** sur le système.

Les moteurs de conteneurs lancent des **processus de conteneur avec une seule étiquette SELinux confinée**, généralement `container_t`, puis définissent le conteneur à l'intérieur du conteneur avec l'étiquette `container_file_t`. Les règles de la politique SELinux disent essentiellement que les **processus `container_t` ne peuvent lire/écrire/exécuter que des fichiers étiquetés `container_file_t`**. Si un processus de conteneur s'échappe du conteneur et tente d'écrire du contenu sur l'hôte, le noyau Linux refuse l'accès et autorise uniquement le processus de conteneur à écrire du contenu étiqueté `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Utilisateurs SELinux

Il existe des utilisateurs SELinux en plus des utilisateurs Linux réguliers. Les utilisateurs SELinux font partie d'une politique SELinux. Chaque utilisateur Linux est associé à un utilisateur SELinux dans le cadre de la politique. Cela permet aux utilisateurs Linux d'hériter des restrictions, des règles de sécurité et des mécanismes placés sur les utilisateurs SELinux.
