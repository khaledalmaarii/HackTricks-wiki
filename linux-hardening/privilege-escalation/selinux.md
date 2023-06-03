# SELinux dans les conteneurs

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) est un **système d'étiquetage**. Chaque **processus** et chaque **objet de système de fichiers** a une **étiquette**. Les politiques SELinux définissent des règles sur ce qu'une **étiquette de processus est autorisée à faire avec toutes les autres étiquettes** du système.

Les moteurs de conteneurs lancent des **processus de conteneurs avec une seule étiquette SELinux confinée**, généralement `container_t`, puis définissent le conteneur à l'intérieur du conteneur pour être étiqueté `container_file_t`. Les règles de la politique SELinux disent essentiellement que les **processus `container_t` ne peuvent lire/écrire/exécuter que des fichiers étiquetés `container_file_t`**. Si un processus de conteneur s'échappe du conteneur et tente d'écrire sur le contenu de l'hôte, le noyau Linux refuse l'accès et permet uniquement au processus de conteneur d'écrire sur le contenu étiqueté `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Utilisateurs SELinux

Il existe des utilisateurs SELinux en plus des utilisateurs Linux réguliers. Les utilisateurs SELinux font partie d'une politique SELinux. Chaque utilisateur Linux est mappé à un utilisateur SELinux dans le cadre de la politique. Cela permet aux utilisateurs Linux d'hériter des restrictions et des règles de sécurité et des mécanismes placés sur les utilisateurs SELinux.
