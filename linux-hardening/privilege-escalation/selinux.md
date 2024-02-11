<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


# SELinux in Houers

[Introduksie en voorbeeld van die redhat-dokumentasie](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) is 'n **etiketteringstelsel**. Elke **proses** en elke **lêersisteemobjek** het 'n **etiket**. SELinux-beleide definieer reëls oor wat 'n **prosesetiket mag doen met al die ander etikette** op die stelsel.

Houer-enjins begin **houerprosesse met 'n enkele beperkte SELinux-etiket**, gewoonlik `container_t`, en stel dan die houer binne die houer in om geëtiketteer te word as `container_file_t`. Die SELinux-beleidreëls sê basies dat die **`container_t`-prosesse slegs lêes/skryf/voer lêers uit wat geëtiketteer is as `container_file_t`**. As 'n houerproses ontsnap uit die houer en probeer skryf na inhoud op die gasheer, weier die Linux-kernel toegang en laat slegs die houerproses toe om te skryf na inhoud wat geëtiketteer is as `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux Gebruikers

Daar is SELinux-gebruikers bo en behalwe die gewone Linux-gebruikers. SELinux-gebruikers maak deel uit van 'n SELinux-beleid. Elke Linux-gebruiker word gekarteer na 'n SELinux-gebruiker as deel van die beleid. Dit stel Linux-gebruikers in staat om die beperkings en sekuriteitsreëls en -meganismes wat op SELinux-gebruikers geplaas is, te erf.
