# Over Pass the Hash/Pass the Key

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous voulez voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

L'attaque **Overpass The Hash/Pass The Key (PTK)** est conçue pour les environnements où le protocole NTLM traditionnel est restreint et où l'authentification Kerberos prend le dessus. Cette attaque exploite le hachage NTLM ou les clés AES d'un utilisateur pour solliciter des tickets Kerberos, permettant un accès non autorisé aux ressources au sein d'un réseau.

Pour exécuter cette attaque, la première étape consiste à acquérir le hachage NTLM ou le mot de passe du compte de l'utilisateur ciblé. Après avoir sécurisé ces informations, un Ticket Granting Ticket (TGT) pour le compte peut être obtenu, permettant à l'attaquant d'accéder à des services ou des machines auxquels l'utilisateur a des autorisations.

Le processus peut être initié avec les commandes suivantes:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Pour les scénarios nécessitant AES256, l'option `-aesKey [clé AES]` peut être utilisée. De plus, le ticket acquis peut être utilisé avec divers outils, tels que smbexec.py ou wmiexec.py, élargissant ainsi la portée de l'attaque.

Les problèmes rencontrés tels que _PyAsn1Error_ ou _KDC cannot find the name_ sont généralement résolus en mettant à jour la bibliothèque Impacket ou en utilisant le nom d'hôte à la place de l'adresse IP, assurant ainsi la compatibilité avec le KDC Kerberos.

Une séquence de commandes alternative utilisant Rubeus.exe démontre un autre aspect de cette technique :
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Cette méthode reflète l'approche **Pass the Key**, en mettant l'accent sur la prise de contrôle et l'utilisation directe du ticket à des fins d'authentification. Il est crucial de noter que l'initiation d'une demande de TGT déclenche l'événement `4768: Un ticket d'authentification Kerberos (TGT) a été demandé`, signifiant une utilisation par défaut de RC4-HMAC, bien que les systèmes Windows modernes préfèrent AES256.

Pour se conformer à la sécurité opérationnelle et utiliser AES256, la commande suivante peut être appliquée:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Références

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
