<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


Il existe plusieurs blogs sur Internet qui **mettent en évidence les dangers de laisser des imprimantes configurées avec LDAP avec des** identifiants de connexion **par défaut/faibles**.\
Cela est dû au fait qu'un attaquant pourrait **tromper l'imprimante pour s'authentifier contre un serveur LDAP malveillant** (généralement un `nc -vv -l -p 444` suffit) et capturer les **identifiants de l'imprimante en clair**.

De plus, plusieurs imprimantes contiendront des **logs avec des noms d'utilisateur** ou pourraient même être capables de **télécharger tous les noms d'utilisateur** du Contrôleur de Domaine.

Toutes ces **informations sensibles** et le **manque de sécurité courant** rendent les imprimantes très intéressantes pour les attaquants.

Quelques blogs sur le sujet :

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Configuration de l'imprimante
- **Emplacement** : La liste des serveurs LDAP se trouve à : `Réseau > Paramètres LDAP > Configuration LDAP`.
- **Comportement** : L'interface permet des modifications du serveur LDAP sans avoir à ressaisir les identifiants, visant la commodité de l'utilisateur mais posant des risques de sécurité.
- **Exploitation** : L'exploitation implique de rediriger l'adresse du serveur LDAP vers une machine contrôlée et de tirer parti de la fonction "Test de connexion" pour capturer les identifiants.

## Capture des identifiants

### Méthode 1 : Écouteur Netcat
Un simple écouteur netcat pourrait suffire :
```bash
sudo nc -k -v -l -p 386
```
Cependant, le succès de cette méthode varie.

### Méthode 2: Serveur LDAP complet avec Slapd
Une approche plus fiable consiste à configurer un serveur LDAP complet car l'imprimante effectue une liaison nulle suivie d'une requête avant de tenter une liaison d'identification.

1. **Configuration du Serveur LDAP**: Le guide suit les étapes de [cette source](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Étapes Clés**:
- Installer OpenLDAP.
- Configurer le mot de passe administrateur.
- Importer des schémas de base.
- Définir le nom de domaine sur la base de données LDAP.
- Configurer le TLS LDAP.
3. **Exécution du Service LDAP**: Une fois configuré, le service LDAP peut être exécuté en utilisant:
```
slapd -d 2
```

**Pour des étapes plus détaillées, consultez la [source originale](https://grimhacker.com/2018/03/09/just-a-printer/).**

# Références
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
