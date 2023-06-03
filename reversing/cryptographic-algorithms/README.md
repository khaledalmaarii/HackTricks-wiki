# Algorithmes Cryptographiques/De Compression

## Algorithmes Cryptographiques/De Compression

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Identification des Algorithmes

Si vous tombez sur un code **utilisant des décalages à droite et à gauche, des XOR et plusieurs opérations arithmétiques**, il est très probable qu'il s'agisse de la mise en œuvre d'un **algorithme cryptographique**. Voici quelques façons d'**identifier l'algorithme utilisé sans avoir besoin de renverser chaque étape**.

### Fonctions API

**CryptDeriveKey**

Si cette fonction est utilisée, vous pouvez trouver quel **algorithme est utilisé** en vérifiant la valeur du deuxième paramètre :

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Consultez ici le tableau des algorithmes possibles et de leurs valeurs attribuées : [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Compresse et décompresse un tampon de données donné.

**CryptAcquireContext**

La fonction **CryptAcquireContext** est utilisée pour acquérir une poignée sur un conteneur de clé particulier dans un fournisseur de services cryptographiques (CSP) particulier. **Cette poignée retournée est utilisée dans les appels aux fonctions CryptoAPI** qui utilisent le CSP sélectionné.

**CryptCreateHash**

Initie le hachage d'un flux de données. Si cette fonction est utilisée, vous pouvez trouver quel **algorithme est utilisé** en vérifiant la valeur du deuxième paramètre :

![](<../../.gitbook/assets/image (376).png>)

Consultez ici le tableau des algorithmes possibles et de leurs valeurs attribuées : [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de code

Parfois, il est très facile d'identifier un algorithme grâce au fait qu'il doit utiliser une valeur spéciale et unique.

![](<../../.gitbook/assets/image (370).png>)

Si vous recherchez la première constante dans Google, voici ce que vous obtenez :

![](<../../.gitbook/assets/image (371).png>)

Par conséquent, vous pouvez
