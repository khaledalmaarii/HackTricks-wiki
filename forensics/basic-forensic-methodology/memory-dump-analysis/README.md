# Analyse de dump de mémoire

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) est l'événement de cybersécurité le plus important en **Espagne** et l'un des plus importants en **Europe**. Avec **pour mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{% embed url="https://www.rootedcon.com/" %}

## Commencer

Commencez à **rechercher** les **malwares** dans le pcap. Utilisez les **outils** mentionnés dans [**Analyse de Malware**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

Le premier framework open-source pour l'analyse de dump de mémoire est [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md). Volatility est un script Python pour l'analyse de dump de mémoire qui ont été collectés avec un outil externe (ou une image mémoire VMware collectée en mettant en pause la VM). Ainsi, étant donné le fichier de dump de mémoire et le "profil" pertinent (le système d'exploitation à partir duquel le dump a été collecté), Volatility peut commencer à identifier les structures dans les données : processus en cours d'exécution, mots de passe, etc. Il est également extensible à l'aide de plugins pour extraire divers types d'artefacts.\
À partir de : [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

## Rapport de crash de mini dump

Lorsque le dump est petit (juste quelques Ko, peut-être quelques Mo), il s'agit probablement d'un rapport de crash de mini dump et non d'un dump de mémoire.

![](<../../../.gitbook/assets/image (216).png>)

Si vous avez Visual Studio installé, vous pouvez ouvrir ce fichier et lier des informations de base telles que le nom du processus, l'architecture, les informations d'exception et les modules en cours d'exécution :

![](<../../../.gitbook/assets/image (217).png>)

Vous pouvez également charger l'exception et voir les instructions décompilées

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

Quoi qu'il en soit, Visual Studio n'est pas le meilleur outil pour effectuer une analyse en profondeur du dump.

Vous devriez l'ouvrir en utilisant **IDA** ou **Radare** pour l'inspecter en **profondeur**.
