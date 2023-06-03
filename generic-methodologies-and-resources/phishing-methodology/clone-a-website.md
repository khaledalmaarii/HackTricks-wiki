<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Pour une évaluation de phishing, il peut parfois être utile de **cloner complètement un site web**.

Notez que vous pouvez également ajouter des charges utiles au site web cloné, comme un crochet BeEF pour "contrôler" l'onglet de l'utilisateur.

Il existe différents outils que vous pouvez utiliser à cette fin :

## wget
```text
wget -mk -nH
```
## goclone

Le clonage de site Web est une technique couramment utilisée dans les attaques de phishing pour tromper les utilisateurs en leur faisant croire qu'ils visitent un site Web légitime alors qu'en réalité, ils sont sur une copie malveillante. Goclone est un outil open source qui permet de cloner facilement un site Web en utilisant la ligne de commande.

Pour utiliser goclone, il suffit de spécifier l'URL du site Web que vous souhaitez cloner et l'emplacement où vous souhaitez enregistrer la copie. Goclone copiera ensuite tous les fichiers et dossiers du site Web, y compris les fichiers HTML, CSS, JavaScript et les images.

Une fois que vous avez cloné le site Web, vous pouvez le modifier pour y inclure des scripts malveillants ou des formulaires de phishing. Vous pouvez ensuite héberger la copie malveillante sur un serveur Web et envoyer des e-mails de phishing aux utilisateurs pour les inciter à visiter le site Web.

Il est important de noter que le clonage de sites Web sans autorisation est illégal et peut entraîner des poursuites judiciaires. Il est donc important d'utiliser cette technique uniquement à des fins éthiques et légales, telles que les tests de sécurité et les audits de vulnérabilité.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Boîte à outils d'ingénierie sociale

---

### Clone a Website

### Cloner un site web

One of the most common techniques used in phishing attacks is to clone a legitimate website and modify it to steal user credentials. This technique is effective because it can be difficult for users to distinguish between a legitimate website and a cloned website.

L'une des techniques les plus courantes utilisées dans les attaques de phishing consiste à cloner un site web légitime et à le modifier pour voler les identifiants de l'utilisateur. Cette technique est efficace car il peut être difficile pour les utilisateurs de distinguer un site web légitime d'un site web cloné.

To clone a website, you can use a tool like HTTrack or Wget to download the website's HTML, CSS, and JavaScript files. Once you have downloaded the files, you can modify them to include your phishing code.

Pour cloner un site web, vous pouvez utiliser un outil comme HTTrack ou Wget pour télécharger les fichiers HTML, CSS et JavaScript du site web. Une fois que vous avez téléchargé les fichiers, vous pouvez les modifier pour inclure votre code de phishing.

Another option is to use a phishing toolkit like SocialFish or HiddenEye, which automate the process of cloning a website and hosting it on a phishing server.

Une autre option consiste à utiliser une boîte à outils de phishing comme SocialFish ou HiddenEye, qui automatisent le processus de clonage d'un site web et son hébergement sur un serveur de phishing.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
