# Vol de divulgation d'informations sensibles à partir d'un site Web

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

Si à un moment donné vous trouvez une **page Web qui vous présente des informations sensibles basées sur votre session** : peut-être qu'elle reflète des cookies, ou imprime des détails de carte de crédit ou toute autre information sensible, vous pouvez essayer de la voler.\
Voici les principales façons de tenter de le faire :

* [**Contournement de CORS**](../pentesting-web/cors-bypass.md) : Si vous pouvez contourner les en-têtes CORS, vous pourrez voler les informations en effectuant une requête Ajax pour une page malveillante.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/) : Si vous trouvez une vulnérabilité XSS sur la page, vous pourriez l'exploiter pour voler les informations.
* [**Balisage suspendu**](../pentesting-web/dangling-markup-html-scriptless-injection/) : Si vous ne pouvez pas injecter des balises XSS, vous pourriez quand même être en mesure de voler les informations en utilisant d'autres balises HTML régulières.
* [**Clickjacking**](../pentesting-web/clickjacking.md) : S'il n'y a pas de protection contre cette attaque, vous pourriez tromper l'utilisateur pour lui faire envoyer les données sensibles (un exemple [ici](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)). 

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert de l'équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
