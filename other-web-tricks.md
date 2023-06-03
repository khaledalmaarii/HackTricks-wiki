# Autres astuces Web

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com).
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### En-tête d'hôte

Plusieurs fois, le back-end fait confiance à l'en-tête **Host** pour effectuer certaines actions. Par exemple, il peut utiliser sa valeur comme **domaine pour envoyer une réinitialisation de mot de passe**. Ainsi, lorsque vous recevez un e-mail avec un lien pour réinitialiser votre mot de passe, le domaine utilisé est celui que vous avez mis dans l'en-tête Host. Ensuite, vous pouvez demander la réinitialisation du mot de passe d'autres utilisateurs et changer le domaine pour un domaine contrôlé par vous pour voler leurs codes de réinitialisation de mot de passe. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Notez qu'il est possible que vous n'ayez même pas besoin d'attendre que l'utilisateur clique sur le lien de réinitialisation de mot de passe pour obtenir le jeton, car peut-être même les **filtres anti-spam ou d'autres dispositifs/bots intermédiaires cliqueront dessus pour l'analyser**.
{% endhint %}

### Booléens de session

Parfois, lorsque vous effectuez une vérification correctement, le back-end **ajoute simplement un booléen avec la valeur "True" à un attribut de sécurité de votre session**. Ensuite, un endpoint différent saura si vous avez réussi à passer cette vérification.\
Cependant, si vous **passez la vérification** et que votre session est accordée cette valeur "True" dans l'attribut de sécurité, vous pouvez essayer d'**accéder à d'autres ressources** qui **dépendent du même attribut** mais que vous **ne devriez pas avoir les autorisations** pour accéder. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Fonctionnalité d'inscription

Essayez de vous inscrire en tant qu'utilisateur déjà existant. Essayez également d'utiliser des caractères équivalents (points, beaucoup d'espaces et Unicode).

### Prendre le contrôle des e-mails

Enregistrez un e-mail, avant de le confirmer, changez l'e-mail. Ensuite, si le nouvel e-mail de confirmation est envoyé au premier e-mail enregistré, vous pouvez prendre le contrôle de n'importe quel e-mail. Ou si vous pouvez activer le deuxième e-mail en confirmant le premier, vous pouvez également prendre le contrôle de n'importe quel compte.

### Accéder au servicedesk interne des entreprises utilisant Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Méthode TRACE

Les développeurs peuvent oublier de désactiver diverses options de débogage dans l'environnement de production. Par exemple, la méthode HTTP `TRACE` est conçue à des fins de diagnostic. Si elle est activée, le serveur Web répondra aux demandes qui utilisent la méthode `TRACE` en écho à la réponse la demande exacte qui a été reçue. Ce comportement est souvent inoffensif, mais conduit parfois à la divulgation d'informations, telles que le nom des en-têtes d'authentification internes qui peuvent être ajoutés aux demandes par des serveurs proxy inverses.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs.
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com).
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
