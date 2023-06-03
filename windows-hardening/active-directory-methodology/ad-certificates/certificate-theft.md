# Vol de certificat AD CS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Que puis-je faire avec un certificat

Avant de voir comment voler les certificats, voici quelques informations sur la façon de trouver à quoi le certificat est utile :
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportation de certificats en utilisant les API de cryptographie - VOL1

La manière la plus simple d'extraire un certificat utilisateur ou machine et sa clé privée est de passer par une **session de bureau interactive**. Si la **clé privée** est **exportable**, il suffit de faire un clic droit sur le certificat dans `certmgr.msc`, puis d'aller dans `Toutes les tâches → Exporter`... pour exporter un fichier .pfx protégé par mot de passe. \
On peut également accomplir cela de manière **programmatique**. Des exemples incluent la commande `ExportPfxCertificate` de PowerShell ou le projet C# CertStealer de [TheWover](https://github.com/TheWover/CertStealer).

En dessous, ces méthodes utilisent la **Microsoft CryptoAPI** (CAPI) ou la plus moderne Cryptography API: Next Generation (CNG) pour interagir avec le magasin de certificats. Ces API effectuent divers services cryptographiques nécessaires pour le stockage et l'authentification des certificats (entre autres utilisations).

Si la clé privée n'est pas exportable, CAPI et CNG n'autorisent pas l'extraction de certificats non exportables. Les commandes `crypto::capi` et `crypto::cng` de **Mimikatz** peuvent patcher le CAPI et le CNG pour **permettre l'exportation** de clés privées. `crypto::capi` **patche** **CAPI** dans le processus en cours tandis que `crypto::cng` nécessite le **patching** de la mémoire de **lsass.exe**.

## Vol de certificat utilisateur via DPAPI - VOL2

Plus d'informations sur DPAPI dans:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows **stocke les clés privées de certificat en utilisant DPAPI**. Microsoft sépare les emplacements de stockage pour les clés privées utilisateur et machine. Lors du déchiffrement manuel des blocs DPAPI chiffrés, un développeur doit comprendre quelle API de cryptographie le système d'exploitation a utilisée car la structure du fichier de clé privée diffère entre les deux API. Lors de l'utilisation de SharpDPAPI, il prend automatiquement en compte ces différences de format de fichier.

Windows **stocke le plus souvent les certificats utilisateur** dans le registre dans la clé `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, bien que certains certificats personnels pour les utilisateurs soient également stockés dans `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Les emplacements de **clé privée associés** à l'utilisateur sont principalement situés à `%APPDATA%\Microsoft\Crypto\RSA\User SID\` pour les clés **CAPI** et `%APPDATA%\Microsoft\Crypto\Keys\` pour les clés **CNG**.

Pour obtenir un certificat et sa clé privée associée, il faut :

1. Identifier **quel certificat on veut voler** dans le magasin de certificats de l'utilisateur et extraire le nom du magasin de clés.
2. Trouver la **clé maître DPAPI** nécessaire pour déchiffrer la clé privée associée.
3. Obtenir la clé maître DPAPI en texte clair et l'utiliser pour **déchiffrer la clé privée**.

Pour **obtenir la clé maître DPAPI en texte clair** :
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Pour simplifier le décryptage des fichiers de clé maître et de clé privée, la commande `certificates` de [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) peut être utilisée avec les arguments `/pvk`, `/mkfile`, `/password` ou `{GUID}:KEY` pour décrypter les clés privées et les certificats associés, en produisant un fichier texte `.pem`.
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Vol de certificat de machine via DPAPI – THEFT3

Windows stocke les certificats de machine dans la clé de registre `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` et stocke les clés privées à plusieurs endroits différents en fonction du compte.\
Bien que SharpDPAPI recherche tous ces emplacements, les résultats les plus intéressants ont tendance à provenir de `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI) et `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG). Ces **clés privées** sont associées au magasin de certificats de la machine et Windows les chiffre avec les **clés maîtresses DPAPI de la machine**.\
On ne peut pas décrypter ces clés en utilisant la clé de sauvegarde DPAPI du domaine, mais plutôt **doit** utiliser le **secret LSA DPAPI\_SYSTEM** sur le système qui est **accessible uniquement par l'utilisateur SYSTEM**.&#x20;

Vous pouvez le faire manuellement avec la commande **`lsadump::secrets`** de **Mimikatz** et ensuite utiliser la clé extraite pour **décrypter les clés maîtresses de la machine**.\
Vous pouvez également patcher CAPI/CNG comme précédemment et utiliser la commande `crypto::certificates /export /systemstore:LOCAL_MACHINE` de **Mimikatz**.\
La commande de certificats de **SharpDPAPI** avec le drapeau **`/machine`** (tout en étant élevé) va automatiquement **s'élever** à **SYSTEM**, **dump** le **secret LSA DPAPI\_SYSTEM**, l'utiliser pour **décrypter** et trouver les clés maîtresses DPAPI de la machine, et utiliser les textes en clair des clés comme table de recherche pour décrypter toutes les clés privées de certificat de machine.

## Recherche de fichiers de certificat – THEFT4

Parfois, les **certificats sont simplement dans le système de fichiers**, comme dans les partages de fichiers ou dans le dossier Téléchargements.\
Le type le plus courant de fichiers de certificat axés sur Windows que nous avons vus sont les fichiers **`.pfx`** et **`.p12`**, avec **`.pkcs12`** et **`.pem`** apparaissant parfois mais moins souvent.\
D'autres extensions de fichiers liées aux certificats intéressantes sont : **`.key`** (_clé privée_), **`.crt/.cer`** (_juste certificat_), **`.csr`** (_Certificate Signing Request, il ne contient pas de certificats ou de clés privées_), **`.jks/.keystore/.keys`** (_Java Keystore. Peut contenir des certificats + des clés privées utilisées par les applications Java_).

Pour trouver ces fichiers, il suffit de rechercher ces extensions à l'aide de PowerShell ou de cmd.

Si vous trouvez un fichier de certificat **PKCS#12** et qu'il est **protégé par mot de passe**, vous pouvez extraire un hash en utilisant [pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html) et le **craquer** en utilisant JohnTheRipper.

## Vol de crédential NTLM via PKINIT – THEFT5

> Afin de **prendre en charge l'authentification NTLM** \[MS-NLMP\] pour les applications se connectant à des services réseau qui **ne prennent pas en charge l'authentification Kerberos**, lorsque PKCA est utilisé, le KDC renvoie la fonction unidirectionnelle (OWF) NTLM de l'utilisateur dans le tampon de certificat d'attribut de privilège (PAC) **`PAC_CREDENTIAL_INFO`**

Ainsi, si le compte s'authentifie et obtient un **TGT via PKINIT**, il existe un "dispositif de sécurité" intégré qui permet à l'hôte actuel d'**obtenir notre hachage NTLM à partir du TGT** pour prendre en charge l'authentification héritée. Cela implique de **décrypter** une **structure PAC_CREDENTIAL_DATA** qui est une représentation sérialisée de la NTLM en texte clair en Network Data Representation (NDR).

[**Kekeo**](https://github.com/gentilkiwi/kekeo) peut être utilisé pour demander un TGT avec ces informations et récupérer les NTLM de l'utilisateur.
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
L'implémentation de Kekeo fonctionnera également avec des certificats protégés par carte à puce qui sont actuellement branchés si vous pouvez récupérer le code PIN. Il sera également pris en charge dans Rubeus.

## Références

* Toutes les informations ont été prises à partir de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité ? Voulez-vous voir votre entreprise annoncée dans HackTricks ? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au repo [hacktricks](https://github.com/carlospolop/hacktricks) et [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
