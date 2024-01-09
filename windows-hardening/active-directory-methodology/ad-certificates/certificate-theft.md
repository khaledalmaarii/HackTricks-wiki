# Vol de certificats AD CS

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Que puis-je faire avec un certificat

Avant de vérifier comment voler les certificats, voici quelques informations sur comment trouver à quoi le certificat est utile :
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
## Exportation de certificats en utilisant les API Crypto – THEFT1

La manière la plus simple d'extraire un certificat d'utilisateur ou de machine et sa clé privée est via une **session de bureau interactive**. Si la **clé privée** est **exportable**, il suffit de cliquer droit sur le certificat dans `certmgr.msc`, et de sélectionner `Toutes les tâches → Exporter`... pour exporter un fichier .pfx protégé par mot de passe. \
On peut également accomplir cela **programmatiquement**. Des exemples incluent le cmdlet `ExportPfxCertificate` de PowerShell ou [le projet C# CertStealer de TheWover](https://github.com/TheWover/CertStealer).

Ces méthodes utilisent en sous-jacent l'**API Crypto de Microsoft** (CAPI) ou l'API de Cryptographie de nouvelle génération (CNG) pour interagir avec le magasin de certificats. Ces API effectuent divers services cryptographiques nécessaires pour le stockage et l'authentification des certificats (entre autres utilisations).

Si la clé privée n'est pas exportable, CAPI et CNG ne permettront pas l'extraction de certificats non exportables. Les commandes `crypto::capi` et `crypto::cng` de **Mimikatz** peuvent patcher CAPI et CNG pour **permettre l'exportation** des clés privées. `crypto::capi` **patche** **CAPI** dans le processus actuel tandis que `crypto::cng` nécessite le **patchage** de la mémoire de **lsass.exe**.

## Vol de certificat utilisateur via DPAPI – THEFT2

Plus d'informations sur DPAPI dans :

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows **stocke les clés privées des certificats en utilisant DPAPI**. Microsoft distingue les emplacements de stockage pour les clés privées d'utilisateur et de machine. Lors du déchiffrement manuel des blobs DPAPI chiffrés, un développeur doit comprendre quelle API de cryptographie l'OS a utilisée car la structure des fichiers de clé privée varie entre les deux API. Lors de l'utilisation de SharpDPAPI, il prend automatiquement en compte ces différences de format de fichier.&#x20;

Windows stocke le plus souvent les certificats d'utilisateur dans le registre sous la clé `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, bien que certains certificats personnels pour les utilisateurs soient **également** stockés dans `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Les emplacements des **clés privées associées** sont principalement `%APPDATA%\Microsoft\Crypto\RSA\User SID\` pour les clés **CAPI** et `%APPDATA%\Microsoft\Crypto\Keys\` pour les clés **CNG**.

Pour obtenir un certificat et sa clé privée associée, il faut :

1. Identifier **quel certificat on souhaite voler** dans le magasin de certificats de l'utilisateur et extraire le nom du magasin de clés.
2. Trouver la **clé maîtresse DPAPI** nécessaire pour déchiffrer la clé privée associée.
3. Obtenir la clé maîtresse DPAPI en clair et l'utiliser pour **déchiffrer la clé privée**.

Pour **obtenir la clé maîtresse DPAPI en clair** :
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Pour simplifier le déchiffrement des fichiers masterkey et des fichiers de clé privée, la commande `certificates` de [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) peut être utilisée avec les arguments `/pvk`, `/mkfile`, `/password`, ou `{GUID}:KEY` pour déchiffrer les clés privées et les certificats associés, produisant un fichier texte `.pem`.
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Vol de certificat de machine via DPAPI – THEFT3

Windows stocke les certificats de machine dans la clé de registre `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` et stocke les clés privées dans plusieurs emplacements différents en fonction du compte.\
Bien que SharpDPAPI recherche dans tous ces emplacements, les résultats les plus intéressants proviennent généralement de `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI) et `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG). Ces **clés privées** sont associées au **magasin de certificats de machine** et Windows les chiffre avec les **clés maîtresses DPAPI de la machine**.\
On ne peut pas déchiffrer ces clés en utilisant la clé de sauvegarde DPAPI du domaine, mais on **doit** utiliser le **secret DPAPI\_SYSTEM LSA** sur le système qui est **accessible uniquement par l'utilisateur SYSTEM**.&#x20;

Vous pouvez faire cela manuellement avec la commande **`lsadump::secrets`** de **Mimikatz** et ensuite utiliser la clé extraite pour **déchiffrer les masterkeys de machine**. \
Vous pouvez également patcher CAPI/CNG comme précédemment et utiliser la commande **Mimikatz’** `crypto::certificates /export /systemstore:LOCAL_MACHINE`. \
La commande certificates de **SharpDPAPI** avec le drapeau **`/machine`** (lorsqu'élevé) va automatiquement **s'élever** à **SYSTEM**, **dumper** le secret **DPAPI\_SYSTEM** LSA, l'utiliser pour **déchiffrer** et trouver les masterkeys DPAPI de machine, et utiliser les textes en clair des clés comme table de recherche pour déchiffrer toutes les clés privées de certificat de machine.

## Trouver les fichiers de certificats – THEFT4

Parfois, **les certificats sont juste dans le système de fichiers**, comme dans les partages de fichiers ou dans le dossier Téléchargements.\
Les types de fichiers de certificats les plus courants que nous avons vus pour Windows sont les fichiers **`.pfx`** et **`.p12`**, avec **`.pkcs12`** et **`.pem`** apparaissant parfois mais moins fréquemment.\
D'autres extensions de fichiers liées aux certificats intéressantes sont : **`.key`** (_clé privée_), **`.crt/.cer`** (_juste certificat_), **`.csr`** (_Demande de Signature de Certificat, ne contient ni certificats ni clés privées_), **`.jks/.keystore/.keys`** (_Java Keystore. Peut contenir des certificats + des clés privées utilisés par des applications Java_).

Pour trouver ces fichiers, il suffit de rechercher ces extensions à l'aide de powershell ou de cmd.

Si vous trouvez un fichier de certificat **PKCS#12** et qu'il est **protégé par mot de passe**, vous pouvez extraire un hash en utilisant [pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html) et le **craquer** en utilisant JohnTheRipper.

## Vol de justificatifs d'identité NTLM via PKINIT – THEFT5

> Afin de **prendre en charge l'authentification NTLM** \[MS-NLMP] pour les applications se connectant à des services réseau qui **ne prennent pas en charge l'authentification Kerberos**, lorsque PKCA est utilisé, le KDC renvoie la fonction à sens unique (OWF) **NTLM de l'utilisateur** dans le certificat d'attribut de privilège (PAC) **`PAC_CREDENTIAL_INFO`** buffer

Ainsi, si un compte s'authentifie et obtient un **TGT via PKINIT**, il existe une "sauvegarde" intégrée qui permet à l'hôte actuel d'**obtenir notre hash NTLM à partir du TGT** pour prendre en charge l'authentification héritée. Cela implique de **déchiffrer** une **structure `PAC_CREDENTIAL_DATA`** qui est une représentation sérialisée en Network Data Representation (NDR) du texte en clair NTLM.

[**Kekeo**](https://github.com/gentilkiwi/kekeo) peut être utilisé pour demander un TGT avec ces informations et récupérer le hash NTML des utilisateurs.
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
L'implémentation de Kekeo fonctionnera également avec les certificats protégés par carte à puce actuellement connectés si vous pouvez [**récupérer le code PIN**](https://github.com/CCob/PinSwipe)**.** Cela sera également pris en charge dans [**Rubeus**](https://github.com/GhostPack/Rubeus).

## Références

* Toutes les informations ont été prises de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
