# Injeção em Aplicações .Net no macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

**Este é um resumo do post [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/). Confira para mais detalhes!**

## Depuração do .NET Core <a href="#net-core-debugging" id="net-core-debugging"></a>

### **Estabelecendo uma Sessão de Depuração** <a href="#net-core-debugging" id="net-core-debugging"></a>

O gerenciamento da comunicação entre o depurador e o depurado no .NET é feito por [**dbgtransportsession.cpp**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp). Este componente configura dois named pipes por processo .NET, como visto em [dbgtransportsession.cpp#L127](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L127), que são iniciados via [twowaypipe.cpp#L27](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/debug-pal/unix/twowaypipe.cpp#L27). Esses pipes são sufixados com **`-in`** e **`-out`**.

Ao visitar o **`$TMPDIR`** do usuário, é possível encontrar FIFOs de depuração disponíveis para depurar aplicações .Net.

[**DbgTransportSession::TransportWorker**](https://github.com/dotnet/runtime/blob/0633ecfb79a3b2f1e4c098d1dd0166bc1ae41739/src/coreclr/debug/shared/dbgtransportsession.cpp#L1259) é responsável por gerenciar a comunicação de um depurador. Para iniciar uma nova sessão de depuração, um depurador deve enviar uma mensagem via o pipe `out` começando com uma estrutura `MessageHeader`, detalhada no código-fonte do .NET:
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
Para solicitar uma nova sessão, esta estrutura é preenchida da seguinte forma, definindo o tipo de mensagem como `MT_SessionRequest` e a versão do protocolo como a versão atual:
```c
static const DWORD kCurrentMajorVersion = 2;
static const DWORD kCurrentMinorVersion = 0;

// Configure the message type and version
sSendHeader.m_eType = MT_SessionRequest;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMajorVersion = kCurrentMajorVersion;
sSendHeader.TypeSpecificData.VersionInfo.m_dwMinorVersion = kCurrentMinorVersion;
sSendHeader.m_cbDataBlock = sizeof(SessionRequestData);
```
Este cabeçalho é então enviado para o alvo usando a chamada de sistema `write`, seguido pela struct `sessionRequestData` contendo um GUID para a sessão:
```c
write(wr, &sSendHeader, sizeof(MessageHeader));
memset(&sDataBlock.m_sSessionID, 9, sizeof(SessionRequestData));
write(wr, &sDataBlock, sizeof(SessionRequestData));
```
Uma operação de leitura no pipe `out` confirma o sucesso ou falha do estabelecimento da sessão de depuração:
```c
read(rd, &sReceiveHeader, sizeof(MessageHeader));
```
## Leitura de Memória
Uma vez estabelecida uma sessão de depuração, a memória pode ser lida usando o tipo de mensagem [`MT_ReadMemory`](https://github.com/dotnet/runtime/blob/f3a45a91441cf938765bafc795cbf4885cad8800/src/coreclr/src/debug/shared/dbgtransportsession.cpp#L1896). A função readMemory é detalhada, realizando as etapas necessárias para enviar uma solicitação de leitura e recuperar a resposta:
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
O conceito de prova completo (POC) está disponível [aqui](https://gist.github.com/xpn/95eefc14918998853f6e0ab48d9f7b0b).

## Escrevendo na Memória

Da mesma forma, a memória pode ser escrita usando a função `writeMemory`. O processo envolve definir o tipo de mensagem como `MT_WriteMemory`, especificar o endereço e o comprimento dos dados e, em seguida, enviar os dados:
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
O POC associado está disponível [aqui](https://gist.github.com/xpn/7c3040a7398808747e158a25745380a5).

## Execução de Código .NET Core <a href="#net-core-code-execution" id="net-core-code-execution"></a>

Para executar código, é necessário identificar uma região de memória com permissões rwx, o que pode ser feito usando vmmap -pages:
```bash
vmmap -pages [pid]
vmmap -pages 35829 | grep "rwx/rwx"
```
Encontrar um local para sobrescrever um ponteiro de função é necessário, e no .NET Core, isso pode ser feito direcionando a **Tabela de Funções Dinâmicas (DFT)**. Esta tabela, detalhada em [`jithelpers.h`](https://github.com/dotnet/runtime/blob/6072e4d3a7a2a1493f514cdf4be75a3d56580e84/src/coreclr/src/inc/jithelpers.h), é usada pelo tempo de execução para funções auxiliares de compilação JIT.

Para sistemas x64, a caça de assinaturas pode ser usada para encontrar uma referência ao símbolo `_hlpDynamicFuncTable` em `libcorclr.dll`.

A função de depuração `MT_GetDCB` fornece informações úteis, incluindo o endereço de uma função auxiliar, `m_helperRemoteStartAddr`, indicando a localização de `libcorclr.dll` na memória do processo. Este endereço é então usado para iniciar a busca pela DFT e sobrescrever um ponteiro de função com o endereço do shellcode.

O código POC completo para injeção no PowerShell está acessível [aqui](https://gist.github.com/xpn/b427998c8b3924ab1d63c89d273734b6).

## Referências

* [https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/](https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
