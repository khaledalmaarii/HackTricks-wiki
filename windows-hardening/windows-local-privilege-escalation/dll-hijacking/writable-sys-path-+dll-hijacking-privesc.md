# Caminho Sys Gravável + Privesc de Dll Hijacking

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Introdução

Se você descobrir que pode **escrever em uma pasta do Caminho do Sistema** (observe que isso não funcionará se você puder escrever em uma pasta do Caminho do Usuário), é possível que você possa **elevar privilégios** no sistema.

Para fazer isso, você pode abusar de um **Dll Hijacking** onde você vai **sequestrar uma biblioteca sendo carregada** por um serviço ou processo com **mais privilégios** do que os seus e, porque esse serviço está carregando uma Dll que provavelmente nem mesmo existe em todo o sistema, ele vai tentar carregá-la a partir do Caminho do Sistema onde você pode escrever.

Para mais informações sobre **o que é Dll Hijacking** verifique:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Privesc com Dll Hijacking

### Encontrando uma Dll ausente

A primeira coisa que você precisa fazer é **identificar um processo** em execução com **mais privilégios** do que você que está tentando **carregar uma Dll do Caminho do Sistema** onde você pode escrever.

O problema nesses casos é que provavelmente esses processos já estão em execução. Para encontrar quais Dlls estão faltando nos serviços, você precisa iniciar o procmon o mais rápido possível (antes que os processos sejam carregados). Portanto, para encontrar .dlls faltantes, faça o seguinte:

* **Crie** a pasta `C:\privesc_hijacking` e adicione o caminho `C:\privesc_hijacking` à **variável de ambiente do Caminho do Sistema**. Você pode fazer isso **manualmente** ou com **PS**:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* Inicie o **`procmon`** e vá para **`Opções`** --> **`Ativar log de inicialização`** e pressione **`OK`** na janela que aparecer.
* Em seguida, **reinicie** o computador. Quando o computador for reiniciado, o **`procmon`** começará a **gravar** eventos imediatamente.
* Assim que o **Windows** for **iniciado, execute o `procmon`** novamente, ele informará que está em execução e perguntará se você deseja **armazenar** os eventos em um arquivo. Diga **sim** e **armazene os eventos em um arquivo**.
* **Após** o **arquivo** ser **gerado**, **feche** a janela do **`procmon`** aberta e **abra o arquivo de eventos**.
* Adicione esses **filtros** e você encontrará todas as Dlls que algum **processo tentou carregar** da pasta do Caminho do Sistema gravável:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Dlls Perdidas

Executando isso em uma **máquina virtual (vmware) Windows 11** gratuita, obtive estes resultados:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Neste caso, os .exe são inúteis, então ignore-os, as Dlls perdidas eram de:

| Serviço                         | Dll                | Linha de Comando                                                     |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Agendador de Tarefas (Schedule) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Serviço de Política de Diagnóstico (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Após encontrar isso, encontrei este post de blog interessante que também explica como [**abusar do WptsExtensions.dll para escalonamento de privilégios**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). O que **vamos fazer agora**.

### Exploração

Portanto, para **escalar privilégios**, vamos sequestrar a biblioteca **WptsExtensions.dll**. Tendo o **caminho** e o **nome**, só precisamos **gerar a dll maliciosa**.

Você pode [**tentar usar qualquer um desses exemplos**](../dll-hijacking.md#creating-and-compiling-dlls). Você poderia executar payloads como: obter um shell reverso, adicionar um usuário, executar um beacon...

{% hint style="warning" %}
Observe que **nem todos os serviços são executados** com **`NT AUTHORITY\SYSTEM`**, alguns também são executados com **`NT AUTHORITY\LOCAL SERVICE`**, que tem **menos privilégios** e você **não poderá criar um novo usuário** abusar de suas permissões.\
No entanto, esse usuário tem o privilégio **`seImpersonate`**, então você pode usar a [**suite potato para escalar privilégios**](../roguepotato-and-printspoofer.md). Portanto, neste caso, um shell reverso é uma opção melhor do que tentar criar um usuário.
{% endhint %}

No momento da escrita, o serviço **Agendador de Tarefas** é executado com **Nt AUTHORITY\SYSTEM**.

Tendo **gerado a Dll maliciosa** (_no meu caso, usei um shell reverso x64 e obtive um shell de volta, mas o defender o matou porque era do msfvenom_), salve-o na pasta do Caminho do Sistema gravável com o nome **WptsExtensions.dll** e **reinicie** o computador (ou reinicie o serviço ou faça o que for necessário para executar novamente o serviço/programa afetado).

Quando o serviço for reiniciado, a **dll deve ser carregada e executada** (você pode **reutilizar** o **truque do procmon** para verificar se a **biblioteca foi carregada conforme o esperado**).
