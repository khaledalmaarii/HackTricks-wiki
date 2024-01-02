# Caminho do Sistema Gravável + Escalada de Privilégio por Hijacking de DLL

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução

Se você descobriu que pode **escrever em uma pasta do Caminho do Sistema** (note que isso não funcionará se você puder escrever em uma pasta do Caminho do Usuário), é possível que você consiga **escalar privilégios** no sistema.

Para fazer isso, você pode abusar de um **Hijacking de DLL** onde você vai **sequestrar uma biblioteca que está sendo carregada** por um serviço ou processo com **mais privilégios** do que os seus, e porque esse serviço está carregando uma DLL que provavelmente nem existe em todo o sistema, ele vai tentar carregá-la a partir do Caminho do Sistema onde você pode escrever.

Para mais informações sobre **o que é Hijacking de DLL**, confira:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Escalada de Privilégio com Hijacking de DLL

### Encontrando uma DLL ausente

A primeira coisa que você precisa é **identificar um processo** rodando com **mais privilégios** do que você que está tentando **carregar uma DLL a partir do Caminho do Sistema** no qual você pode escrever.

O problema nesses casos é que provavelmente esses processos já estão em execução. Para descobrir quais DLLs estão faltando nos serviços, você precisa iniciar o procmon o mais rápido possível (antes que os processos sejam carregados). Então, para encontrar .dlls ausentes, faça:

* **Crie** a pasta `C:\privesc_hijacking` e adicione o caminho `C:\privesc_hijacking` à **variável de ambiente Caminho do Sistema**. Você pode fazer isso **manualmente** ou com **PS**:
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
* Inicie o **`procmon`** e vá para **`Opções`** --> **`Habilitar registro de inicialização`** e pressione **`OK`** no prompt.
* Em seguida, **reinicie**. Quando o computador for reiniciado, o **`procmon`** começará a **registrar** eventos o mais rápido possível.
* Uma vez que o **Windows** for **iniciado, execute o `procmon`** novamente, ele informará que esteve em execução e perguntará **se você deseja armazenar** os eventos em um arquivo. Diga **sim** e **armazene os eventos em um arquivo**.
* **Após** o **arquivo** ser **gerado**, **feche** a janela do **`procmon`** aberta e **abra o arquivo de eventos**.
* Adicione estes **filtros** e você encontrará todas as DLLs que algum **processo tentou carregar** da pasta do Caminho do Sistema editável:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### DLLs Ausentes

Executando isso em uma máquina **virtual (vmware) Windows 11** gratuita, obtive estes resultados:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Neste caso, os .exe são inúteis, então ignore-os, as DLLs ausentes eram de:

| Serviço                         | Dll                | Linha de Comando                                                      |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Agendador de Tarefas (Schedule) | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Serviço de Política de Diagnóstico (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Após encontrar isso, encontrei este interessante post de blog que também explica como [**abusar do WptsExtensions.dll para privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Que é o que **vamos fazer agora**.

### Exploração

Então, para **escalar privilégios**, vamos sequestrar a biblioteca **WptsExtensions.dll**. Tendo o **caminho** e o **nome**, só precisamos **gerar a dll maliciosa**.

Você pode [**tentar usar qualquer um destes exemplos**](../dll-hijacking.md#creating-and-compiling-dlls). Você poderia executar cargas úteis como: obter um shell reverso, adicionar um usuário, executar um beacon...

{% hint style="warning" %}
Note que **nem todos os serviços são executados** com **`NT AUTHORITY\SYSTEM`** alguns também são executados com **`NT AUTHORITY\LOCAL SERVICE`**, que tem **menos privilégios** e você **não poderá criar um novo usuário** para abusar de suas permissões.\
No entanto, esse usuário tem o privilégio **`seImpersonate`**, então você pode usar a [**suíte potato para escalar privilégios**](../roguepotato-and-printspoofer.md). Portanto, neste caso, um shell reverso é uma opção melhor do que tentar criar um usuário.
{% endhint %}

No momento da escrita, o serviço **Agendador de Tarefas** é executado com **Nt AUTHORITY\SYSTEM**.

Tendo **gerado a Dll maliciosa** (_no meu caso, usei um shell reverso x64 e consegui um shell de volta, mas o defender o matou porque era do msfvenom_), salve-a no Caminho do Sistema editável com o nome **WptsExtensions.dll** e **reinicie** o computador (ou reinicie o serviço ou faça o que for necessário para reexecutar o serviço/programa afetado).

Quando o serviço for reiniciado, a **dll deve ser carregada e executada** (você pode **reutilizar** o truque do **procmon** para verificar se a **biblioteca foi carregada conforme esperado**).

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
