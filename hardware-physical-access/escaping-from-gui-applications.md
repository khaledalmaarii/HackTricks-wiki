<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares de roubo**.

O principal objetivo do WhiteIntel é combater tomadas de conta de contas e ataques de ransomware resultantes de malwares de roubo de informações.

Você pode verificar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

---

# Verificar possíveis ações dentro da aplicação GUI

**Diálogos Comuns** são aquelas opções de **salvar um arquivo**, **abrir um arquivo**, selecionar uma fonte, uma cor... A maioria deles **oferecerá uma funcionalidade completa do Explorer**. Isso significa que você poderá acessar funcionalidades do Explorer se puder acessar essas opções:

* Fechar/Fechar como
* Abrir/Abrir com
* Imprimir
* Exportar/Importar
* Pesquisar
* Escanear

Você deve verificar se pode:

* Modificar ou criar novos arquivos
* Criar links simbólicos
* Acessar áreas restritas
* Executar outros aplicativos

## Execução de Comandos

Talvez **usando a opção `Abrir com`** você possa abrir/executar algum tipo de shell.

### Windows

Por exemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encontre mais binários que podem ser usados para executar comandos (e realizar ações inesperadas) aqui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Mais aqui: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Bypass de restrições de caminho

* **Variáveis de ambiente**: Existem muitas variáveis de ambiente que apontam para algum caminho
* **Outros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Links simbólicos**
* **Atalhos**: CTRL+N (abrir nova sessão), CTRL+R (Executar Comandos), CTRL+SHIFT+ESC (Gerenciador de Tarefas),  Windows+E (abrir explorer), CTRL-B, CTRL-I (Favoritos), CTRL-H (Histórico), CTRL-L, CTRL-O (Diálogo Arquivo/Abrir), CTRL-P (Diálogo Imprimir), CTRL-S (Salvar Como)
* Menu Administrativo Oculto: CTRL-ALT-F8, CTRL-ESC-F9
* **URIs de Shell**: _shell:Ferramentas Administrativas, shell:Bibliotecas de Documentos, shell:Bibliotecas, shell:Perfis de Usuários, shell:Pessoal, shell:Pasta de Pesquisa, shell:Sistema, shell:Locais de Rede, shell:Enviar para, shell:Perfis de Usuários, shell:Ferramentas Administrativas Comuns, shell:Meu Computador, shell:Internet_
* **Caminhos UNC**: Caminhos para se conectar a pastas compartilhadas. Você deve tentar se conectar ao C$ da máquina local ("\\\127.0.0.1\c$\Windows\System32")
* **Mais caminhos UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## Baixe Seus Binários

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor de Registro: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Acessando o sistema de arquivos pelo navegador

| CAMINHO                | CAMINHO              | CAMINHO               | CAMINHO                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Atalhos

* Teclas de Acesso Rápido – Pressione SHIFT 5 vezes
* Teclas do Mouse – SHIFT+ALT+NUMLOCK
* Alto Contraste – SHIFT+ALT+PRINTSCN
* Teclas de Alternância – Mantenha NUMLOCK pressionado por 5 segundos
* Teclas de Filtro – Mantenha o SHIFT direito pressionado por 12 segundos
* WINDOWS+F1 – Pesquisa do Windows
* WINDOWS+D – Mostrar Área de Trabalho
* WINDOWS+E – Abrir o Explorador do Windows
* WINDOWS+R – Executar
* WINDOWS+U – Centro de Facilidade de Acesso
* WINDOWS+F – Pesquisar
* SHIFT+F10 – Menu de Contexto
* CTRL+SHIFT+ESC – Gerenciador de Tarefas
* CTRL+ALT+DEL – Tela de Splash em versões mais recentes do Windows
* F1 – Ajuda F3 – Pesquisa
* F6 – Barra de Endereço
* F11 – Alternar tela cheia no Internet Explorer
* CTRL+H – Histórico do Internet Explorer
* CTRL+T – Internet Explorer – Nova Guia
* CTRL+N – Internet Explorer – Nova Página
* CTRL+O – Abrir Arquivo
* CTRL+S – Salvar CTRL+N – Nova RDP / Citrix
## Swipes

* Deslize da esquerda para a direita para ver todas as janelas abertas, minimizando o aplicativo KIOSK e acessando todo o sistema operacional diretamente;
* Deslize da direita para a esquerda para abrir o Centro de Ação, minimizando o aplicativo KIOSK e acessando todo o sistema operacional diretamente;
* Deslize de cima para baixo para tornar a barra de título visível para um aplicativo aberto em modo de tela cheia;
* Deslize de baixo para cima para mostrar a barra de tarefas em um aplicativo em tela cheia.

## Truques do Internet Explorer

### 'Barra de Ferramentas de Imagem'

É uma barra de ferramentas que aparece no canto superior esquerdo da imagem quando clicada. Você poderá Salvar, Imprimir, Enviar por e-mail, Abrir "Minhas Imagens" no Explorer. O Kiosk precisa estar usando o Internet Explorer.

### Protocolo Shell

Digite esses URLs para obter uma visualização do Explorer:

* `shell:Ferramentas Administrativas`
* `shell:BibliotecaDocumentos`
* `shell:Bibliotecas`
* `shell:PerfisUsuários`
* `shell:Pessoal`
* `shell:PastaInícioPesquisa`
* `shell:PastaLocaisRede`
* `shell:EnviarPara`
* `shell:PerfisUsuários`
* `shell:FerramentasAdministrativasComuns`
* `shell:MeuComputador`
* `shell:PastaInternet`
* `Shell:Perfil`
* `Shell:ArquivosProgramas`
* `Shell:Sistema`
* `Shell:PainelControle`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Painel de Controle
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Meu Computador
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Meus Locais de Rede
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Mostrar Extensões de Arquivo

Verifique esta página para mais informações: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Truques de Navegadores

Backup de versões iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Crie um diálogo comum usando JavaScript e acesse o explorador de arquivos: `document.write('<input/type=file>')`
Fonte: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gestos e botões

* Deslize para cima com quatro (ou cinco) dedos / Toque duplo no botão Início: Para visualizar a visualização de multitarefa e alterar o aplicativo

* Deslize de um lado para o outro com quatro ou cinco dedos: Para mudar para o próximo/último aplicativo

* Belisque a tela com cinco dedos / Toque no botão Início / Deslize para cima com 1 dedo da parte inferior da tela em um movimento rápido para cima: Para acessar a Página Inicial

* Deslize um dedo da parte inferior da tela apenas 1-2 polegadas (devagar): O dock aparecerá

* Deslize para baixo a partir do topo da tela com 1 dedo: Para ver suas notificações

* Deslize para baixo com 1 dedo no canto superior direito da tela: Para ver o centro de controle do iPad Pro

* Deslize 1 dedo da esquerda da tela 1-2 polegadas: Para ver a visualização de Hoje

* Deslize rapidamente 1 dedo do centro da tela para a direita ou esquerda: Para mudar para o próximo/último aplicativo

* Pressione e segure o botão Liga/Desliga no canto superior direito do iPad + Mova o controle deslizante Deslizar para desligar todo o caminho para a direita: Para desligar

* Pressione o botão Liga/Desliga no canto superior direito do iPad e o botão Início por alguns segundos: Para forçar um desligamento completo

* Pressione o botão Liga/Desliga no canto superior direito do iPad e o botão Início rapidamente: Para tirar uma captura de tela que aparecerá no canto inferior esquerdo da tela. Pressione ambos os botões ao mesmo tempo brevemente, pois se você os segurar por alguns segundos, um desligamento completo será realizado.

## Atalhos

Você deve ter um teclado para iPad ou um adaptador de teclado USB. Apenas os atalhos que podem ajudar a escapar do aplicativo serão mostrados aqui.

| Tecla | Nome         |
| --- | ------------ |
| ⌘   | Comando      |
| ⌥   | Opção (Alt) |
| ⇧   | Shift        |
| ↩   | Retorno       |
| ⇥   | Tab          |
| ^   | Controle      |
| ←   | Seta para a Esquerda   |
| →   | Seta para a Direita  |
| ↑   | Seta para Cima     |
| ↓   | Seta para Baixo   |

### Atalhos do Sistema

Esses atalhos são para as configurações visuais e de som, dependendo do uso do iPad.

| Atalho | Ação                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Diminuir Brilho da Tela                                                                    |
| F2       | Aumentar Brilho da Tela                                                                |
| F7       | Voltar uma música                                                                  |
| F8       | Reproduzir/Pausar                                                                     |
| F9       | Avançar música                                                                      |
| F10      | Silenciar                                                                           |
| F11      | Diminuir volume                                                                |
| F12      | Aumentar volume                                                                |
| ⌘ Espaço  | Exibir uma lista de idiomas disponíveis; para escolher um, toque novamente na barra de espaço. |

### Navegação no iPad

| Atalho                                           | Ação                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ir para a Página Inicial                                              |
| ⌘⇧H (Command-Shift-H)                              | Ir para a Página Inicial                                              |
| ⌘ (Espaço)                                          | Abrir o Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | Listar os últimos dez aplicativos usados                                 |
| ⌘\~                                                | Ir para o último aplicativo                                       |
| ⌘⇧3 (Command-Shift-3)                              | Captura de tela (aparece no canto inferior esquerdo para salvar ou agir sobre ela) |
| ⌘⇧4                                                | Captura de tela e abertura no editor                    |
| Pressionar e segurar ⌘                                   | Lista de atalhos disponíveis para o aplicativo                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Mostra o dock                                      |
| ^⌥H (Control-Option-H)                             | Botão Início                                             |
| ^⌥H H (Control-Option-H-H)                         | Mostra a barra de multitarefa                                      |
| ^⌥I (Control-Option-i)                             | Seletor de item                                            |
| Escape                                             | Botão Voltar                                             |
| → (Seta para a Direita)                                    | Próximo item                                               |
| ← (Seta para a Esquerda)                                     | Item anterior                                           |
| ↑↓ (Seta para Cima, Seta para Baixo)                          | Toque simultaneamente no item selecionado                        |
| ⌥ ↓ (Opção-Seta para Baixo)                            | Rolagem para baixo                                             |
| ⌥↑ (Opção-Seta para Cima)                               | Rolagem para cima                                               |
| ⌥← ou ⌥→ (Opção-Seta para a Esquerda ou Opção-Seta para a Direita) | Rolagem para a esquerda ou direita                                    |
| ^⌥S (Control-Option-S)                             | Ativar ou desativar a fala do VoiceOver                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Alternar para o aplicativo anterior                              |
| ⌘⇥ (Command-Tab)                                   | Alternar de volta para o aplicativo original                         |
| ←+→, depois Opção + ← ou Opção+→                   | Navegar pelo Dock                                   |
### Atalhos do Safari

| Atalho                  | Ação                                           |
| ----------------------- | ---------------------------------------------- |
| ⌘L (Command-L)          | Abrir Localização                              |
| ⌘T                      | Abrir uma nova aba                             |
| ⌘W                      | Fechar a aba atual                             |
| ⌘R                      | Atualizar a aba atual                          |
| ⌘.                      | Parar o carregamento da aba atual              |
| ^⇥                      | Alternar para a próxima aba                   |
| ^⇧⇥ (Control-Shift-Tab) | Mover para a aba anterior                      |
| ⌘L                      | Selecionar o campo de texto/URL para modificá-lo |
| ⌘⇧T (Command-Shift-T)   | Abrir a última aba fechada (pode ser usado várias vezes) |
| ⌘\[                     | Voltar uma página no histórico de navegação   |
| ⌘]                      | Avançar uma página no histórico de navegação  |
| ⌘⇧R                     | Ativar o Modo Leitor                           |

### Atalhos do Mail

| Atalho                   | Ação                       |
| ------------------------ | -------------------------- |
| ⌘L                       | Abrir Localização          |
| ⌘T                       | Abrir uma nova aba         |
| ⌘W                       | Fechar a aba atual         |
| ⌘R                       | Atualizar a aba atual      |
| ⌘.                       | Parar o carregamento da aba atual |
| ⌘⌥F (Command-Option/Alt-F) | Pesquisar na sua caixa de correio |

# Referências

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares de roubo**.

O objetivo principal do WhiteIntel é combater invasões de contas e ataques de ransomware resultantes de malwares de roubo de informações.

Você pode acessar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou nos siga no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
