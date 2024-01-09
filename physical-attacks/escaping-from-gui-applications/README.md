<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Verifique possíveis ações dentro da aplicação GUI

**Diálogos Comuns** são aquelas opções de **salvar um arquivo**, **abrir um arquivo**, selecionar uma fonte, uma cor... A maioria deles oferecerá uma funcionalidade completa do Explorer. Isso significa que você poderá acessar funcionalidades do Explorer se conseguir acessar estas opções:

* Fechar/Salvar como
* Abrir/Abrir com
* Imprimir
* Exportar/Importar
* Pesquisar
* Digitalizar

Você deve verificar se pode:

* Modificar ou criar novos arquivos
* Criar links simbólicos
* Obter acesso a áreas restritas
* Executar outros aplicativos

## Execução de Comando

Talvez **usando a opção** _**Abrir com**_ você possa abrir/executar algum tipo de shell.

### Windows

Por exemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encontre mais binários que podem ser usados para executar comandos (e realizar ações inesperadas) aqui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Mais aqui: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Contornando restrições de caminho

* **Variáveis de ambiente**: Existem muitas variáveis de ambiente que apontam para algum caminho
* **Outros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Links simbólicos**
* **Atalhos**: CTRL+N (abrir nova sessão), CTRL+R (Executar Comandos), CTRL+SHIFT+ESC (Gerenciador de Tarefas),  Windows+E (abrir explorer), CTRL-B, CTRL-I (Favoritos), CTRL-H (Histórico), CTRL-L, CTRL-O (Diálogo de Abrir Arquivo), CTRL-P (Diálogo de Impressão), CTRL-S (Salvar Como)
* Menu Administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
* **URIs do Shell**: _shell:Ferramentas Administrativas, shell:Biblioteca de Documentos, shell:Bibliotecas, shell:Perfis de Usuário, shell:Pessoal, shell:Pasta de Pesquisa Inicial, shell:Sistema, shell:Pasta de Locais de Rede, shell:Enviar Para, shell:Perfis de Usuários, shell:Ferramentas Administrativas Comuns, shell:Pasta do Meu Computador, shell:Pasta da Internet_
* **Caminhos UNC**: Caminhos para conectar a pastas compartilhadas. Você deve tentar se conectar ao C$ da máquina local ("\\\127.0.0.1\c$\Windows\System32")
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

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Atalhos

* Teclas de Aderência – Pressione SHIFT 5 vezes
* Teclas do Mouse – SHIFT+ALT+NUMLOCK
* Alto Contraste – SHIFT+ALT+PRINTSCN
* Teclas de Alternância – Mantenha NUMLOCK pressionado por 5 segundos
* Teclas de Filtro – Mantenha a tecla SHIFT direita pressionada por 12 segundos
* WINDOWS+F1 – Pesquisa do Windows
* WINDOWS+D – Mostrar Área de Trabalho
* WINDOWS+E – Abrir Windows Explorer
* WINDOWS+R – Executar
* WINDOWS+U – Centro de Facilidade de Acesso
* WINDOWS+F – Pesquisar
* SHIFT+F10 – Menu de Contexto
* CTRL+SHIFT+ESC – Gerenciador de Tarefas
* CTRL+ALT+DEL – Tela de boas-vindas em versões mais recentes do Windows
* F1 – Ajuda F3 – Pesquisar
* F6 – Barra de Endereços
* F11 – Alternar tela cheia no Internet Explorer
* CTRL+H – Histórico do Internet Explorer
* CTRL+T – Internet Explorer – Nova Aba
* CTRL+N – Internet Explorer – Nova Página
* CTRL+O – Abrir Arquivo
* CTRL+S – Salvar CTRL+N – Novo RDP / Citrix

## Gestos

* Deslize da esquerda para a direita para ver todas as janelas abertas, minimizando o aplicativo KIOSK e acessando o sistema operacional diretamente;
* Deslize da direita para a esquerda para abrir o Centro de Ação, minimizando o aplicativo KIOSK e acessando o sistema operacional diretamente;
* Deslize de cima para baixo para tornar a barra de título visível para um aplicativo aberto em modo de tela cheia;
* Deslize de baixo para cima para mostrar a barra de tarefas em um aplicativo de tela cheia.

## Truques do Internet Explorer

### 'Barra de Ferramentas de Imagem'

É uma barra de ferramentas que aparece no canto superior esquerdo da imagem quando clicada. Você poderá Salvar, Imprimir, Mailto, Abrir "Minhas Imagens" no Explorer. O Kiosk precisa estar usando o Internet Explorer.

### Protocolo Shell

Digite estas URLs para obter uma visualização do Explorer:

* `shell:Ferramentas Administrativas`
* `shell:Biblioteca de Documentos`
* `shell:Bibliotecas`
* `shell:Perfis de Usuário`
* `shell:Pessoal`
* `shell:Pasta de Pesquisa Inicial`
* `shell:Pasta de Locais de Rede`
* `shell:Enviar Para`
* `shell:Perfis de Usuários`
* `shell:Ferramentas Administrativas Comuns`
* `shell:Pasta do Meu Computador`
* `shell:Pasta da Internet`
* `Shell:Perfil`
* `Shell:ProgramFiles`
* `Shell:Sistema`
* `Shell:Pasta de Controle`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Painel de Controle
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Meu Computador
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Meus Locais de Rede
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

# Truques dos navegadores

Versões de backup do iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Crie um diálogo comum usando JavaScript e acesse o explorador de arquivos: `document.write('<input/type=file>')`
Fonte: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gestos e botões

### Deslize para cima com quatro (ou cinco) dedos / Toque duas vezes no botão Início

Para visualizar a visão de multitarefa e mudar de App

### Deslize para um lado ou outro com quatro ou cinco dedos

Para mudar para o próximo/último App

### Belisque a tela com cinco dedos / Toque no botão Início / Deslize para cima com 1 dedo a partir da parte inferior da tela em um movimento rápido para cima

Para acessar Início

### Deslize um dedo a partir da parte inferior da tela apenas 1-2 polegadas (lentamente)

O dock aparecerá

### Deslize para baixo a partir do topo da tela com 1 dedo

Para ver suas notificações

### Deslize para baixo com 1 dedo no canto superior direito da tela

Para ver o centro de controle do iPad Pro

### Deslize 1 dedo da esquerda da tela 1-2 polegadas

Para ver a visualização de Hoje

### Deslize rápido 1 dedo do centro da tela para a direita ou esquerda

Para mudar para o próximo/último App

### Pressione e segure o botão Ligar/**Desligar**/Dormir no canto superior direito do **iPad +** Mova o controle deslizante Desligar para a direita completamente,

Para desligar

### Pressione o botão Ligar/**Desligar**/Dormir no canto superior direito do **iPad e o botão Início por alguns segundos**

Para forçar um desligamento completo

### Pressione o botão Ligar/**Desligar**/Dormir no canto superior direito do **iPad e o botão Início rapidamente**

Para tirar uma captura de tela que aparecerá no canto inferior esquerdo da tela. Pressione ambos os botões ao mesmo tempo muito brevemente, pois se você segurá-los por alguns segundos, um desligamento completo será realizado.

## Atalhos

Você deve ter um teclado para iPad ou um adaptador de teclado USB. Apenas atalhos que podem ajudar a escapar do aplicativo serão mostrados aqui.

| Tecla | Nome         |
| ----- | ------------ |
| ⌘     | Comando      |
| ⌥     | Opção (Alt)  |
| ⇧     | Shift        |
| ↩     | Retorno      |
| ⇥     | Tab          |
| ^     | Controle     |
| ←     | Seta Esquerda|
| →     | Seta Direita |
| ↑     | Seta para Cima|
| ↓     | Seta para Baixo|

### Atalhos do sistema

Estes atalhos são para as configurações visuais e de som, dependendo do uso do iPad.

| Atalho    | Ação                                                                         |
| --------- | ------------------------------------------------------------------------------ |
| F1        | Escurecer Tela                                                                |
| F2        | Clarear tela                                                                  |
| F7        | Voltar uma música                                                             |
| F8        | Reproduzir/pausar                                                             |
| F9        | Pular música                                                                  |
| F10       | Silenciar                                                                     |
| F11       | Diminuir volume                                                               |
| F12       | Aumentar volume                                                               |
| ⌘ Espaço  | Exibir uma lista de idiomas disponíveis; para escolher um, toque no espaço novamente. |

### Navegação no iPad

| Atalho                                             | Ação                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ir para Início                                         |
| ⌘⇧H (Comando-Shift-H)                              | Ir para Início                                         |
| ⌘ (Espaço)                                         | Abrir Spotlight                                        |
| ⌘⇥ (Comando-Tab)                                   | Listar os últimos dez aplicativos usados               |
| ⌘\~                                                | Ir para o último App                                   |
| ⌘⇧3 (Comando-Shift-3)                              | Captura de tela (flutua no canto inferior esquerdo para salvar ou agir sobre ela) |
| ⌘⇧4                                                | Captura de tela e abrir no editor                      |
| Pressione e segure ⌘                               | Lista de atalhos disponíveis para o App                |
| ⌘⌥D (Comando-Opção/Alt-D)                          | Mostra o dock                                          |
| ^⌥H (Controle-Opção-H)                             | Botão Início                                           |
| ^⌥H H (Controle-Opção-H-H)                         | Mostrar barra de multitarefa                           |
| ^⌥I (Controle-Opção-i)                             | Escolha de item                                        |
| Escape                                             | Botão Voltar                                           |
| → (Seta para a direita)                            | Próximo item                                           |
| ← (Seta para a esquerda)                           | Item anterior                                          |
| ↑↓ (Seta para cima, Seta para baixo)               | Toque simultaneamente no item selecionado              |
| ⌥ ↓ (Opção-Seta para baixo)                        | Rolar para baixo                                       |
| ⌥↑ (Opção-Seta para cima)                          | Rolar para cima                                        |
| ⌥← ou ⌥→ (Opção-Seta para a esquerda ou Opção-Seta para a direita) | Rolar para a esquerda ou direita                      |
| ^⌥S (Controle-Opção-S)                             | Ligar ou desligar a fala do VoiceOver                  |
| ⌘⇧⇥ (Comando-Shift-Tab)                            | Mudar para o aplicativo anterior                       |
| ⌘⇥ (Comando-Tab)                                   | Voltar para o aplicativo original                      |
| ←+→, depois Opção + ← ou Opção+→                   | Navegar pelo Dock                                      |

### Atalhos do Safari

| Atalho                  | Ação                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Comando-L)          | Abrir Localização                               |
| ⌘T                      | Abrir uma nova aba                              |
| ⌘W                      | Fechar a aba atual                              |
| ⌘R                      | Atualizar a aba atual                           |
| ⌘.                      | Parar de carregar a aba atual                   |
| ^⇥                      | Mudar para a próxima aba                        |
| ^⇧⇥ (Controle-Shift-Tab) | Mover para a aba anterior                       |
| ⌘L                      | Selecionar o campo de texto/URL para modificá-lo|
| ⌘⇧T (Comando-Shift-T)   | Abrir a última aba fechada (pode ser usado várias vezes) |
| ⌘\[                     | Voltar uma página no histórico de navegação     |
| ⌘]                      | Avan
