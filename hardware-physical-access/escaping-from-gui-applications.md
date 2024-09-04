# Escapando de KIOSKs

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}



---

## Verifique o dispositivo físico

|   Componente   | Ação                                                               |
| -------------- | ------------------------------------------------------------------ |
| Botão de energia| Desligar e ligar o dispositivo pode expor a tela de inicialização  |
| Cabo de energia | Verifique se o dispositivo reinicia quando a energia é cortada brevemente |
| Portas USB     | Conecte um teclado físico com mais atalhos                        |
| Ethernet       | A varredura de rede ou sniffing pode permitir mais exploração     |


## Verifique as possíveis ações dentro da aplicação GUI

**Diálogos Comuns** são aquelas opções de **salvar um arquivo**, **abrir um arquivo**, selecionar uma fonte, uma cor... A maioria deles **oferecerá uma funcionalidade completa do Explorer**. Isso significa que você poderá acessar funcionalidades do Explorer se conseguir acessar essas opções:

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

### Execução de Comandos

Talvez **usando a opção `Abrir com`** você possa abrir/executar algum tipo de shell.

#### Windows

Por exemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encontre mais binários que podem ser usados para executar comandos (e realizar ações inesperadas) aqui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Mais aqui: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Contornando restrições de caminho

* **Variáveis de ambiente**: Existem muitas variáveis de ambiente que apontam para algum caminho
* **Outros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Links simbólicos**
* **Atalhos**: CTRL+N (abrir nova sessão), CTRL+R (Executar Comandos), CTRL+SHIFT+ESC (Gerenciador de Tarefas), Windows+E (abrir explorer), CTRL-B, CTRL-I (Favoritos), CTRL-H (Histórico), CTRL-L, CTRL-O (Arquivo/Abrir Diálogo), CTRL-P (Diálogo de Impressão), CTRL-S (Salvar Como)
* Menu Administrativo Oculto: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **Caminhos UNC**: Caminhos para conectar a pastas compartilhadas. Você deve tentar conectar ao C$ da máquina local ("\\\127.0.0.1\c$\Windows\System32")
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

### Baixe Seus Binários

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor de registro: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Acessando o sistema de arquivos pelo navegador

| CAMINHO              | CAMINHO            | CAMINHO             | CAMINHO              |
| -------------------- | ------------------ | ------------------- | --------------------- |
| File:/C:/windows     | File:/C:/windows/  | File:/C:/windows\\  | File:/C:\windows      |
| File:/C:\windows\\   | File:/C:\windows/  | File://C:/windows   | File://C:/windows/    |
| File://C:/windows\\  | File://C:\windows  | File://C:\windows/  | File://C:\windows\\   |
| C:/windows           | C:/windows/        | C:/windows\\        | C:\windows            |
| C:\windows\\         | C:\windows/        | %WINDIR%            | %TMP%                 |
| %TEMP%               | %SYSTEMDRIVE%      | %SYSTEMROOT%        | %APPDATA%             |
| %HOMEDRIVE%          | %HOMESHARE         |                     | <p><br></p>           |

### Atalhos

* Teclas de Aderência – Pressione SHIFT 5 vezes
* Teclas de Mouse – SHIFT+ALT+NUMLOCK
* Alto Contraste – SHIFT+ALT+PRINTSCN
* Teclas de Alternância – Mantenha NUMLOCK pressionado por 5 segundos
* Teclas de Filtro – Mantenha SHIFT direito pressionado por 12 segundos
* WINDOWS+F1 – Pesquisa do Windows
* WINDOWS+D – Mostrar Área de Trabalho
* WINDOWS+E – Iniciar o Windows Explorer
* WINDOWS+R – Executar
* WINDOWS+U – Centro de Acessibilidade
* WINDOWS+F – Pesquisar
* SHIFT+F10 – Menu de Contexto
* CTRL+SHIFT+ESC – Gerenciador de Tarefas
* CTRL+ALT+DEL – Tela de inicialização em versões mais recentes do Windows
* F1 – Ajuda F3 – Pesquisar
* F6 – Barra de Endereços
* F11 – Alternar tela cheia no Internet Explorer
* CTRL+H – Histórico do Internet Explorer
* CTRL+T – Internet Explorer – Nova Aba
* CTRL+N – Internet Explorer – Nova Página
* CTRL+O – Abrir Arquivo
* CTRL+S – Salvar CTRL+N – Novo RDP / Citrix

### Deslizes

* Deslize do lado esquerdo para o direito para ver todas as janelas abertas, minimizando o aplicativo KIOSK e acessando todo o SO diretamente;
* Deslize do lado direito para o esquerdo para abrir o Centro de Ações, minimizando o aplicativo KIOSK e acessando todo o SO diretamente;
* Deslize a partir da borda superior para tornar a barra de título visível para um aplicativo aberto em modo de tela cheia;
* Deslize para cima a partir da parte inferior para mostrar a barra de tarefas em um aplicativo de tela cheia.

### Truques do Internet Explorer

#### 'Barra de Imagem'

É uma barra de ferramentas que aparece no canto superior esquerdo da imagem quando é clicada. Você poderá Salvar, Imprimir, Enviar por e-mail, Abrir "Minhas Imagens" no Explorer. O Kiosk precisa estar usando o Internet Explorer.

#### Protocolo Shell

Digite estas URLs para obter uma visualização do Explorer:

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Painel de Controle
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Meu Computador
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Minhas Pastas de Rede
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Mostrar Extensões de Arquivo

Verifique esta página para mais informações: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Truques de Navegadores

Versões de backup do iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Crie um diálogo comum usando JavaScript e acesse o explorador de arquivos: `document.write('<input/type=file>')`\
Fonte: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestos e botões

* Deslize para cima com quatro (ou cinco) dedos / Toque duas vezes no botão Home: Para ver a visualização de multitarefa e mudar de aplicativo
* Deslize de um lado ou de outro com quatro ou cinco dedos: Para mudar para o próximo/último aplicativo
* Pinça a tela com cinco dedos / Toque no botão Home / Deslize para cima com 1 dedo a partir da parte inferior da tela em um movimento rápido para cima: Para acessar a tela inicial
* Deslize um dedo a partir da parte inferior da tela apenas 1-2 polegadas (devagar): O dock aparecerá
* Deslize para baixo a partir do topo da tela com 1 dedo: Para ver suas notificações
* Deslize para baixo com 1 dedo no canto superior direito da tela: Para ver o centro de controle do iPad Pro
* Deslize 1 dedo a partir da esquerda da tela 1-2 polegadas: Para ver a visualização de Hoje
* Deslize rapidamente 1 dedo do centro da tela para a direita ou esquerda: Para mudar para o próximo/último aplicativo
* Pressione e segure o botão Ligar/**Desligar**/Suspender no canto superior direito do **iPad +** Mova o controle deslizante para **desligar** completamente para a direita: Para desligar
* Pressione o botão Ligar/**Desligar**/Suspender no canto superior direito do **iPad e o botão Home por alguns segundos**: Para forçar um desligamento completo
* Pressione o botão Ligar/**Desligar**/Suspender no canto superior direito do **iPad e o botão Home rapidamente**: Para tirar uma captura de tela que aparecerá no canto inferior esquerdo da tela. Pressione ambos os botões ao mesmo tempo muito rapidamente, pois se você mantiver pressionado por alguns segundos, um desligamento completo será realizado.

### Atalhos

Você deve ter um teclado de iPad ou um adaptador de teclado USB. Apenas os atalhos que podem ajudar a escapar da aplicação serão mostrados aqui.

| Tecla | Nome         |
| ----- | ------------ |
| ⌘   | Comando      |
| ⌥   | Opção (Alt) |
| ⇧   | Shift        |
| ↩   | Retorno      |
| ⇥   | Tab          |
| ^   | Controle     |
| ←   | Seta para a Esquerda   |
| →   | Seta para a Direita  |
| ↑   | Seta para Cima     |
| ↓   | Seta para Baixo   |

#### Atalhos do sistema

Esses atalhos são para as configurações visuais e de som, dependendo do uso do iPad.

| Atalho | Ação                                                                         |
| ------ | ----------------------------------------------------------------------------- |
| F1     | Diminuir a tela                                                              |
| F2     | Aumentar a tela                                                              |
| F7     | Voltar uma música                                                            |
| F8     | Reproduzir/pause                                                             |
| F9     | Pular música                                                                  |
| F10    | Mudo                                                                         |
| F11    | Diminuir volume                                                              |
| F12    | Aumentar volume                                                              |
| ⌘ Espa | Exibir uma lista de idiomas disponíveis; para escolher um, toque na barra de espaço novamente. |

#### Navegação no iPad

| Atalho                                           | Ação                                                  |
| ------------------------------------------------ | ----------------------------------------------------- |
| ⌘H                                             | Ir para a tela inicial                                |
| ⌘⇧H (Command-Shift-H)                          | Ir para a tela inicial                                |
| ⌘ (Espaço)                                     | Abrir Spotlight                                      |
| ⌘⇥ (Command-Tab)                               | Listar os últimos dez aplicativos usados              |
| ⌘\~                                            | Ir para o último aplicativo                            |
| ⌘⇧3 (Command-Shift-3)                          | Captura de tela (paira no canto inferior esquerdo para salvar ou agir sobre ela) |
| ⌘⇧4                                            | Captura de tela e abri-la no editor                  |
| Pressione e segure ⌘                           | Lista de atalhos disponíveis para o aplicativo        |
| ⌘⌥D (Command-Option/Alt-D)                     | Abre o dock                                          |
| ^⌥H (Control-Option-H)                         | Botão Home                                           |
| ^⌥H H (Control-Option-H-H)                     | Mostrar a barra de multitarefa                        |
| ^⌥I (Control-Option-i)                         | Seletor de itens                                      |
| Escape                                         | Botão voltar                                         |
| → (Seta para a Direita)                        | Próximo item                                         |
| ← (Seta para a Esquerda)                       | Item anterior                                        |
| ↑↓ (Seta para Cima, Seta para Baixo)          | Toque simultaneamente no item selecionado            |
| ⌥ ↓ (Option-Seta para Baixo)                  | Rolagem para baixo                                   |
| ⌥↑ (Option-Seta para Cima)                    | Rolagem para cima                                    |
| ⌥← ou ⌥→ (Option-Seta para a Esquerda ou Option-Seta para a Direita) | Rolagem para a esquerda ou para a direita            |
| ^⌥S (Control-Option-S)                         | Ativar ou desativar a fala do VoiceOver             |
| ⌘⇧⇥ (Command-Shift-Tab)                        | Alternar para o aplicativo anterior                  |
| ⌘⇥ (Command-Tab)                               | Voltar para o aplicativo original                     |
| ←+→, então Option + ← ou Option+→              | Navegar pelo Dock                                    |

#### Atalhos do Safari

| Atalho                | Ação                                           |
| --------------------- | ---------------------------------------------- |
| ⌘L (Command-L)        | Abrir Localização                              |
| ⌘T                    | Abrir uma nova aba                             |
| ⌘W                    | Fechar a aba atual                            |
| ⌘R                    | Atualizar a aba atual                          |
| ⌘.                    | Parar de carregar a aba atual                 |
| ^⇥                    | Alternar para a próxima aba                   |
| ^⇧⇥ (Control-Shift-Tab) | Mover para a aba anterior                     |
| ⌘L                    | Selecionar o campo de entrada de texto/URL para modificá-lo |
| ⌘⇧T (Command-Shift-T) | Abrir a última aba fechada (pode ser usado várias vezes) |
| ⌘\[                   | Voltar uma página no seu histórico de navegação |
| ⌘]                    | Avançar uma página no seu histórico de navegação |
| ⌘⇧R                   | Ativar o Modo Leitor                           |

#### Atalhos do Mail

| Atalho                   | Ação                       |
| ------------------------ | -------------------------- |
| ⌘L                       | Abrir Localização          |
| ⌘T                       | Abrir uma nova aba         |
| ⌘W                       | Fechar a aba atual        |
| ⌘R                       | Atualizar a aba atual      |
| ⌘.                       | Parar de carregar a aba atual |
| ⌘⌥F (Command-Option/Alt-F) | Pesquisar na sua caixa de entrada |

## Referências

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)



{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
