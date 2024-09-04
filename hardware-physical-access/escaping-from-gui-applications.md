# Escapando de KIOSKs

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}



---

## Verificar dispositivo físico

|   Componente   | Acción                                                               |
| -------------- | -------------------------------------------------------------------- |
| Botón de encendido  | Apagar y encender el dispositivo puede exponer la pantalla de inicio      |
| Cable de alimentación   | Verificar si el dispositivo se reinicia cuando se corta brevemente la alimentación   |
| Puertos USB     | Conectar un teclado físico con más atajos                        |
| Ethernet      | Un escaneo de red o sniffing puede permitir una mayor explotación             |


## Verificar posibles acciones dentro de la aplicación GUI

**Diálogos Comunes** son aquellas opciones de **guardar un archivo**, **abrir un archivo**, seleccionar una fuente, un color... La mayoría de ellos **ofrecerán una funcionalidad completa de Explorador**. Esto significa que podrás acceder a las funcionalidades del Explorador si puedes acceder a estas opciones:

* Cerrar/Cerrar como
* Abrir/Abrir con
* Imprimir
* Exportar/Importar
* Buscar
* Escanear

Deberías verificar si puedes:

* Modificar o crear nuevos archivos
* Crear enlaces simbólicos
* Obtener acceso a áreas restringidas
* Ejecutar otras aplicaciones

### Ejecución de Comandos

Quizás **usando una opción `Abrir con`** puedas abrir/ejecutar algún tipo de shell.

#### Windows

Por ejemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encuentra más binarios que pueden ser usados para ejecutar comandos (y realizar acciones inesperadas) aquí: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Más aquí: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Eludir restricciones de ruta

* **Variables de entorno**: Hay muchas variables de entorno que apuntan a alguna ruta
* **Otros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Enlaces simbólicos**
* **Atajos**: CTRL+N (abrir nueva sesión), CTRL+R (Ejecutar Comandos), CTRL+SHIFT+ESC (Administrador de tareas), Windows+E (abrir explorador), CTRL-B, CTRL-I (Favoritos), CTRL-H (Historial), CTRL-L, CTRL-O (Archivo/Abrir Diálogo), CTRL-P (Diálogo de Imprimir), CTRL-S (Guardar como)
* Menú administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **Rutas UNC**: Rutas para conectarse a carpetas compartidas. Deberías intentar conectarte al C$ de la máquina local ("\\\127.0.0.1\c$\Windows\System32")
* **Más rutas UNC:**

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

### Descarga tus binarios

Consola: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorador: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor de registro: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Accediendo al sistema de archivos desde el navegador

| RUTA                | RUTA              | RUTA               | RUTA                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Atajos

* Teclas adhesivas – Presiona SHIFT 5 veces
* Teclas de mouse – SHIFT+ALT+NUMLOCK
* Alto contraste – SHIFT+ALT+PRINTSCN
* Teclas de alternancia – Mantén NUMLOCK durante 5 segundos
* Teclas de filtro – Mantén SHIFT derecho durante 12 segundos
* WINDOWS+F1 – Búsqueda de Windows
* WINDOWS+D – Mostrar escritorio
* WINDOWS+E – Lanzar el explorador de Windows
* WINDOWS+R – Ejecutar
* WINDOWS+U – Centro de accesibilidad
* WINDOWS+F – Buscar
* SHIFT+F10 – Menú contextual
* CTRL+SHIFT+ESC – Administrador de tareas
* CTRL+ALT+DEL – Pantalla de inicio en versiones más nuevas de Windows
* F1 – Ayuda F3 – Buscar
* F6 – Barra de direcciones
* F11 – Alternar pantalla completa dentro de Internet Explorer
* CTRL+H – Historial de Internet Explorer
* CTRL+T – Internet Explorer – Nueva pestaña
* CTRL+N – Internet Explorer – Nueva página
* CTRL+O – Abrir archivo
* CTRL+S – Guardar CTRL+N – Nueva RDP / Citrix

### Deslizamientos

* Desliza desde el lado izquierdo hacia la derecha para ver todas las ventanas abiertas, minimizando la aplicación KIOSK y accediendo directamente a todo el sistema operativo;
* Desliza desde el lado derecho hacia la izquierda para abrir el Centro de Acción, minimizando la aplicación KIOSK y accediendo directamente a todo el sistema operativo;
* Desliza desde el borde superior para hacer visible la barra de título de una aplicación abierta en modo de pantalla completa;
* Desliza hacia arriba desde la parte inferior para mostrar la barra de tareas en una aplicación de pantalla completa.

### Trucos de Internet Explorer

#### 'Barra de herramientas de imagen'

Es una barra de herramientas que aparece en la parte superior izquierda de la imagen cuando se hace clic. Podrás Guardar, Imprimir, Mailto, Abrir "Mis Imágenes" en el Explorador. El Kiosk necesita estar usando Internet Explorer.

#### Protocolo Shell

Escribe estas URL para obtener una vista de Explorador:

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
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Panel de Control
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mi Computadora
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mis Lugares de Red
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Mostrar extensiones de archivo

Consulta esta página para más información: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Trucos de navegadores

Versiones de respaldo de iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Crea un diálogo común usando JavaScript y accede al explorador de archivos: `document.write('<input/type=file>')`\
Fuente: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestos y botones

* Desliza hacia arriba con cuatro (o cinco) dedos / Doble toque en el botón de inicio: Para ver la vista de multitarea y cambiar de aplicación
* Desliza de un lado a otro con cuatro o cinco dedos: Para cambiar a la siguiente/última aplicación
* Pellizca la pantalla con cinco dedos / Toca el botón de inicio / Desliza hacia arriba con 1 dedo desde la parte inferior de la pantalla en un movimiento rápido hacia arriba: Para acceder a la pantalla de inicio
* Desliza un dedo desde la parte inferior de la pantalla solo 1-2 pulgadas (lento): La base aparecerá
* Desliza hacia abajo desde la parte superior de la pantalla con 1 dedo: Para ver tus notificaciones
* Desliza hacia abajo con 1 dedo en la esquina superior derecha de la pantalla: Para ver el centro de control del iPad Pro
* Desliza 1 dedo desde el lado izquierdo de la pantalla 1-2 pulgadas: Para ver la vista de Hoy
* Desliza rápido 1 dedo desde el centro de la pantalla hacia la derecha o hacia la izquierda: Para cambiar a la siguiente/última aplicación
* Presiona y mantén el botón de Encendido/**Apagar**/Reposo en la esquina superior derecha del **iPad +** Mueve el control deslizante de **apagar** todo el camino hacia la derecha: Para apagar
* Presiona el botón de Encendido/**Apagar**/Reposo en la esquina superior derecha del **iPad y el botón de inicio durante unos segundos**: Para forzar un apagado duro
* Presiona el botón de Encendido/**Apagar**/Reposo en la esquina superior derecha del **iPad y el botón de inicio rápidamente**: Para tomar una captura de pantalla que aparecerá en la parte inferior izquierda de la pantalla. Presiona ambos botones al mismo tiempo muy brevemente, ya que si los mantienes durante unos segundos se realizará un apagado duro.

### Atajos

Deberías tener un teclado para iPad o un adaptador de teclado USB. Solo se mostrarán los atajos que podrían ayudar a escapar de la aplicación.

| Tecla | Nombre         |
| ----- | -------------- |
| ⌘   | Comando      |
| ⌥   | Opción (Alt) |
| ⇧   | Shift        |
| ↩   | Retorno      |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Flecha Izquierda   |
| →   | Flecha Derecha  |
| ↑   | Flecha Arriba     |
| ↓   | Flecha Abajo     |

#### Atajos del sistema

Estos atajos son para la configuración visual y de sonido, dependiendo del uso del iPad.

| Atajo | Acción                                                                         |
| ----- | ------------------------------------------------------------------------------ |
| F1    | Atenuar pantalla                                                                |
| F2    | Aumentar brillo de pantalla                                                    |
| F7    | Retroceder una canción                                                          |
| F8    | Reproducir/pausar                                                               |
| F9    | Saltar canción                                                                  |
| F10   | Silenciar                                                                       |
| F11   | Disminuir volumen                                                                |
| F12   | Aumentar volumen                                                                |
| ⌘ Espacio  | Mostrar una lista de idiomas disponibles; para elegir uno, toca la barra espaciadora nuevamente. |

#### Navegación en iPad

| Atajo                                           | Acción                                                  |
| ------------------------------------------------ | ------------------------------------------------------- |
| ⌘H                                                 | Ir a Inicio                                            |
| ⌘⇧H (Comando-Shift-H)                              | Ir a Inicio                                            |
| ⌘ (Espacio)                                        | Abrir Spotlight                                        |
| ⌘⇥ (Comando-Tab)                                   | Listar las últimas diez aplicaciones usadas             |
| ⌘\~                                                | Ir a la última aplicación                               |
| ⌘⇧3 (Comando-Shift-3)                              | Captura de pantalla (flota en la parte inferior izquierda para guardar o actuar sobre ella) |
| ⌘⇧4                                                | Captura de pantalla y ábrela en el editor              |
| Presiona y mantén ⌘                                   | Lista de atajos disponibles para la aplicación         |
| ⌘⌥D (Comando-Opción/Alt-D)                         | Muestra el dock                                        |
| ^⌥H (Control-Opción-H)                             | Botón de inicio                                        |
| ^⌥H H (Control-Opción-H-H)                         | Mostrar barra de multitarea                             |
| ^⌥I (Control-Opción-i)                             | Selector de ítems                                      |
| Escape                                             | Botón de retroceso                                     |
| → (Flecha derecha)                                 | Siguiente ítem                                         |
| ← (Flecha izquierda)                                | Ítem anterior                                          |
| ↑↓ (Flecha arriba, Flecha abajo)                  | Toca simultáneamente el ítem seleccionado              |
| ⌥ ↓ (Opción-Flecha abajo)                          | Desplazarse hacia abajo                                |
| ⌥↑ (Opción-Flecha arriba)                         | Desplazarse hacia arriba                               |
| ⌥← o ⌥→ (Opción-Flecha izquierda o Opción-Flecha derecha) | Desplazarse a la izquierda o derecha                  |
| ^⌥S (Control-Opción-S)                             | Activar o desactivar el habla de VoiceOver            |
| ⌘⇧⇥ (Comando-Shift-Tab)                            | Cambiar a la aplicación anterior                       |
| ⌘⇥ (Comando-Tab)                                   | Volver a la aplicación original                        |
| ←+→, luego Opción + ← o Opción+→                   | Navegar a través del Dock                               |

#### Atajos de Safari

| Atajo                | Acción                                           |
| ------------------- | ------------------------------------------------ |
| ⌘L (Comando-L)      | Abrir Ubicación                                  |
| ⌘T                  | Abrir una nueva pestaña                          |
| ⌘W                  | Cerrar la pestaña actual                         |
| ⌘R                  | Actualizar la pestaña actual                     |
| ⌘.                  | Detener la carga de la pestaña actual           |
| ^⇥                  | Cambiar a la siguiente pestaña                   |
| ^⇧⇥ (Control-Shift-Tab) | Moverse a la pestaña anterior                   |
| ⌘L                  | Seleccionar el campo de entrada de texto/URL para modificarlo |
| ⌘⇧T (Comando-Shift-T) | Abrir la última pestaña cerrada (se puede usar varias veces) |
| ⌘\[                 | Retroceder una página en tu historial de navegación |
| ⌘]                  | Avanzar una página en tu historial de navegación |
| ⌘⇧R                 | Activar Modo Lector                              |

#### Atajos de Mail

| Atajo                   | Acción                       |
| ---------------------- | ---------------------------- |
| ⌘L                     | Abrir Ubicación              |
| ⌘T                     | Abrir una nueva pestaña      |
| ⌘W                     | Cerrar la pestaña actual     |
| ⌘R                     | Actualizar la pestaña actual |
| ⌘.                     | Detener la carga de la pestaña actual |
| ⌘⌥F (Comando-Opción/Alt-F) | Buscar en tu bandeja de entrada |

## Referencias

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)



{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
