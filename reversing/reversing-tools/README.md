{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

# Guía de Decompilación de Wasm y Compilación de Wat

En el ámbito de **WebAssembly**, las herramientas para **decompilar** y **compilar** son esenciales para los desarrolladores. Esta guía presenta algunos recursos en línea y software para manejar archivos **Wasm (binario de WebAssembly)** y **Wat (texto de WebAssembly)**.

## Herramientas en Línea

- Para **decompilar** Wasm a Wat, la herramienta disponible en [la demo wasm2wat de Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) es útil.
- Para **compilar** Wat de nuevo a Wasm, la [demo wat2wasm de Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/) cumple con el propósito.
- Otra opción de decompilación se puede encontrar en [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Soluciones de Software

- Para una solución más robusta, [JEB de PNF Software](https://www.pnfsoftware.com/jeb/demo) ofrece características extensas.
- El proyecto de código abierto [wasmdec](https://github.com/wwwg/wasmdec) también está disponible para tareas de decompilación.

# Recursos de Decompilación de .Net

Decompilar ensamblados .Net se puede lograr con herramientas como:

- [ILSpy](https://github.com/icsharpcode/ILSpy), que también ofrece un [plugin para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), permitiendo su uso multiplataforma.
- Para tareas que involucran **decompilación**, **modificación** y **recompilación**, se recomienda encarecidamente [dnSpy](https://github.com/0xd4d/dnSpy/releases). **Hacer clic derecho** en un método y elegir **Modificar Método** permite cambios en el código.
- [dotPeek de JetBrains](https://www.jetbrains.com/es-es/decompiler/) es otra alternativa para decompilar ensamblados .Net.

## Mejorando la Depuración y Registro con DNSpy

### Registro de DNSpy
Para registrar información en un archivo usando DNSpy, incorpora el siguiente fragmento de código .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Contraseña: " + password + "\n");
%%%

### Depuración de DNSpy
Para una depuración efectiva con DNSpy, se recomienda una secuencia de pasos para ajustar los **atributos de ensamblado** para la depuración, asegurando que las optimizaciones que podrían obstaculizar la depuración estén deshabilitadas. Este proceso incluye cambiar la configuración de `DebuggableAttribute`, recompilar el ensamblado y guardar los cambios.

Además, para depurar una aplicación .Net ejecutada por **IIS**, ejecutar `iisreset /noforce` reinicia IIS. Para adjuntar DNSpy al proceso de IIS para depuración, la guía instruye sobre seleccionar el proceso **w3wp.exe** dentro de DNSpy y comenzar la sesión de depuración.

Para una vista completa de los módulos cargados durante la depuración, se aconseja acceder a la ventana de **Módulos** en DNSpy, seguida de abrir todos los módulos y ordenar los ensamblados para facilitar la navegación y depuración.

Esta guía encapsula la esencia de la decompilación de WebAssembly y .Net, ofreciendo un camino para que los desarrolladores naveguen estas tareas con facilidad.

## **Decompilador de Java**
Para decompilar bytecode de Java, estas herramientas pueden ser muy útiles:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Depuración de DLLs**
### Usando IDA
- **Rundll32** se carga desde rutas específicas para versiones de 64 bits y 32 bits.
- **Windbg** se selecciona como el depurador con la opción de suspender en la carga/descarga de bibliotecas habilitada.
- Los parámetros de ejecución incluyen la ruta de la DLL y el nombre de la función. Esta configuración detiene la ejecución al cargar cada DLL.

### Usando x64dbg/x32dbg
- Similar a IDA, **rundll32** se carga con modificaciones en la línea de comandos para especificar la DLL y la función.
- Se ajustan las configuraciones para romper en la entrada de la DLL, permitiendo establecer un punto de interrupción en el punto de entrada deseado de la DLL.

### Imágenes
- Los puntos de detención de ejecución y configuraciones se ilustran a través de capturas de pantalla.

## **ARM & MIPS**
- Para emulación, [arm_now](https://github.com/nongiach/arm_now) es un recurso útil.

## **Shellcodes**
### Técnicas de Depuración
- **Blobrunner** y **jmp2it** son herramientas para asignar shellcodes en memoria y depurarlos con Ida o x64dbg.
- Blobrunner [versiones](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [versión compilada](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** ofrece emulación e inspección de shellcode basada en GUI, destacando las diferencias en el manejo de shellcode como un archivo frente a shellcode directo.

### Desofuscación y Análisis
- **scdbg** proporciona información sobre funciones de shellcode y capacidades de desofuscación.
%%%bash
scdbg.exe -f shellcode # Información básica
scdbg.exe -f shellcode -r # Informe de análisis
scdbg.exe -f shellcode -i -r # Hooks interactivos
scdbg.exe -f shellcode -d # Volcar shellcode decodificado
scdbg.exe -f shellcode /findsc # Encontrar desplazamiento de inicio
scdbg.exe -f shellcode /foff 0x0000004D # Ejecutar desde el desplazamiento
%%%

- **CyberChef** para desensamblar shellcode: [receta de CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Un ofuscador que reemplaza todas las instrucciones con `mov`.
- Recursos útiles incluyen una [explicación en YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) y [diapositivas en PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** podría revertir la ofuscación de movfuscator, requiriendo dependencias como `libcapstone-dev` y `libz3-dev`, e instalando [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Para binarios de Delphi, se recomienda [IDR](https://github.com/crypto2011/IDR).


# Cursos

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Desofuscación binaria\)



{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}
