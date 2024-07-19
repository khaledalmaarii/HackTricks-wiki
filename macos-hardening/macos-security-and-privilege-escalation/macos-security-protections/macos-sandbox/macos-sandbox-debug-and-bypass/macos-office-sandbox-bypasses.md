# Bypass del Sandbox de Office en macOS

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos en** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

### Bypass del Sandbox de Word a través de Launch Agents

La aplicación utiliza un **Sandbox personalizado** usando el derecho **`com.apple.security.temporary-exception.sbpl`** y este sandbox personalizado permite escribir archivos en cualquier lugar siempre que el nombre del archivo comience con `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Por lo tanto, escapar fue tan fácil como **escribir un `plist`** LaunchAgent en `~/Library/LaunchAgents/~$escape.plist`.

Revisa el [**informe original aquí**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Bypass del Sandbox de Word a través de Login Items y zip

Recuerda que desde el primer escape, Word puede escribir archivos arbitrarios cuyos nombres comiencen con `~$`, aunque después del parche de la vulnerabilidad anterior no era posible escribir en `/Library/Application Scripts` o en `/Library/LaunchAgents`.

Se descubrió que desde dentro del sandbox es posible crear un **Login Item** (aplicaciones que se ejecutarán cuando el usuario inicie sesión). Sin embargo, estas aplicaciones **no se ejecutarán a menos que** estén **notarizadas** y **no es posible agregar argumentos** (por lo que no puedes simplemente ejecutar un shell inverso usando **`bash`**).

Desde el bypass anterior del Sandbox, Microsoft deshabilitó la opción de escribir archivos en `~/Library/LaunchAgents`. Sin embargo, se descubrió que si pones un **archivo zip como Login Item**, el `Archive Utility` simplemente **descomprimirá** en su ubicación actual. Así que, debido a que por defecto la carpeta `LaunchAgents` de `~/Library` no se crea, fue posible **comprimir un plist en `LaunchAgents/~$escape.plist`** y **colocar** el archivo zip en **`~/Library`** para que al descomprimirlo alcance el destino de persistencia.

Revisa el [**informe original aquí**](https://objective-see.org/blog/blog\_0x4B.html).

### Bypass del Sandbox de Word a través de Login Items y .zshenv

(Recuerda que desde el primer escape, Word puede escribir archivos arbitrarios cuyos nombres comiencen con `~$`).

Sin embargo, la técnica anterior tenía una limitación, si la carpeta **`~/Library/LaunchAgents`** existe porque algún otro software la creó, fallaría. Así que se descubrió una cadena diferente de Login Items para esto.

Un atacante podría crear los archivos **`.bash_profile`** y **`.zshenv`** con la carga útil para ejecutar y luego comprimirlos y **escribir el zip en la** carpeta del usuario de la víctima: **`~/~$escape.zip`**.

Luego, agregar el archivo zip a los **Login Items** y luego la aplicación **`Terminal`**. Cuando el usuario vuelva a iniciar sesión, el archivo zip se descomprimiría en los archivos del usuario, sobrescribiendo **`.bash_profile`** y **`.zshenv`** y, por lo tanto, el terminal ejecutará uno de estos archivos (dependiendo de si se usa bash o zsh).

Revisa el [**informe original aquí**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Bypass del Sandbox de Word con Open y variables de entorno

Desde procesos en sandbox todavía es posible invocar otros procesos usando la utilidad **`open`**. Además, estos procesos se ejecutarán **dentro de su propio sandbox**.

Se descubrió que la utilidad open tiene la opción **`--env`** para ejecutar una aplicación con **variables de entorno específicas**. Por lo tanto, fue posible crear el **archivo `.zshenv`** dentro de una carpeta **dentro** del **sandbox** y usar `open` con `--env` configurando la **variable `HOME`** a esa carpeta abriendo esa aplicación `Terminal`, que ejecutará el archivo `.zshenv` (por alguna razón también fue necesario establecer la variable `__OSINSTALL_ENVIROMENT`).

Revisa el [**informe original aquí**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Bypass del Sandbox de Word con Open y stdin

La utilidad **`open`** también soportaba el parámetro **`--stdin`** (y después del bypass anterior ya no era posible usar `--env`).

La cuestión es que incluso si **`python`** estaba firmado por Apple, **no ejecutará** un script con el atributo **`quarantine`**. Sin embargo, fue posible pasarle un script desde stdin, por lo que no verificará si estaba en cuarentena o no:&#x20;

1. Dejar un archivo **`~$exploit.py`** con comandos de Python arbitrarios.
2. Ejecutar _open_ **`–stdin='~$exploit.py' -a Python`**, que ejecuta la aplicación Python con nuestro archivo dejado sirviendo como su entrada estándar. Python ejecuta felizmente nuestro código, y dado que es un proceso hijo de _launchd_, no está sujeto a las reglas del sandbox de Word.

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos en** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}
