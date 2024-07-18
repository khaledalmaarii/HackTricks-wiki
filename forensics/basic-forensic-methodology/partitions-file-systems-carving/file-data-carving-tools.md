{% hint style="success" %}
Aprende y practica AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}


# Herramientas de Carving

## Autopsy

La herramienta más común utilizada en forense para extraer archivos de imágenes es [**Autopsy**](https://www.autopsy.com/download/). Descárgala, instálala y haz que ingiera el archivo para encontrar archivos "ocultos". Ten en cuenta que Autopsy está diseñado para admitir imágenes de disco y otros tipos de imágenes, pero no archivos simples.

## Binwalk <a id="binwalk"></a>

**Binwalk** es una herramienta para buscar archivos binarios como imágenes y archivos de audio en busca de archivos y datos incrustados.
Puede ser instalado con `apt`, sin embargo, el [origen](https://github.com/ReFirmLabs/binwalk) se puede encontrar en github.
**Comandos útiles**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Otra herramienta común para encontrar archivos ocultos es **foremost**. Puedes encontrar el archivo de configuración de foremost en `/etc/foremost.conf`. Si solo deseas buscar archivos específicos, descoméntalos. Si no descomentas nada, foremost buscará por los tipos de archivo configurados por defecto.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** es otra herramienta que se puede utilizar para encontrar y extraer **archivos incrustados en un archivo**. En este caso, deberás descomentar en el archivo de configuración \(_/etc/scalpel/scalpel.conf_\) los tipos de archivo que deseas extraer.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Esta herramienta viene incluida en Kali pero puedes encontrarla aquí: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Esta herramienta puede escanear una imagen y **extraer pcaps** en su interior, **información de red \(URLs, dominios, IPs, MACs, correos electrónicos\)** y más **archivos**. Solo necesitas hacer:
```text
bulk_extractor memory.img -o out_folder
```
Explora **toda la información** que la herramienta ha recopilado \(¿contraseñas?\), **analiza** los **paquetes** \(lee [**Análisis de Pcaps**](../pcap-inspection/)\), busca **dominios extraños** \(dominios relacionados con **malware** o **no existentes**\).

## PhotoRec

Puedes encontrarlo en [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Viene con versión GUI y CLI. Puedes seleccionar los **tipos de archivos** que deseas que PhotoRec busque.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Herramientas Específicas de Carving de Datos

## FindAES

Busca claves AES buscando sus programaciones de claves. Capaz de encontrar claves de 128, 192 y 256 bits, como las utilizadas por TrueCrypt y BitLocker.

Descarga [aquí](https://sourceforge.net/projects/findaes/).

# Herramientas complementarias

Puedes usar [**viu** ](https://github.com/atanunq/viu)para ver imágenes desde la terminal.
Puedes usar la herramienta de línea de comandos de Linux **pdftotext** para transformar un PDF en texto y leerlo.



{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* ¡Consulta los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
