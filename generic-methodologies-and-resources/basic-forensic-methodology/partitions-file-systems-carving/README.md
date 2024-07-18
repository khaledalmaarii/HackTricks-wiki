# Partitions/File Systems/Carving

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Partitions

Un disco duro o un **SSD puede contener diferentes particiones** con el objetivo de separar datos físicamente.\
La **unidad mínima** de un disco es el **sector** (normalmente compuesto de 512B). Por lo tanto, el tamaño de cada partición debe ser un múltiplo de ese tamaño.

### MBR (master Boot Record)

Se asigna en el **primer sector del disco después de los 446B del código de arranque**. Este sector es esencial para indicar a la PC qué y de dónde debe montarse una partición.\
Permite hasta **4 particiones** (como máximo **solo 1** puede estar activa/**arrancable**). Sin embargo, si necesitas más particiones, puedes usar **particiones extendidas**. El **byte final** de este primer sector es la firma del registro de arranque **0x55AA**. Solo una partición puede marcarse como activa.\
MBR permite **máx 2.2TB**.

![](<../../../.gitbook/assets/image (350).png>)

![](<../../../.gitbook/assets/image (304).png>)

Desde los **bytes 440 a 443** del MBR puedes encontrar la **Firma de Disco de Windows** (si se usa Windows). La letra de unidad lógica del disco duro depende de la Firma de Disco de Windows. Cambiar esta firma podría impedir que Windows arranque (herramienta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (310).png>)

**Formato**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Código de arranque  |
| 446 (0x1BE) | 16 (0x10)  | Primera partición   |
| 462 (0x1CE) | 16 (0x10)  | Segunda partición    |
| 478 (0x1DE) | 16 (0x10)  | Tercera partición   |
| 494 (0x1EE) | 16 (0x10)  | Cuarta partición    |
| 510 (0x1FE) | 2 (0x2)    | Firma 0x55 0xAA    |

**Formato del Registro de Partición**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Bandera activa (0x80 = arrancable)                    |
| 1 (0x01)  | 1 (0x01) | Cabeza de inicio                                       |
| 2 (0x02)  | 1 (0x01) | Sector de inicio (bits 0-5); bits superiores del cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01) | Cilindro de inicio, 8 bits más bajos                  |
| 4 (0x04)  | 1 (0x01) | Código de tipo de partición (0x83 = Linux)            |
| 5 (0x05)  | 1 (0x01) | Cabeza final                                           |
| 6 (0x06)  | 1 (0x01) | Sector final (bits 0-5); bits superiores del cilindro (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Cilindro final, 8 bits más bajos                      |
| 8 (0x08)  | 4 (0x04) | Sectores precedentes a la partición (little endian)   |
| 12 (0x0C) | 4 (0x04) | Sectores en la partición                               |

Para montar un MBR en Linux, primero necesitas obtener el desplazamiento de inicio (puedes usar `fdisk` y el comando `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Y luego usa el siguiente código
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Dirección de bloque lógico)**

**La dirección de bloque lógico** (**LBA**) es un esquema común utilizado para **especificar la ubicación de bloques** de datos almacenados en dispositivos de almacenamiento de computadoras, generalmente sistemas de almacenamiento secundario como discos duros. LBA es un esquema de direccionamiento lineal particularmente simple; **los bloques se localizan mediante un índice entero**, siendo el primer bloque LBA 0, el segundo LBA 1, y así sucesivamente.

### GPT (Tabla de particiones GUID)

La Tabla de Particiones GUID, conocida como GPT, es preferida por sus capacidades mejoradas en comparación con MBR (Registro de arranque maestro). Distintiva por su **identificador único global** para particiones, GPT se destaca en varios aspectos:

* **Ubicación y tamaño**: Tanto GPT como MBR comienzan en **sector 0**. Sin embargo, GPT opera en **64 bits**, en contraste con los 32 bits de MBR.
* **Límites de partición**: GPT admite hasta **128 particiones** en sistemas Windows y acomoda hasta **9.4ZB** de datos.
* **Nombres de partición**: Ofrece la capacidad de nombrar particiones con hasta 36 caracteres Unicode.

**Resiliencia y recuperación de datos**:

* **Redundancia**: A diferencia de MBR, GPT no confina la partición y los datos de arranque a un solo lugar. Replica estos datos a lo largo del disco, mejorando la integridad y resiliencia de los datos.
* **Verificación de redundancia cíclica (CRC)**: GPT emplea CRC para asegurar la integridad de los datos. Monitorea activamente la corrupción de datos y, cuando se detecta, GPT intenta recuperar los datos corruptos desde otra ubicación del disco.

**MBR protector (LBA0)**:

* GPT mantiene la compatibilidad hacia atrás a través de un MBR protector. Esta característica reside en el espacio MBR legado pero está diseñada para evitar que utilidades basadas en MBR más antiguas sobrescriban erróneamente discos GPT, protegiendo así la integridad de los datos en discos formateados con GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (1062).png>)

**MBR híbrido (LBA 0 + GPT)**

[Desde Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

En sistemas operativos que soportan **arranque basado en GPT a través de servicios BIOS** en lugar de EFI, el primer sector también puede seguir utilizándose para almacenar la primera etapa del código del **bootloader**, pero **modificado** para reconocer **particiones GPT**. El bootloader en el MBR no debe asumir un tamaño de sector de 512 bytes.

**Encabezado de la tabla de particiones (LBA 1)**

[Desde Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

El encabezado de la tabla de particiones define los bloques utilizables en el disco. También define el número y tamaño de las entradas de partición que componen la tabla de particiones (desplazamientos 80 y 84 en la tabla).

| Desplazamiento | Longitud | Contenido                                                                                                                                                                        |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)       | 8 bytes  | Firma ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h o 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)en máquinas little-endian) |
| 8 (0x08)       | 4 bytes  | Revisión 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                     |
| 12 (0x0C)      | 4 bytes  | Tamaño del encabezado en little endian (en bytes, generalmente 5Ch 00h 00h 00h o 92 bytes)                                                                                                    |
| 16 (0x10)      | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) del encabezado (desplazamiento +0 hasta el tamaño del encabezado) en little endian, con este campo en cero durante el cálculo                                |
| 20 (0x14)      | 4 bytes  | Reservado; debe ser cero                                                                                                                                                          |
| 24 (0x18)      | 8 bytes  | LBA actual (ubicación de esta copia del encabezado)                                                                                                                                      |
| 32 (0x20)      | 8 bytes  | LBA de respaldo (ubicación de la otra copia del encabezado)                                                                                                                                  |
| 40 (0x28)      | 8 bytes  | Primer LBA utilizable para particiones (último LBA de la tabla de particiones primaria + 1)                                                                                                          |
| 48 (0x30)      | 8 bytes  | Último LBA utilizable (primer LBA de la tabla de particiones secundaria − 1)                                                                                                                       |
| 56 (0x38)      | 16 bytes | GUID del disco en endian mixto                                                                                                                                                       |
| 72 (0x48)      | 8 bytes  | LBA inicial de un array de entradas de partición (siempre 2 en la copia primaria)                                                                                                        |
| 80 (0x50)      | 4 bytes  | Número de entradas de partición en el array                                                                                                                                            |
| 84 (0x54)      | 4 bytes  | Tamaño de una sola entrada de partición (generalmente 80h o 128)                                                                                                                           |
| 88 (0x58)      | 4 bytes  | CRC32 del array de entradas de partición en little endian                                                                                                                               |
| 92 (0x5C)      | \*       | Reservado; debe ser ceros para el resto del bloque (420 bytes para un tamaño de sector de 512 bytes; pero puede ser más con tamaños de sector más grandes)                                         |

**Entradas de partición (LBA 2–33)**

| Formato de entrada de partición GUID |          |                                                                                                                   |
| ------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Desplazamiento                        | Longitud | Contenido                                                                                                          |
| 0 (0x00)                              | 16 bytes | [Tipo de partición GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (endian mixto) |
| 16 (0x10)                             | 16 bytes | GUID de partición único (endian mixto)                                                                              |
| 32 (0x20)                             | 8 bytes  | Primer LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                             | 8 bytes  | Último LBA (inclusive, generalmente impar)                                                                                 |
| 48 (0x30)                             | 8 bytes  | Banderas de atributos (por ejemplo, el bit 60 denota solo lectura)                                                                   |
| 56 (0x38)                             | 72 bytes | Nombre de la partición (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE unidades de código)                                   |

**Tipos de particiones**

![](<../../../.gitbook/assets/image (83).png>)

Más tipos de particiones en [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspección

Después de montar la imagen forense con [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), puedes inspeccionar el primer sector utilizando la herramienta de Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** En la imagen siguiente se detectó un **MBR** en el **sector 0** e interpretado:

![](<../../../.gitbook/assets/image (354).png>)

Si fuera una **tabla GPT en lugar de un MBR**, debería aparecer la firma _EFI PART_ en el **sector 1** (que en la imagen anterior está vacío).

## Sistemas de archivos

### Lista de sistemas de archivos de Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

El sistema de archivos **FAT (Tabla de asignación de archivos)** está diseñado en torno a su componente central, la tabla de asignación de archivos, situada al inicio del volumen. Este sistema protege los datos manteniendo **dos copias** de la tabla, asegurando la integridad de los datos incluso si una se corrompe. La tabla, junto con la carpeta raíz, debe estar en una **ubicación fija**, crucial para el proceso de arranque del sistema.

La unidad básica de almacenamiento del sistema de archivos es un **cluster, generalmente de 512B**, que comprende múltiples sectores. FAT ha evolucionado a través de versiones:

* **FAT12**, que admite direcciones de cluster de 12 bits y maneja hasta 4078 clusters (4084 con UNIX).
* **FAT16**, que mejora a direcciones de 16 bits, permitiendo hasta 65,517 clusters.
* **FAT32**, que avanza aún más con direcciones de 32 bits, permitiendo un impresionante 268,435,456 clusters por volumen.

Una limitación significativa en todas las versiones de FAT es el **tamaño máximo de archivo de 4GB**, impuesto por el campo de 32 bits utilizado para el almacenamiento del tamaño del archivo.

Los componentes clave del directorio raíz, particularmente para FAT12 y FAT16, incluyen:

* **Nombre de archivo/carpeta** (hasta 8 caracteres)
* **Atributos**
* **Fechas de creación, modificación y último acceso**
* **Dirección de la tabla FAT** (que indica el cluster inicial del archivo)
* **Tamaño del archivo**

### EXT

**Ext2** es el sistema de archivos más común para **particiones que no registran** (**particiones que no cambian mucho**) como la partición de arranque. **Ext3/4** son **con registro** y se utilizan generalmente para el **resto de las particiones**.

## **Metadatos**

Algunos archivos contienen metadatos. Esta información se refiere al contenido del archivo que a veces puede ser interesante para un analista, ya que dependiendo del tipo de archivo, puede tener información como:

* Título
* Versión de MS Office utilizada
* Autor
* Fechas de creación y última modificación
* Modelo de la cámara
* Coordenadas GPS
* Información de la imagen

Puedes usar herramientas como [**exiftool**](https://exiftool.org) y [**Metadiver**](https://www.easymetadata.com/metadiver-2/) para obtener los metadatos de un archivo.

## **Recuperación de archivos eliminados**

### Archivos eliminados registrados

Como se vio antes, hay varios lugares donde el archivo aún se guarda después de haber sido "eliminado". Esto se debe a que generalmente la eliminación de un archivo de un sistema de archivos simplemente lo marca como eliminado, pero los datos no se tocan. Entonces, es posible inspeccionar los registros de los archivos (como el MFT) y encontrar los archivos eliminados.

Además, el sistema operativo generalmente guarda mucha información sobre los cambios en el sistema de archivos y copias de seguridad, por lo que es posible intentar usarlos para recuperar el archivo o la mayor cantidad de información posible.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Carving de archivos**

**El carving de archivos** es una técnica que intenta **encontrar archivos en la gran cantidad de datos**. Hay 3 formas principales en que herramientas como esta funcionan: **Basado en los encabezados y pies de los tipos de archivos**, basado en las **estructuras** de los tipos de archivos y basado en el **contenido** mismo.

Ten en cuenta que esta técnica **no funciona para recuperar archivos fragmentados**. Si un archivo **no está almacenado en sectores contiguos**, entonces esta técnica no podrá encontrarlo o al menos parte de él.

Hay varias herramientas que puedes usar para el carving de archivos indicando los tipos de archivos que deseas buscar.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Carving de flujo de datos

El carving de flujo de datos es similar al carving de archivos, pero **en lugar de buscar archivos completos, busca fragmentos interesantes** de información.\
Por ejemplo, en lugar de buscar un archivo completo que contenga URLs registradas, esta técnica buscará URLs.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Eliminación segura

Obviamente, hay formas de **"eliminar de forma segura" archivos y parte de los registros sobre ellos**. Por ejemplo, es posible **sobrescribir el contenido** de un archivo con datos basura varias veces, y luego **eliminar** los **registros** del **$MFT** y **$LOGFILE** sobre el archivo, y **eliminar las copias de sombra del volumen**.\
Puedes notar que incluso al realizar esa acción puede haber **otras partes donde la existencia del archivo aún está registrada**, y eso es cierto y parte del trabajo del profesional forense es encontrarlas.

## Referencias

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certificado en Forense Digital Windows**

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
