# Das Modbus-Protokoll

## Einführung in das Modbus-Protokoll

Das Modbus-Protokoll ist ein weit verbreitetes Protokoll in der industriellen Automatisierung und Steuerungssystemen. Modbus ermöglicht die Kommunikation zwischen verschiedenen Geräten wie programmierbaren Logikcontrollern (PLCs), Sensoren, Aktuatoren und anderen industriellen Geräten. Das Verständnis des Modbus-Protokolls ist entscheidend, da dies das am häufigsten verwendete Kommunikationsprotokoll in der ICS ist und ein großes Potenzial für Angriffe bietet, um Befehle in PLCs einzuschleusen.

Hier werden Konzepte punktweise dargelegt, um den Kontext des Protokolls und seine Betriebsweise zu vermitteln. Die größte Herausforderung in der Sicherheit von ICS-Systemen ist der Implementierungs- und Aktualisierungsaufwand. Diese Protokolle und Standards wurden in den frühen 80er und 90er Jahren entworfen und werden immer noch weit verbreitet eingesetzt. Da eine Branche viele Geräte und Verbindungen hat, ist es sehr schwierig, Geräte zu aktualisieren, was Hackern einen Vorteil verschafft, da sie veraltete Protokolle verwenden können. Angriffe auf Modbus sind praktisch unvermeidlich, da es ohne Aktualisierung verwendet wird und sein Betrieb für die Branche entscheidend ist.

## Die Client-Server-Architektur

Das Modbus-Protokoll wird typischerweise in einer Client-Server-Architektur verwendet, bei der ein Master-Gerät (Client) die Kommunikation mit einem oder mehreren Slave-Geräten (Servern) initiiert. Dies wird auch als Master-Slave-Architektur bezeichnet, die in der Elektronik und im IoT mit SPI, I2C usw. weit verbreitet ist.

## Serielle und Ethernet-Versionen

Das Modbus-Protokoll ist sowohl für die serielle Kommunikation als auch für die Ethernet-Kommunikation ausgelegt. Die serielle Kommunikation wird in Legacy-Systemen weit verbreitet eingesetzt, während moderne Geräte Ethernet unterstützen, das hohe Datenraten bietet und für moderne industrielle Netzwerke besser geeignet ist.

## Datenrepräsentation

Daten werden im Modbus-Protokoll als ASCII oder Binär übertragen, obwohl das binäre Format aufgrund seiner Kompatibilität mit älteren Geräten verwendet wird.

## Funktionscodes

Das ModBus-Protokoll arbeitet mit der Übertragung spezifischer Funktionscodes, die zur Steuerung der PLCs und verschiedener Steuergeräte verwendet werden. Dieser Teil ist wichtig zu verstehen, da Replay-Angriffe durch erneutes Senden von Funktionscodes durchgeführt werden können. Legacy-Geräte unterstützen keine Verschlüsselung für die Datenübertragung und haben in der Regel lange Kabel, die sie verbinden, was dazu führt, dass diese Kabel manipuliert und Daten abgefangen/eingeschleust werden können.

## Adressierung von Modbus

Jedes Gerät im Netzwerk hat eine eindeutige Adresse, die für die Kommunikation zwischen den Geräten unerlässlich ist. Protokolle wie Modbus RTU, Modbus TCP usw. werden verwendet, um die Adressierung zu implementieren und dienen als Transportschicht für die Datenübertragung. Die übertragene Daten sind im Modbus-Protokollformat enthalten, das die Nachricht enthält.

Darüber hinaus implementiert Modbus auch Fehlerprüfungen, um die Integrität der übertragenen Daten sicherzustellen. Aber vor allem ist Modbus ein offener Standard, den jeder in seinen Geräten implementieren kann. Dies hat dazu geführt, dass dieses Protokoll zu einem globalen Standard geworden ist und in der industriellen Automatisierungsbranche weit verbreitet ist.

Aufgrund seines weit verbreiteten Einsatzes und des Mangels an Aktualisierungen bietet das Angreifen von Modbus einen erheblichen Vorteil mit seiner Angriffsfläche. ICS ist stark von der Kommunikation zwischen Geräten abhängig, und Angriffe darauf können gefährlich für den Betrieb der industriellen Systeme sein. Angriffe wie Replay, Dateninjektion, Datensniffing und -lecks, Denial of Service, Datenfälschung usw. können durchgeführt werden, wenn das Übertragungsmedium vom Angreifer identifiziert wird.
