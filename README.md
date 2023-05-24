# Scappy-Website

### Funktion

Unsere Website funktioniert mithilfe von einer Python Library namens Flask.
Diese Library fungiert als unsere Kommunikationsschnittstelle zwischen Anwender und Scapy Skript.
Der Anwender kann eine Wireshark Datei einlesen (d.h. *.pcap oder *.pcapng).
Folgend wähl er eines unsere Analyse Tools aus und klickt auf Upload.
Nun wird die Wiresharkdatei im Hintergrund Analysiert und nach einer kurzen Wartezeit bekommt der Anwender seine Ausgewählte Analyse Grafisch dargestellt.

### Flask

Flask ist ein schlankes Webframework zum Programmieren von Webanwendungen mit Python. Es wurde von dem österreichischen Open-Source-Entwickler Armin Ronacher entworfen. Das Framework ist als Bibliothek für Python installierbar und verfolgt einen minimalistischen Ansatz. Es benötigt das WSGI-Toolkit „Werkzeug“ und die Template-Engine „Jinja“. Die Software steht unter BSD-Lizenz und ist frei verfügbar.

### Scapy

Scapy ist eine mächtige Python-Bibliothek, die zum Erstellen, Manipulieren und Übertragen von Netzwerkpaketen verwendet wird. Sie ermöglicht umfangreiche Netzwerkanalyse und -überwachung und unterstützt eine Vielzahl von Protokollen. Mit Scapy können Entwickler komplexe Netzwerkaktivitäten wie Scanning, Tracerouting, Angriffe und Netzwerktests programmatisch ausführen und steuern.

## Herangehensweise

### Venv

Wir haben uns dazu entschieden ein Virtuelles Environment (venv) zu erstellen.
Dies ist eine Möglickeit Python Interpreter für ein spezielles Projekt zu bauen, in diesem befinden sich dann alle benötigten Libraries. Das ist nötig, damit wenn man sich das Projekt über Git herunterlädt jedes Python Skript funktioniert.
Das Venv muss bei jedem Neu-Start des Systems gestartet werden.
Dabei ist es wichtig zu wissen, dass ein Venv das auf Windows erstellt wurde nicht auf Linux bzw. MacOS funktioniert da wichtige Binarys nicht vorhanden oder verändert vorliegen. Das gleiche gilt für die andere Richtung.

### GIT

Git ist ein Kollaborations Tool welches mehreren Enticklern ermöglicht an verschiedenen Teilen und verschieden Zeitpunkten an dem Projekt zu arbeiten.

Git erstellt für jedes Projekt einen **main** Branch. Dieser ist das Hauptprojekt und verläuft immer als Primäre Zeitlinie mit. Aus diesem **main** Branch kann man dann weitere Branches abzweigen um bsp. an verschiedenen Funktionen weiterzuarbeiten ohne andere Entwickler bei Ihrer Arbeit zu stören.

Um immer aktuell zu sein **Fetcht** man bevor man zu arbeiten beginnt sein **Repository**, sprich man lässt die Ordner Struktur Online nachschauen ob es veränderungen gibt.

Wenn man nun gearbeitet hat und seinen Fortschritt zwischenspeichern möchte, ähnlich wie bei einem Spiel macht man ein **Commit**. Dieser stellt einen Punkt auf dem Zeitstrahl an. Dieser wird aber *NICHT*  mit dem Online Repo synchronisiert.

Erst wenn man nun einen **Push** Befehl sendet wir der Zwischenspeicher geleert und alles Online im Git Repo gespeichert.

Wenn die Entwicklung einer Funktion **(Branch)** fertiggsetellt ist, kann man entweder verschiedene **Branches** oder einen **Branch** mit der **Main** verbinden. Dies nennt man **Merge**. Dabei werden dann alle Dateien miteinander verglichen und dann ohne Redundanz zusammengeführt.

Wir Empfehlen dabei Git Hub als auch die Desktopanwendung Git Hub Desktop zu verwenden.
Dies macht all dies deutlich einfacher und hilft dabei das ganze schnell und einfach zu erlernen.

### Unsere Scapy Skripts

### Flask

### HTML/CSS
