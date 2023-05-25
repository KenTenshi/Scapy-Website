# Scapy-Website

### Funktion

Unsere Website funktioniert mit Hilfe einer Python Library namens Flask.

Diese Library fungiert als unsere Kommunikationsschnittstelle zwischen Anwender und Scapy Skript.

Der Anwender kann eine Wireshark Datei einlesen (d.h. *.pcap oder *.pcapng).

Folgend wählt man eines unserer Analysetools aus und klickt auf Upload.

Nun wird die Wiresharkdatei im Hintergrund analysiert und nach einer kurzen Wartezeit bekommt der Anwender seine ausgewählte Analyse grafisch dargestellt.

### Flask

Flask ist ein schlankes Webframework zum Programmieren von Webanwendungen mit Python. Es wurde von dem österreichischen Open-Source-Entwickler Armin Ronacher entworfen. Das Framework ist als Bibliothek für Python installierbar und verfolgt einen minimalistischen Ansatz. Es benötigt das WSGI-Toolkit „Werkzeug“ und die Template-Engine „Jinja“. Die Software steht unter BSD-Lizenz und ist frei verfügbar.

### Scapy

Scapy ist eine mächtige Python-Bibliothek, die zum Erstellen, Manipulieren und Übertragen von Netzwerkpaketen verwendet wird. Sie ermöglicht umfangreiche Netzwerkanalyse und -überwachung und unterstützt eine Vielzahl von Protokollen. Mit Scapy können Entwickler komplexe Netzwerkaktivitäten wie Scanning, Tracerouting, Angriffe und Netzwerktests programmatisch ausführen und steuern.

## Herangehensweise

Wir haben begonnen damit, dass wir entschieden haben ein virtuelles Environment zu nutzen, damit es uns möglich ist, für dieses Projekt sowohl ungebunden an den Standort zu arbeiten, als auch online kooperativ tätig sein zu können. Das virtuelle stellt in diesem Fall sicher, dass wir auf die selbe Basis an Libaries zurück greifen, was im Vorfeld Fehler ausschließt. In dieses virtuelle Environment haben wir dann scapy installiert und um flask ergänzt. Scapy wird wie bereits beschrieben genutzt um die einzulesenden Pakete zu analysieren, flask ist dafür zuständig das Frontend für den User zu liefern in dem er seine Dateien einlesen lassen kann. Um dann online zusammen und gleichzeitig am Projekt weiter arbeiten zu können nutzen wir Github inklusive der zugehörigen Software GibHub Desktop. Dies hat für uns das Konzept von Softwareentwicklung mit Versionskontrolle im Hintergrund nahe gelegt. Zudem ist es uns damit möglich einzelne Funktionen zu entwickeln, die wir dann später in den main branch mergen können, ohne dass wir etwas kaputt coden. Außerdem ist es möglich (sofern man regelmäßg "comitted") falls man das Programm mal "zercoded" hat zu einem früheren Status zurückzukehren und von dort aus wieder weiter zu starten. Danach haben wir die erste Funktion integriert. Sie liefert eine Übersicht über die in der pcap Datei enthaltenen Pakettypen sowie Top5 IP-Adressen, Top5 Quell-Ports und Top5 Ziel-Ports.

Dies war unser erstes Ziel welches wir erreichen wollten. Danach haben wir begonnnen weitere aus unserer Sicht spannende Funktionen zu integrieren. Dazu zählen detailiertere Paketauflistungen, Unterscheidung der DHCP Pakete in Request und Replies, DNS sowie Ping Requests und Replies nach Häufigkeit und Quell-IP). Die Webseite läuft, ließst eingelesene Dateien aus und die Funktionen liefern die gewünschten Ergebnisse.

### Venv

Wir haben uns dazu entschieden ein Virtuelles Environment (venv) zu erstellen.

Dies ist eine Möglichkeit Python Interpreter für ein spezielles Projekt zu bauen, in diesem befinden sich dann alle benötigten Libraries. Das ist nötig, damit wenn man sich das Projekt über Git herunterlädt jedes Python Skript funktioniert.

Das Venv muss bei jedem Neu-Start des Systems gestartet werden.

Dabei ist es wichtig zu wissen, dass ein Venv das auf Windows erstellt, wurde nicht auf Linux bzw. MacOS funktioniert da wichtige Binarys nicht vorhanden oder verändert vorliegen. Das gleiche gilt für die andere Richtung.

### GIT

Git ist ein Kollaborationstool welches mehreren Entwicklern ermöglicht an verschiedenen Teilen und verschieden Zeitpunkten an dem Projekt zu arbeiten.

Git erstellt für jedes Projekt einen **main** Branch. Dieser ist das Hauptprojekt und verläuft immer als Primäre Zeitlinie mit. Aus diesem **main** Branch kann man dann weitere Branches abzweigen um bsp. an verschiedenen Funktionen weiterzuarbeiten ohne andere Entwickler bei Ihrer Arbeit zu stören.

Um immer aktuell zu sein **Fetcht** man bevor man zu arbeiten beginnt sein **Repository**, sprich man lässt die Ordner Struktur Online nachschauen ob es veränderungen gibt.

Wenn man nun gearbeitet hat und seinen Fortschritt zwischenspeichern möchte, ähnlich wie bei einem Spiel macht man ein **Commit**. Dieser stellt einen Punkt auf dem Zeitstrahl an. Dieser wird aber *NICHT*  mit dem Online Repo synchronisiert.

Erst wenn man nun einen **Push** Befehl sendet wir der Zwischenspeicher geleert und alles Online im Git Repo gespeichert.

Wenn die Entwicklung einer Funktion **(Branch)** fertiggsetellt ist, kann man entweder verschiedene **Branches** oder einen **Branch** mit der **Main** verbinden. Dies nennt man **Merge**. Dabei werden dann alle Dateien miteinander verglichen und dann ohne Redundanz zusammengeführt.

Wir Empfehlen dabei Git Hub als auch die Desktopanwendung Git Hub Desktop zu verwenden.

Dies macht all dies deutlich einfacher und hilft dabei das ganze schnell und einfach zu erlernen.

### Unsere Scapy Skripts

1. Top5 Pakettypen
2. IP Statistiken
3. Pakettypen (alle, nicht wie Top5)
4. DNS
5. Ping
6. DHCP

##### Standard

Unser Skript analysiert die eingelesene .pcap Datei und gibt die Top 5. der Pakete aus.

Dies könnte Interessant für die Fehleranalyse sein.

##### Ping Pakete auswerten

### Flask

Flask ist ein Webframework für Python, dass die Entwicklung von Webanwendungen erleichtert. Es bietet Werkzeuge und Funktionen zum Erstellen von Webseiten, Handhaben von Anfragen und Antworten, Verwalten von Benutzersitzungen und vielem mehr.

Wenn man beide Bibliotheken kombiniert, kann man beispielsweise eine Webanwendung entwickeln, die Netzwerkpakete analysiert oder verschiedene Netzwerktools bereitstellt. Man kann eine Benutzeroberfläche mit Flask erstellen, in die der Benutzer PCAP-Dateien hochladen kann. Anschließend man Scapy verwenden, um die hochgeladenen PCAP-Dateien zu analysieren und bestimmte Informationen daraus zu extrahieren. Diese Informationen können dann in der Flask-Anwendung angezeigt oder weiterverarbeitet werden.

### HTML/CSS

CSS steht für "Cascading Style Sheets" wird verwendet, um das Aussehen von Webseiten zu gestalten.

Mit CSS können Sie Dinge wie Farben, Schriftarten, Abstände und Hintergrundbilder für Ihre Webseite festlegen. Es ermöglicht Ihnen auch, das Layout Ihrer Seite anzupassen, indem Sie Elemente positionieren und anordnen.

Dank CSS ist es Möglich, das Aussehen einer Webseite an verschiedene Geräte anzupassen (Auflösung skalieren wie z.B. mit Vektorgraphen). Mit sogenannten Medienabfragen können Sie festlegen, wie Ihre Webseite auf Mobilgeräten oder Bildschirmen unterschiedlicher Größe angezeigt wird.

### Was könnte man in Zukunft machen wenn man daran weiter arbeitet?

Zukünftig planen wir den Service Online verfügbar zu machen.
Dieser muss dann auf einem gemieteten Rootserver z.B. bei Hetzner laufen.
Außerdem planen wir weitere Funktionen zu implementieren als auch an den bestehenden Funktionen weiter zu arbeiten.
Beispielsweise könnte man Grafiken hinzufügen um  die visualisierung zu verbessern.
Ein Netzwerkscanner Tool was direkt darüber läuft, wäre ebenfalls eine sinnvolle Ergänzung.
