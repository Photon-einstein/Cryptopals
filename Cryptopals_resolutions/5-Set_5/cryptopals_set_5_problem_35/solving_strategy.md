1.  Ports of the servers running in this program (Done)
    Port of Mallory 18080 (production)
    Port of Mallory 18081 (test)

    Port of Server 18082 (production)
    Port of Server 18083 (test)

2.  Add Mallory server code as a copy of the real server, adapting the port numbers (Done)
    2.1.1. Test root endpoint of Mallory server (Done)
    Endpoint URL:
    On the browser:

    ````bash
    http://localhost:18080/

            ```

    2.1.2. Test sessionsData endpoint of Mallory server (Done)
    Endpoint URL:
    On the browser:
    `bash
        http://localhost:18080/sessionsData
        `

    2.2.1. Test root endpoint of real server (Done)
    Endpoint URL:
    On the browser:
    `bash
        http://localhost:18082/
        `

    2.2.2. Test sessionsData endpoint of Mallory server (Done)
    Endpoint URL:
    On the browser:
    `bash
        http://localhost:18082/sessionsData
        `
    ````

3.  Create UML sequence diagram with a .svg output (Done)

    - To generate the sequence diagram in .svg format, run this command at the 'uml_diagrams' folder:

    ```bash
    java -jar /home/tiago-sousa/.vscode/extensions/jebbs.plantuml-2.18.1/plantuml.jar -tsvg sequence_diagram.puml
    ```

4.  Regenerate base uml diagrams with names updated (Done)
