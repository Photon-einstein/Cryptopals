To run clang-format locally:

```bash
clang-format -i <file 1> ...
```

To run the static code analysis locally:

```bash
bash local_static_analysis.sh
```

To generate an uml class diagram:

```bash
plantuml <class_diagram_name>.puml
```

To generate an uml diagram with a .svg format as output:

1. Find the location of the vscode extension of the plant uml, from the root directory.

```bash
find . -name plantuml.jar
```

In my personal computer as an example:
```bash
/home/tiago-sousa/.vscode/extensions/jebbs.plantuml-2.18.1/plantuml.jar
```

2. To generate a .svg file format, run from the 'uml_diagram' folder the following command:

```bash
java -jar /home/tiago-sousa/.vscode/extensions/jebbs.plantuml-2.18.1/plantuml.jar -tsvg <uml_diagram_name>.puml
```

To run the unit tests with valgrind:

```bash
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./run_tests
```

