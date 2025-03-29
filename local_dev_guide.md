To run clang-format locally:

```bash
clang-format -i <file 1> ...
```

To run the static code analysis locally:

```bash
bash local_static_analysis.sh
```

To generate a uml class diagram:

```bash
plantuml <class_diagram_name>.puml
```

To run the unit tests with valgrind:

```bash
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./run_tests
```
