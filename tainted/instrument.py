import argparse
import ast
import os

import astor


class TaintInstrumentor(ast.NodeTransformer):
    def __init__(self):
        super().__init__()
        self.imports = set()

    @staticmethod
    def create_taintable_object(node, is_tainted=False) -> ast.Call:
        node = ast.Call(func=ast.Name("_make_taintable"), args=[node], keywords=[])
        if is_tainted:
            node.args.append(ast.Constant(value=is_tainted))
        return node

    @staticmethod
    def create_function_sink(node) -> ast.Call:
        return ast.Call(
            func=ast.Name("_function_sink"),
            args=[node.func, *node.args],
            keywords=node.keywords,
        )

    # def visit_Constant(self, node):
    #     return self.create_taintable_object(node)

    # Formatted f-strings do not propagate taint
    # def visit_FormattedValue(self, node):
    #     node = self.create_taintable_object(node)
    #     return node

    # def visit_JoinedStr(self, node):
    # return self.create_taintable_object(node)

    # def visit_List(self, node):
    # node = self.generic_visit(node)
    # return self.create_taintable_object(node)

    # def visit_Tuple(self, node):
    #     node = self.generic_visit(node)
    #     return self.create_taintable_object(node)

    # def visit_Set(self, node):
    #     node = self.generic_visit(node)
    #     return self.create_taintable_object(node)

    # def visit_Dict(self, node):
    #     node = self.generic_visit(node)
    #     return self.create_taintable_object(node)

    def visit_Assign(self, node):
        # If we are assigning a taint sink, we first need to intercept the call
        # and then assign the result to the variable
        if node.type_comment == "taint[sink]" and isinstance(node.value, ast.Call):
            new_block = self.create_function_sink(node.value)
            node = ast.Assign(targets=node.targets, value=new_block)
            return node

        node = self.generic_visit(node)

        # Otherwise, we just need to create a taint object and mark it according to
        # the type comment, if available

        type_comment_to_fn = {
            "taint[source]": "_taint",
            "taint[sink]": "_raise_if_tainted",
            "taint[sanitized]": "_untaint",
        }

        if node.type_comment in type_comment_to_fn:
            fn_name = type_comment_to_fn[node.type_comment]
            return ast.Assign(
                targets=node.targets,  # type: ignore
                value=ast.Call(func=ast.Name(fn_name), args=[node.value], keywords=[]),  # type: ignore
            )

        return node

    # Expressions
    def visit_Call(self, node):
        # Patch the dummy function to intercept the call
        if hasattr(node.func, "id") and node.func.id in {"taint_sink"}:  # type: ignore
            return self.create_function_sink(node.args[0])
        node = self.generic_visit(node)
        return node


def instrument_code(src: str) -> str:
    tree = ast.parse(src, mode="exec", type_comments=True)
    instr = TaintInstrumentor()
    rewrite_tree = instr.visit(tree)
    runtime_import = ast.ImportFrom(
        module="tainted",
        names=[
            ast.alias(name="*", asname=None),
        ],
        level=0,
    )
    final_tree = ast.Module(body=[runtime_import, *rewrite_tree.body], type_ignores=[])
    return astor.to_source(final_tree)


def instrument_file(path: str, output: str):
    with open(path, "r") as r:
        src = r.read()
        instrumented_src = instrument_code(src)

    if not output:
        print(instrumented_src)
    else:
        with open(output, "w") as w:
            w.write(instrumented_src)


def main(args) -> None:
    if os.path.isfile(args.path):
        return instrument_file(args.path, args.output)

    os.makedirs(args.output, exist_ok=True)

    for root, _, files in os.walk(args.path):
        if any(i in root for i in args.ignore):
            continue

        for f in files:
            if f in args.ignore:
                continue
            if f.endswith(".py"):
                instrument_file(os.path.join(root, f), os.path.join(args.output, f))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Instrument a Python file or directory to track taint"
    )
    parser.add_argument("path", help="Path to the file or directory to instrument")
    parser.add_argument(
        "--output",
        "-o",
        help="Output path for the instrumented file or directory, otherwise the instrumented file will be printed to stdout",
    )
    parser.add_argument(
        "--ignore",
        "-i",
        nargs="*",
        help="List of files or directories to ignore when instrumenting a directory",
        default=[],
    )

    args = parser.parse_args()
    main(args)
