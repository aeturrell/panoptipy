import ast
import importlib.resources

def extract_check_info_from_code(code: str) -> list[dict[str, str]]:
    """
    Parses Python code using AST and extracts check_id and description
    from super().__init__() calls within __init__ methods.

    Args:
        code: A string containing the Python source code.

    Returns:
        A list of dictionaries, each containing a 'check_id' and 'description'.
    """
    check_info_list = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        print(f"Error parsing code: {e}")
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == '__init__':
                if isinstance(node.func.value, ast.Call):
                    if isinstance(node.func.value.func, ast.Name) and node.func.value.func.id == 'super':
                        check_id = None
                        description = None
                        for keyword in node.keywords:
                            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                                if keyword.arg == 'check_id':
                                    check_id = keyword.value.value
                                elif keyword.arg == 'description':
                                    description = keyword.value.value
                            elif hasattr(ast, 'Str') and isinstance(keyword.value, ast.Str):
                                if keyword.arg == 'check_id':
                                    check_id = keyword.value.s
                                elif keyword.arg == 'description':
                                    description = keyword.value.s
                        if check_id is not None and description is not None:
                            check_info_list.append({
                                'check_id': check_id,
                                'description': description
                            })
    return check_info_list


def get_check_id_and_description_pairs() -> list[dict[str, str]]:
    """
    Reads the checks.py file and extracts check_id and description pairs.

    Returns:
        A list of dictionaries, each containing a 'check_id' and 'description'.
    """
    try:
        with importlib.resources.files(__package__).joinpath("checks.py").open("r", encoding="utf-8") as f:
            code = f.read()
            return extract_check_info_from_code(code)
    except Exception as e:
        print(f"Failed to read checks.py: {e}")
        return []
