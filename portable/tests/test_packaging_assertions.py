import os
import ast

def test_launcher_imports_entry_point():
    launcher_path = os.path.join(os.path.dirname(__file__), "..", "launcher.py")
    with open(launcher_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename="launcher.py")
    
    # Assert imports cybersage_portable.__main__.main
    imports_main = any(
        isinstance(node, ast.ImportFrom) and node.module == "cybersage_portable.__main__" and any(n.name == "main" for n in node.names)
        for node in tree.body
    )
    assert imports_main, "launcher.py must import main from cybersage_portable.__main__"
    
    # Assert it checks __name__ == "__main__"
    has_main_check = any(
        isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
        isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"
        for node in tree.body
    )
    assert has_main_check, "launcher.py must not execute on ordinary import"

def test_workflow_packaging_arguments():
    workflow_path = os.path.join(os.path.dirname(__file__), "..", "..", ".github", "workflows", "portable-build.yml")
    with open(workflow_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "launcher.py" in content, "Workflow must build launcher.py"
    assert "cybersage_portable/__main__.py" not in content, "Obsolete direct PyInstaller target must be absent"
    assert "--privacy-mode minimal" in content, "Workflow must use --privacy-mode minimal"
    assert "--output smoke-output" in content, "Workflow must treat --output as a directory named smoke-output"
    assert "portable/requirements.txt" not in content, "Workflow must not reference portable/requirements.txt"

def test_pyproject_build_backend_is_correct():
    pyproject_path = os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")
    with open(pyproject_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "setuptools.build_meta" in content, "build-backend must be setuptools.build_meta"
    assert "setuptools.backends.legacy" not in content, "setuptools.backends.legacy is invalid and must be absent"
