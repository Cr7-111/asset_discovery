# 文件作用：后端应用包初始化文件，并兼容旧版 app 导入路径。
"""Backend application package.

Also provide lazy compatibility exports so older imports like
``from app import create_app`` still work even if Python resolves ``app`` to
this package first.
"""


def __getattr__(name: str):
    # 兼容旧代码中的 from app import create_app 等写法，实际对象延迟转发到 backend.run。
    if name in {"app", "create_app", "initialize_application", "logger"}:
        from backend import run as _run

        return getattr(_run, name)
    # 其他不存在的属性仍按标准 Python 包行为抛出 AttributeError。
    raise AttributeError(name)
