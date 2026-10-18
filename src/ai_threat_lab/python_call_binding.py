"""Bind a restricted local Python call using AST/value descriptors, never evaluation."""

import ast

MAX_PARAMETERS = 32


def bind_arguments(function, call, arguments, keywords, empty):
    """Return parameter descriptors or None for unsupported/invalid binding syntax."""
    signature = function.args
    positional = [*signature.posonlyargs, *signature.args]
    parameters = [*positional, *signature.kwonlyargs]
    defaults = [*signature.defaults, *(d for d in signature.kw_defaults if d is not None)]
    if (
        not isinstance(function, ast.FunctionDef)
        or function.decorator_list
        or signature.vararg
        or signature.kwarg
        or len(parameters) > MAX_PARAMETERS
        or len({parameter.arg for parameter in parameters}) != len(parameters)
        or any(not isinstance(default, ast.Constant) for default in defaults)
        or any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in ast.walk(function))
        or any(isinstance(arg, ast.Starred) for arg in call.args)
        or any(keyword.arg is None for keyword in call.keywords)
        or len({keyword.arg for keyword in call.keywords}) != len(call.keywords)
        or len(arguments) > len(positional)
    ):
        return None
    bound = {parameter.arg: value for parameter, value in zip(positional, arguments)}
    allowed = {parameter.arg for parameter in [*signature.args, *signature.kwonlyargs]}
    for name, value in keywords.items():
        if name not in allowed or name in bound:
            return None
        bound[name] = value
    first_default = len(positional) - len(signature.defaults)
    for index, parameter in enumerate(positional):
        if parameter.arg not in bound:
            if index < first_default:
                return None
            bound[parameter.arg] = empty
    for parameter, default in zip(signature.kwonlyargs, signature.kw_defaults, strict=True):
        if parameter.arg not in bound:
            if default is None:
                return None
            bound[parameter.arg] = empty
    return bound
