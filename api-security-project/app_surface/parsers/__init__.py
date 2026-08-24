"""Framework route parsers for static API surface mapping."""
from .python_parser import PythonRouteParser
from .node_parser import NodeRouteParser
from .java_parser import JavaRouteParser
from .dotnet_parser import DotnetRouteParser
from .go_parser import GoRouteParser
from .php_parser import PhpRouteParser
from .cpp_parser import CppRouteParser

ALL_PARSERS = [
    PythonRouteParser(),
    NodeRouteParser(),
    JavaRouteParser(),
    DotnetRouteParser(),
    GoRouteParser(),
    PhpRouteParser(),
    CppRouteParser(),
]
