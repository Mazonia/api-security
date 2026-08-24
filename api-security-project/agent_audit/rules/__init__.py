"""Agent Audit Rules Suite."""
from .excessive_agency import ExcessiveAgencyRule
from .authz_gaps import AuthorizationGapsRule
from .tool_injection import ToolInjectionRule
from .rag_security import RagSecurityRule
from .provider_keys import ProviderKeysRule
from .iot_actuation import IoTActuationRule

ALL_AGENT_RULES = [
    ExcessiveAgencyRule(),
    AuthorizationGapsRule(),
    ToolInjectionRule(),
    RagSecurityRule(),
    ProviderKeysRule(),
    IoTActuationRule(),
]
