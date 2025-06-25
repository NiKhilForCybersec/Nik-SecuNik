# backend/rules/__init__.py


"""
Rules Module - Detection rule management system
Provides comprehensive rule management for YARA, Sigma, and custom rules
"""

from .rule_manager import (
    Rule,
    RuleManager,
    initialize_rule_manager
)

from .rule_validator import (
    ValidationResult,
    RuleValidator
)

from .rule_importer import (
    ImportResult,
    RuleImporter,
    import_rules,
    validate_import_file
)

from .custom_rule_engine import (
    RuleOperator,
    RuleCondition,
    RuleAction,
    CustomRule,
    CustomRuleEngine,
    create_example_rule
)

__all__ = [
    # Rule Manager
    'Rule',
    'RuleManager',
    'initialize_rule_manager',
    
    # Rule Validator
    'ValidationResult',
    'RuleValidator',
    
    # Rule Importer
    'ImportResult',
    'RuleImporter',
    'import_rules',
    'validate_import_file',
    
    # Custom Rule Engine
    'RuleOperator',
    'RuleCondition', 
    'RuleAction',
    'CustomRule',
    'CustomRuleEngine',
    'create_example_rule'
]

# Module version
__version__ = '1.0.0'
