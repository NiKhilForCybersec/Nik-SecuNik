"""
Parser Factory
Selects and instantiates the appropriate parser based on file type
"""

import logging
from typing import Dict, Type, Optional, Any, Union
from pathlib import Path
import importlib
import pkgutil

from parsers.base_parser import BaseParser
from core.file_identifier import FileIdentifier

logger = logging.getLogger(__name__)


class ParserFactory:
    """Factory class for creating parser instances"""
    
    # Parser registry mapping parser names to parser classes
    _parsers: Dict[str, Type[BaseParser]] = {}
    
    # File extension to parser mapping
    _extension_map: Dict[str, str] = {}
    
    @classmethod
    def register_parser(cls, parser_name: str, parser_class: Type[BaseParser]) -> None:
        """
        Register a parser class
        
        Args:
            parser_name: Name of the parser
            parser_class: Parser class (must inherit from BaseParser)
        """
        if not issubclass(parser_class, BaseParser):
            raise ValueError(f"Parser {parser_name} must inherit from BaseParser")
            
        cls._parsers[parser_name] = parser_class
        
        # Register supported extensions
        try:
            instance = parser_class(Path("/dummy"))  # Temporary instance to get extensions
            for ext in instance.supported_extensions:
                cls._extension_map[ext] = parser_name
        except:
            pass  # Some parsers might require valid files
            
        logger.info(f"Registered parser: {parser_name}")
    
    @classmethod
    def discover_parsers(cls) -> None:
        """Auto-discover and register all parsers in the parsers package"""
        import backend.parsers as parsers_package
        
        # Get the parsers package path
        package_path = Path(parsers_package.__file__).parent
        
        # Recursively find all modules in the parsers package
        for importer, modname, ispkg in pkgutil.walk_packages(
            path=[str(package_path)],
            prefix="parsers.",
            onerror=lambda x: None
        ):
            if modname.endswith('__init__'):
                continue
                
            try:
                # Import the module
                module = importlib.import_module(modname)
                
                # Find all parser classes in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    
                    # Check if it's a parser class
                    if (isinstance(attr, type) and 
                        issubclass(attr, BaseParser) and 
                        attr is not BaseParser):
                        
                        # Get parser name from the class
                        try:
                            instance = attr(Path("/dummy"))
                            parser_name = instance.parser_name
                            cls.register_parser(parser_name, attr)
                        except:
                            # Try to get parser name from class attribute
                            if hasattr(attr, 'parser_name'):
                                parser_name = attr.parser_name
                                cls.register_parser(parser_name, attr)
                                
            except Exception as e:
                logger.warning(f"Failed to import parser module {modname}: {str(e)}")
    
    @classmethod
    def get_parser(
        cls, 
        file_path: Union[str, Path], 
        parser_name: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> BaseParser:
        """
        Get appropriate parser instance for a file
        
        Args:
            file_path: Path to the file to parse
            parser_name: Optional specific parser to use
            config: Optional parser configuration
            
        Returns:
            Parser instance
            
        Raises:
            ValueError: If no suitable parser found
        """
        file_path = Path(file_path)
        
        # Auto-discover parsers if registry is empty
        if not cls._parsers:
            cls.discover_parsers()
        
        # If specific parser requested, use it
        if parser_name:
            if parser_name not in cls._parsers:
                raise ValueError(f"Unknown parser: {parser_name}")
            return cls._parsers[parser_name](file_path, config)
        
        # Use FileIdentifier to determine parser
        file_identifier = FileIdentifier()
        identified_parser = file_identifier.identify(str(file_path))
        
        if identified_parser and identified_parser in cls._parsers:
            logger.info(f"Using parser '{identified_parser}' for file: {file_path.name}")
            return cls._parsers[identified_parser](file_path, config)
        
        # Fallback to extension-based selection
        ext = file_path.suffix.lower()
        if ext in cls._extension_map:
            parser_name = cls._extension_map[ext]
            logger.info(f"Using parser '{parser_name}' based on extension for: {file_path.name}")
            return cls._parsers[parser_name](file_path, config)
        
        # Last resort - try generic text parser
        if 'text' in cls._parsers:
            logger.warning(f"No specific parser found, using generic text parser for: {file_path.name}")
            return cls._parsers['text'](file_path, config)
        
        raise ValueError(f"No suitable parser found for file: {file_path.name}")
    
    @classmethod
    def list_parsers(cls) -> Dict[str, Dict[str, Any]]:
        """
        List all available parsers
        
        Returns:
            Dictionary of parser info
        """
        if not cls._parsers:
            cls.discover_parsers()
            
        parser_info = {}
        for name, parser_class in cls._parsers.items():
            try:
                instance = parser_class(Path("/dummy"))
                parser_info[name] = {
                    "class": parser_class.__name__,
                    "module": parser_class.__module__,
                    "extensions": instance.supported_extensions
                }
            except:
                parser_info[name] = {
                    "class": parser_class.__name__,
                    "module": parser_class.__module__,
                    "extensions": []
                }
                
        return parser_info