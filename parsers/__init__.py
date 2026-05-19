from typing import Optional, Dict, Any
from .ssh_parser import SSHParser
from .kernel_parser import KernelParser
from .auditd_parser import AuditdParser

class ParserRouter:
    def __init__(self):
        self.parsers = {
            "ssh": SSHParser(),
            "kernel": KernelParser(),
            "auditd": AuditdParser(),
            # Add more here
        }
    
    def parse(self, source: str, line: str) -> Optional[Dict[str, Any]]:
        """Route line to appropriate parser."""
        parser = self.parsers.get(source)
        if not parser:
            return None
        return parser.parse(line)
    
    def cleanup(self):
        """Call cleanup on stateful parsers."""
        for parser in self.parsers.values():
            if hasattr(parser, 'cleanup'):
                parser.cleanup()

# Convenience function
router = ParserRouter()

def parse_line(source: str, line: str) -> Optional[Dict[str, Any]]:
    return router.parse(source, line)