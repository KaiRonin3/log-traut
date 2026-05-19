import re
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class BaseParser(ABC):

    def __init__(self, source_name: str):
        self.source_name = source_name

    @abstractmethod
    def parse(self, line: str)-> Optional[Dict[str, Any]]:
        pass
    def extract_timestamp(self, line: str) -> str:
        from datetime import datetime
        return datetime.now().isoformat()