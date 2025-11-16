"""Custom JSON encoder to handle datetime serialization."""
from datetime import datetime, date
import json

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime objects."""
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)

def json_dumps(obj, **kwargs):
    """Dump object to JSON string with datetime support."""
    return json.dumps(obj, cls=DateTimeEncoder, **kwargs)

def json_loads(json_str):
    """Load JSON string to Python object."""
    return json.loads(json_str)
