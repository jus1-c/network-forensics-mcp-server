"""Input validation utilities."""

import os
from pathlib import Path
from typing import Optional

from ..config import config
from ..exceptions import InvalidFileError, SecurityError, ValidationError


def validate_file_path(file_path: str, must_exist: bool = True) -> Path:
    """Validate file path for security.
    
    Args:
        file_path: Path to validate
        must_exist: Whether file must exist
        
    Returns:
        Validated Path object
        
    Raises:
        ValidationError: If path is invalid
        SecurityError: If path contains security issues
    """
    if not file_path:
        raise ValidationError("File path cannot be empty")
    
    # Convert to Path object
    path = Path(file_path)
    
    # Check for path traversal
    try:
        resolved = path.resolve()
    except (OSError, ValueError) as e:
        raise SecurityError(f"Invalid file path: {e}")
    
    # Check if path is absolute
    if not path.is_absolute():
        raise SecurityError("File path must be absolute")
    
    # Check file extension
    if path.suffix.lower() not in config.allowed_extensions:
        raise InvalidFileError(
            f"File must be one of: {', '.join(config.allowed_extensions)}"
        )
    
    if must_exist:
        if not path.exists():
            raise ValidationError(f"File not found: {file_path}")
        
        if not path.is_file():
            raise ValidationError(f"Path is not a file: {file_path}")
        
        # Check file size
        file_size = path.stat().st_size
        if file_size > config.max_file_size:
            raise ValidationError(
                f"File too large: {file_size} bytes (max: {config.max_file_size})"
            )
    
    return resolved


def validate_packet_limit(limit: Optional[int], default: Optional[int] = None) -> int:
    """Validate packet limit.
    
    Args:
        limit: Requested limit
        default: Default value if limit is None
        
    Returns:
        Validated limit
    """
    if limit is None:
        return default or config.default_packet_limit
    
    if not isinstance(limit, int) or limit < 0:
        raise ValidationError("Packet limit must be a positive integer")
    
    if limit > config.max_packets_per_request:
        raise ValidationError(
            f"Packet limit exceeds maximum: {config.max_packets_per_request}"
        )
    
    return limit


def validate_display_filter(filter_str: Optional[str]) -> Optional[str]:
    """Validate Wireshark display filter.
    
    Args:
        filter_str: Display filter string
        
    Returns:
        Validated filter string or None
    """
    if filter_str is None:
        return None
    
    if not isinstance(filter_str, str):
        raise ValidationError("Display filter must be a string")
    
    # Basic security checks
    if len(filter_str) > 1000:
        raise ValidationError("Display filter too long (max 1000 characters)")
    
    # Check for shell injection attempts
    dangerous_chars = [';', '&', '|', '`', '$', '>', '<']
    if any(c in filter_str for c in dangerous_chars):
        raise SecurityError("Display filter contains dangerous characters")
    
    return filter_str.strip()


def validate_packet_index(index: int, max_index: int) -> int:
    """Validate packet index.
    
    Args:
        index: Requested index
        max_index: Maximum valid index
        
    Returns:
        Validated index
    """
    if not isinstance(index, int):
        raise ValidationError("Packet index must be an integer")
    
    if index < 0 or index >= max_index:
        raise ValidationError(
            f"Packet index {index} out of range (0-{max_index-1})"
        )
    
    return index


def sanitize_output_path(output_path: str, allowed_dirs: Optional[list] = None) -> Path:
    """Sanitize output path.
    
    Args:
        output_path: Output path
        allowed_dirs: List of allowed directories
        
    Returns:
        Sanitized Path object
    """
    path = Path(output_path)
    
    # Ensure absolute path
    if not path.is_absolute():
        raise SecurityError("Output path must be absolute")
    
    # Check allowed directories if specified
    if allowed_dirs:
        resolved = path.resolve()
        for allowed in allowed_dirs:
            if str(resolved).startswith(str(Path(allowed).resolve())):
                return resolved
        raise SecurityError("Output path not in allowed directories")
    
    return path
