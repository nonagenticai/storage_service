"""
Constraint types for string validation in Pydantic models.
"""

from typing import Annotated

from pydantic import Field

SAFE_STRING_PATTERN = r"^[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*$"

SafeString = Annotated[str, Field(pattern=SAFE_STRING_PATTERN)]
SafeStringShort = Annotated[str, Field(min_length=1, max_length=256, pattern=SAFE_STRING_PATTERN)]
SafeStringMedium = Annotated[str, Field(min_length=1, max_length=1000, pattern=SAFE_STRING_PATTERN)]
SafeStringLong = Annotated[str, Field(min_length=1, max_length=10000, pattern=SAFE_STRING_PATTERN)]
SafeCodeString = Annotated[str, Field(max_length=50000, pattern=SAFE_STRING_PATTERN)]
