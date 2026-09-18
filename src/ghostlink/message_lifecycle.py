"""Shared GhostLink message lifecycle policy constants.

These values are protocol-policy inputs used by both historical local v2 codec code
and the current ratcheted v3 runtime. Keeping them outside either message codec
prevents the current runtime from depending on retired protocol-v2 implementation.
"""

MESSAGE_ID_BYTES = 16
MESSAGE_DEFAULT_TTL_SECONDS = 24 * 60 * 60
MESSAGE_MAX_LIFETIME_SECONDS = 7 * 24 * 60 * 60
MESSAGE_CLOCK_SKEW_SECONDS = 5 * 60
