"""toolprint - what your agent's tool surface costs, and what it can do.

Footprint: the tokens tool definitions consume on every request. Fingerprint:
what those definitions are, and whether they changed without review.
"""

# The public name is spelled here and in cli.py's argparse prog only, which is
# what made the rename from the mcpdrift placeholder a two-line change.
TOOL_NAME = "toolprint"
__version__ = "0.2.3"
