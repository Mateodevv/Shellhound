# server/engines/ -- the analysis engines, as plain library code.
#
# No argparse, no subprocess dispatch, no report files: each engine takes a
# JobContext (progress + cancellation) and writes structured results straight
# into the case databases. The detection logic is ported from the legacy
# modules and deliberately kept rule-for-rule identical -- it was tuned on
# real cases, and this rewrite changes the shell, not the dog's nose.
