# server/ -- SHELLHOUND web-native rewrite.
#
# FastAPI backend serving the React SPA (web/dist) and a JSON API. The five
# features -- Findings, Actors, IOC Box, CMS Inventory, Database -- are views
# over per-case SQLite databases that the engines fill exactly once per piece
# of evidence. Traces and searches are queries against that index, never a
# second pass over the log files.
