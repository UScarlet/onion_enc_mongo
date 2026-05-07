ENABLE_DEMO_REWRITE = True
DEMO_REWRITE_FIELD = "name"
DEMO_REWRITE_FROM = "proxy_check"
DEMO_REWRITE_TO = "proxy_check_modified"

# Режимы:
# "verbose"  - подробное логирование из inspector.py
# "summary"  - короткое и понятное логирование из logger_inspector.py
INSPECTOR_MODE = "summary"