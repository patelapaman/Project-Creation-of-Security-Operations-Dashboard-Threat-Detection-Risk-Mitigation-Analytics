"""Service package.

Milestone 3 keeps this initializer lightweight so individual services can be
imported without eagerly initializing the database stack.
"""
_EXPORTS = {
    "run_pipeline": (".pipeline_service", "run_pipeline"),
    "run_enrichment": (".enrichment_service", "run_enrichment"),
    "run_mitre_mapping": (".mitre_service", "run_mitre_mapping"),
    "get_dashboard_analytics": (".analytics_service", "get_dashboard_analytics"),
    "run_feature_engineering": (".feature_service", "run_feature_engineering"),
}
__all__ = list(_EXPORTS)

def __getattr__(name):
    if name in _EXPORTS:
        import importlib
        module, attr = _EXPORTS[name]
        value=getattr(importlib.import_module(module, __name__), attr)
        globals()[name]=value
        return value
    raise AttributeError(name)
