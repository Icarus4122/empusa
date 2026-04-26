# Empusa Hooks

Drop Python scripts into any event folder below.
Each script must define a `run(context)` function.

## Hook Events

- **on_startup/**
- **on_shutdown/**
- **pre_build/**
- **post_build/**
- **pre_scan_host/**
- **post_scan/**
- **on_loot_add/**
- **on_report_generated/**
- **pre_report_write/**
- **on_env_select/**
- **pre_command/**
- **post_command/**
- **post_compile/**

## Context Dict

Every hook receives a `context` dict with at minimum:
```python
{
    "event": "<event_name>",
    "timestamp": "2026-03-29 19:45:12",
    "session_env": "kobold",
    # ... plus event-specific keys
}
```

## Example

```python
# empusa/hooks/on_loot_add/notify.py
def run(context):
    print(f"[Hook] New loot on {context['host']}: {context['username']}")
```
