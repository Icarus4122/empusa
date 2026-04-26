# Empusa Plugins

Each subdirectory is a plugin.  Minimum structure:

```
my_plugin/
├-- manifest.json   (required)
├-- config.json     (optional)
└-- plugin.py       (required - defines activate/deactivate)
```

## manifest.json

```json
{
  "name": "my_plugin",
  "version": "1.0.0",
  "author": "Your Name",
  "description": "What this plugin does",
  "events": ["post_scan", "on_loot_add"],
  "requires": [],
  "permissions": ["loot_read"],
  "enabled": true
}
```

## plugin.py

```python
def activate(services, registry, bus):
    """Called when the plugin is loaded."""
    services.logger.info('My plugin activated!')

def deactivate():
    """Called on shutdown or disable."""
    pass

def on_event(event):
    """Called for each subscribed event."""
    pass
```
