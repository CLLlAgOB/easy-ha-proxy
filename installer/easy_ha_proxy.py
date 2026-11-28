"""Not run: the installer is the host agent's "cli" (installer/easy-ha-proxy).

The updater of releases before 1.2.0 checks that a source it downloads holds
this file and installer/requirements.txt before it hands over to
installer/easy-ha-proxy. Remove both once no supported gateway runs such a
release.
"""

raise SystemExit("easy-ha-proxy: run installer/easy-ha-proxy; the installer is no longer Python.")
