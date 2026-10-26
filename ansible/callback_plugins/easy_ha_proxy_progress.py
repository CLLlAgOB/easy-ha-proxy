# -*- coding: utf-8 -*-
"""Machine-readable progress for the web update page.

Adds one line per task to the normal output while EASY_HA_PROXY_PROGRESS=1:

    EHP-PROGRESS 57/123 haproxy-admin : easy-ha-proxy-guardd | Install script

The total is counted the way ``ansible-playbook --list-tasks`` counts: every
play compiled, filtered by the selected tags. Tasks a dynamic include adds at
run time are not in it, so the count can pass the total; the reader caps the
bar. Without the variable the plugin prints nothing, so a terminal run looks
exactly as before.
"""

from __future__ import annotations

DOCUMENTATION = """
    name: easy_ha_proxy_progress
    type: aggregate
    short_description: task counter for the easy-ha-proxy update page
    description:
      - Prints "EHP-PROGRESS done/total task" before each task when
        EASY_HA_PROXY_PROGRESS=1 is set in the environment.
"""

import os

from ansible import constants as C
from ansible.playbook.block import Block
from ansible.plugins.callback import CallbackBase

MARKER = "EHP-PROGRESS"
MAX_NAME = 160


def _count(block) -> int:
    total = 0
    for task in block.block:
        if isinstance(task, Block):
            total += _count(task)
        elif not (task.action in C._ACTION_META and task.implicit):
            total += 1
    return total


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "easy_ha_proxy_progress"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.active = os.environ.get("EASY_HA_PROXY_PROGRESS") == "1"
        self.total = 0
        self.done = 0

    def _emit(self, name: str = "") -> None:
        clean = " ".join(str(name or "").split())[:MAX_NAME]
        self._display.display(f"{MARKER} {self.done}/{self.total} {clean}".rstrip())

    def v2_playbook_on_start(self, playbook):
        if not self.active:
            return
        total = 0
        try:
            for play in playbook.get_plays():
                manager = play.get_variable_manager()
                variables = manager.get_vars(play=play) if manager is not None else {}
                for block in play.compile():
                    block = block.filter_tagged_tasks(variables)
                    if block.has_tasks():
                        total += _count(block)
        except Exception:  # noqa: BLE001 - progress must never break a run
            total = 0
        self.total = total
        self._emit()

    def v2_playbook_on_task_start(self, task, is_conditional):
        if not self.active:
            return
        self.done += 1
        self._emit(task.get_name())

    def v2_playbook_on_handler_task_start(self, task):
        if not self.active:
            return
        # Handlers are not in the count; name them without moving the bar.
        self._emit(task.get_name())
