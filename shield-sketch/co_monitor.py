#!/usr/bin/env python3

##
## Control plane co-monitoring for Shield
## 
from cms import CountMinSketch
import threading

class CoMonitor:
    def __init__(self, n_task: int, layer3_array_size_exp_per_tasks: list[int], decay_amount: int):
        self.cms = [CountMinSketch(layer3_array_size_exp_per_tasks[i]) for i in range(n_task)]
        self.decay_amount = decay_amount
        self.lock = threading.Lock()

    def plus(self, task_id: int, element, overflowed_data: list[int]) -> int:
        with self.lock:
            result = min(self.cms[task_id].plus(element, overflowed_data))
            return result

    def decay(self):    # decay not called
        with self.lock:
            for task_id in range(len(self.cms)):
                self.cms[task_id].decay(self.decay_amount)

    def read(self, task_id: int, element) -> list[int]:
        with self.lock:
            return self.cms[task_id].read(element)
