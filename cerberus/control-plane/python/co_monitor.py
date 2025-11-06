#!/usr/bin/python3

##
## Control plane co-monitoring for Cerberus
## 
from cms import CountMinSketch
import threading

class CoMonitor:
    def __init__(self, n_task: int, counter_size_per_tasks: list[int], array_size_per_tasks: list[int], n_hash: int = 3, n_window: int = 2):
        self.cms = [[CountMinSketch(counter_size_per_tasks[i], 2**array_size_per_tasks[i], n_hash) for i in range(n_task)] for _ in range(n_window)]
        self.current_max = [[0] * n_task for _ in range(n_window)]
        self.lock = threading.Lock()

    def read(self, task_id: int, element, current_window: int) -> list[int]:
        with self.lock:
            return self.cms[current_window][task_id].read(element)
        
    def get_current_max(self, current_window: int):
        with self.lock:
            return self.current_max[current_window]
    
    def update(self, task_id: int, element, overflowed_data: list[int], current_window: int) -> list[int]:
        with self.lock:
            result = 0
            max = 0
            min = self.cms[current_window][task_id].max
            for i, hash_value in enumerate(self.cms[current_window][task_id].keys(element)):   
                self.cms[current_window][task_id].cms[i][hash_value] += overflowed_data[i]
                current = self.cms[current_window][task_id].cms[i][hash_value]
                if current > max:
                    max = current
                if current < min:
                    min = current
            result = min 
            # Maximum value in the current window (for slice resizing)
            if max > self.current_max[current_window][task_id]:
                print(f"[Debug] Task {task_id}: Updated current_max[{current_window}] = {self.current_max[current_window][task_id]}")
                self.current_max[current_window][task_id] = max

            return result
        
    def reset(self, current_window: int):
        with self.lock:
            for task_id in range(len(self.cms[current_window])):
                self.cms[current_window][task_id].reset()
            self.current_max[current_window] = [0] * len(self.current_max[current_window])

    # Get current counts for all keys as dictionary: for multi_window-based threshold
    def get_current_counts(self, task_id: int, current_window: int) -> dict:
        with self.lock:
            counts = {}
            for i in range(len(self.cms[current_window][task_id].cms)):  
                for j in range(len(self.cms[current_window][task_id].cms[i])):
                    key = (i, j)
                    counts[key] = self.cms[current_window][task_id].cms[i][j]
            return counts