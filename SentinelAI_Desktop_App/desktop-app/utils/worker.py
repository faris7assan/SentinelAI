from PyQt5.QtCore import QThread, pyqtSignal


class Worker(QThread):
    result   = pyqtSignal(object)
    error    = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn, self._args, self._kwargs = fn, args, kwargs
        self.setTerminationEnabled(True)

    def run(self):
        try:
            out = self._fn(*self._args, **self._kwargs)
            self.result.emit(out)
        except Exception as e:
            self.error.emit(str(e))
