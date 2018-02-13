import typing
import logging
import sarge
import time
import threading
from typing import Callable
from os import path
import os
import ssl
from installer.constants import create_logger, is_darwin, is_win, is_ubuntu
from urllib.request import urlretrieve

logger = create_logger(__name__)

# ------------------------ ERRORS ------------------------


class UserCancelledError(RuntimeError):
    """
        Error to throw if user cancels process of running a sequence of tasks
    """
    def __init__(self, *args, **kwargs):
        pass


class ExternalProcessError(BaseException):
    """
        Error to throw if running a process returns a non-zero exit code
    """
    def __init__(self, *args, **kwargs):
        pass


class StopperError(BaseException):
    """
        Error to throw just stopping the installation process, and log no details.
    """
    def __init__(self, *args, **kwargs):
        pass

# ------------------------ TASKS ------------------------


class InterruptableTask:
    """
        Base class for tasks. It has these features:
        1. 'parameters' field that can be set and then be used in run
        2. can be glued to another task is the form 't1 & t2' -> this expression is a task itself
            which if runs returns the result of second task
        3. can be piped to another task is the form 't1 | t2' -> this expression is a task itself
            which if runs, invokes the first task then adds its result as parameters['input'] of the second task
            the result is calculated similar to glue operator
    """
    _parameters = {}

    def __init__(self, is_cancelled: Callable[[], bool] = lambda: False):
        self._is_cancelled = is_cancelled
        pass

    def get_parameters(self):
        return self._parameters

    def set_parameters(self, parameters):
        self._parameters = parameters
        return self

    def __and__(self, other):
        class GlueTask(InterruptableTask):
            def __init__(self, task1: InterruptableTask, task2: InterruptableTask):
                super().__init__()
                self._task1 = task1
                self._task2 = task2

            def get_parameters(self):
                return self._task1.get_parameters()

            def set_parameters(self, parameters):
                self._task1.set_parameters(parameters)
                self._task2.set_parameters(parameters)
                return self

            def run(self):
                self._task1.run()
                return self._task2.run()
        return GlueTask(self, other)

    def __or__(self, other):
        class PipeTask(InterruptableTask):
            def __init__(self, task1: InterruptableTask, task2: InterruptableTask):
                super().__init__()
                self._task1 = task1
                self._task2 = task2

            def get_parameters(self):
                return self._task1.get_parameters()

            def set_parameters(self, parameters):
                self._task1.set_parameters(parameters)
                self._task2.set_parameters(parameters)
                return self

            def run(self):
                result = self._task1.run()
                self._task2.set_parameters({**self._task2.get_parameters(), 'input': result})
                return self._task2.run()
        return PipeTask(self, other)

    def parallel(self, other):
        class ParallelTask(InterruptableTask):
            def __init__(self, task1: InterruptableTask, task2: InterruptableTask):
                super().__init__()
                self._task1 = task1
                self._task2 = task2

            def get_parameters(self):
                return self._task1.get_parameters()

            def set_parameters(self, parameters):
                self._task1.set_parameters(parameters)
                self._task2.set_parameters(parameters)
                return self

            def run(self):
                task2 = threading.Thread(target=self._task2.run, name='parallel-task', daemon=True)
                task2.start()
                r = self._task1.run()
                task2.join()
                return r
        return ParallelTask(self, other)

    def execute(self, cmd, is_cancelled=None, throw_exception=None, dont_log_stdout=None, dont_log_stderr=None, async=False):
        process_run_task = ProcessRunTask(cmd, is_cancelled=is_cancelled or self._is_cancelled)
        process_run_task.set_parameters({
            'async': async,
            'dont_log_stdout': dont_log_stdout,
            'dont_log_stderr': dont_log_stderr
        })
        exit_code, std_out, std_err = process_run_task.run()
        if throw_exception and not exit_code == 0:
            raise ExternalProcessError(throw_exception)
        return exit_code, std_out, std_err

    def download(self, url, file):
        return DownloadTask(url, file, self._is_cancelled).run()

    @typing.abstractmethod
    def run(self):
        pass


class ProcessRunTask(InterruptableTask):
    """
        This process runner is a wrapper over sarge.run that adds several abilities to it:
        1. Logs process output stream with DEBUG level to default logger
        2. Logs process error stream with WARNING level to default logger
        3. Returns tripe of (exit_code as int, process_standard_output as str, process_standard_error as str)
        4. Takes a mutable function (is_cancelled) as parameter and periodically checks it, if it returns true
            it kills the created process and throws an InterruptedError() exception
    """
    def __init__(self, cmd: str, is_cancelled: Callable[[], bool] = lambda: False):
        super().__init__(is_cancelled)
        self._cmd = cmd

    def run(self) -> (int, str):
        cancelled = False
        finished = False
        capture_out = sarge.Capture()
        capture_err = sarge.Capture()
        captured_out = []
        captured_err = []

        logger.debug("Process executed: %s", self._cmd)
        pipeline = sarge.run(self._cmd, async=True, stdout=capture_out, stderr=capture_err, shell=False)

        def kill_all_if_cancelled():
            process_is_running = 2
            while process_is_running:
                if finished:
                    process_is_running = process_is_running - 1
                while True:
                    line_out_bin = capture_out.readline(block=False)
                    line_out = str(line_out_bin, encoding='utf-8')
                    line = line_out.replace('\n', '').replace('\r', '').replace('\0', '')
                    if not line_out or ord(line_out[0]) == 0:
                        break
                    else:
                        captured_out.append(line)
                        if not self.get_parameters()['dont_log_stdout']:
                            logger.debug(f"| {line}")
                while True:
                    line_out_bin = capture_err.readline(block=False)
                    line_err = str(line_out_bin, encoding='utf-8')
                    line = line_err.replace('\n', '').replace('\r', '').replace('\0', '')
                    if not line_out or ord(line_out[0]) == 0:
                        break
                    else:
                        captured_err.append(line)
                        if not self.get_parameters()['dont_log_stderr']:
                            logger.warning(f"| {line}")
                if self._is_cancelled():
                    nonlocal cancelled
                    cancelled = True
                    for c in pipeline.commands:
                        c.terminate()
                time.sleep(0.1)

        if self.get_parameters()['async']:
           return 0, '', ''

        watchdog = threading.Thread(target=kill_all_if_cancelled, name='process-watchdog', daemon=True)
        watchdog.start()

        pipeline.wait()
        finished = True
        watchdog.join()
        if cancelled:
            raise UserCancelledError()

        return pipeline.returncode, '\n'.join(captured_out), '\n'.join(captured_err)


class MultiPlatformTask(InterruptableTask):
    """
        A task that can behave differently based on OS
    """
    def __init__(self, is_cancelled: Callable[[], bool] = lambda: False):
        super().__init__(is_cancelled)

    def run_macos(self):
        raise NotImplementedError()

    def run_win(self):
        raise NotImplementedError()

    def run_ubuntu(self):
        raise NotImplementedError()

    def run(self):
        if is_win:
            return self.run_win()
        elif is_darwin:
            return self.run_macos()
        elif is_ubuntu:
            return self.run_ubuntu()
        else:
            raise NotImplementedError("Unsupported operating system !")


class DownloadTask(InterruptableTask):
    def __init__(self, url: str, save_full_path: str, is_cancelled: Callable[[], bool] = lambda: False):
        super().__init__(is_cancelled)
        self._url = url
        self._save_full_path = save_full_path

    def run(self):
        def hook(block_num, block_size, total_size):
            if self._is_cancelled():
                raise UserCancelledError()
            percent = min(100 * block_num * block_size / total_size, 100.00)
            logger.debug("PROGRESS: %%%d", percent)

        if not path.exists(self._save_full_path):
            if not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
                ssl._create_default_https_context = ssl._create_unverified_context
            logger.debug("Downloading file %s from %s", self._save_full_path, self._url)
            urlretrieve(self._url, filename=f'{self._save_full_path}.part', reporthook=hook)
            os.rename(f'{self._save_full_path}.part', self._save_full_path)
            logger.debug("Successfully downloaded file %s ", self._save_full_path)
        else:
            logger.debug("File %s was already in cache, skipped download. ", self._save_full_path)


class RetrierTask(InterruptableTask):
    """
        Wraps another tasks and retries it in case of ExternalProcessError
    """
    def __init__(self, task: InterruptableTask, retries: int = 3):
        super().__init__(task._is_cancelled)
        self._task = task
        self._retries = retries

    def run(self):
        for i in range(1, self._retries):
            try:
                return self._task.run()
            except UserCancelledError:
                raise
            except ExternalProcessError:
                logger.debug(f'Retrying.. (%d/%d)', i, self._retries)


class ConditionalTask(InterruptableTask):
    """
        Wraps another tasks and retries it in case of ExternalProcessError
    """
    def __init__(self, task: InterruptableTask, condition: Callable[[], bool] = lambda: True):
        super().__init__(task._is_cancelled)
        self._task = task
        self._condition = condition

    def run(self):
        if self._condition():
            return self._task.run()
        else:
            return None
