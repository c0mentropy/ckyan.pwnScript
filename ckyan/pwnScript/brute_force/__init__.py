from ..connect import connect_io
from ..misc import sl, rp, sh


class BruteForce:
    def __init__(self, exp=None, cmd: bytes = b"ls", recv_str: bytes = b"flag"):
        if exp is not None:
            self.exp = exp
        else:
            return

        self.cmd = cmd
        self.recv_str = recv_str

    def set_exp(self, exp=None, cmd: bytes = b"ls", recv_str: bytes = b"flag"):

        if exp is not None:
            self.exp = exp
        else:
            return

        self.cmd = cmd
        self.recv_str = recv_str

    def _attack(self):

        if self.exp is None:
            return

        try:

            self.exp()

            sl(self.cmd)
            if rp(lambda x: self.recv_str in x) != b'':
                sh()
            else:
                raise EOFError

        except BrokenPipeError as e:
            connect_io.conn.close()
            raise e

        except EOFError as e:
            connect_io.conn.close()
            raise e

    def attack(self):
        while True:
            try:
                self._attack()
                break
            except EOFError:
                continue
            except BrokenPipeError:
                continue
