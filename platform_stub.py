'''
[zerovault] vagrant@:~/ZeroVault % cloudabi-run /usr/local/x86_64-unknown-cloudabi/bin/python3 < zv.yaml
Traceback (most recent call last):
  File "<script>", line 29, in <module>
  File "wsgiref/simple_server.py", line 17, in <module>
  File "platform.py", line 116, in <module>
  File "subprocess.py", line 50, in <module>
  File "signal.py", line 10, in <module>
  File "enum.py", line 632, in _convert
  File "enum.py", line 293, in __call__
  File "enum.py", line 384, in _create_
IndexError: list index out of range

gevent is cited as a case where monkey-patching is worthwhile. If the
socket module used ocap for gethostbyname, of course this wouldn't be
necessary.
http://stackoverflow.com/a/11977492
'''

def python_implementation():
    return 'python XXX'


def monkey_patch_platform(this_module):
    from sys import modules
    modules['platform'] = this_module
    from platform import python_implementation
    assert python_implementation()  # test

