"""Mock kernel/OS queries, not the isolation implementation; no Linux operations."""
import contextlib,struct,sys,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from test_external_review import compat
import test_collector as fixtures
setUpModule=fixtures.setUpModule
tearDownModule=fixtures.tearDownModule

class NamespaceTests(unittest.TestCase):
    def run_check(self,pairs=((1,'lo'),),flags=8,query_error=None):
        channel=Mock();channel.__enter__=Mock(return_value=channel);channel.__exit__=Mock(return_value=False)
        channel.fileno.return_value=77
        ioctl=Mock(return_value=struct.pack('16sH22x',b'lo',flags),side_effect=query_error)
        with patch.object(compat.os,'getuid',return_value=1001,create=True), \
             patch.object(compat.socket,'if_nameindex',return_value=list(pairs)), \
             patch.object(compat.socket,'socket',return_value=channel), \
             patch.dict(sys.modules,{'fcntl':types.SimpleNamespace(ioctl=ioctl)}), \
             patch.object(Path,'iterdir',side_effect=AssertionError('inherited host sysfs must not be used')), \
             patch.object(Path,'read_text',side_effect=AssertionError('host sysfs flags must not be read')):
            result=compat.isolated('net:[100]',1001,readlink=lambda p:'net:[200]')
        ioctl.assert_called_once_with(77,0x8913,struct.pack('16sH22x',b'lo',0))
        channel.__exit__.assert_called_once()
        return result
    def test_inherited_sysfs_ignored_process_namespace_loopback_down(self):
        self.assertFalse(self.run_check()['sysfs_used'])
    def test_unexpected_interface(self):
        for names in (((1,'lo'),(2,'eth0')),((2,'eth0'),)):
            with self.subTest(names=names),self.assertRaises(ValueError):self.run_check(names)
    def test_loopback_up_rejected(self):
        with self.assertRaisesRegex(ValueError,'loopback_is_up'):self.run_check(flags=9)
    def test_ioctl_failure_rejected(self):
        with self.assertRaises(OSError):self.run_check(query_error=OSError('invented ioctl failure'))
    def test_inventory_query_failure(self):
        with patch.object(compat.os,'getuid',return_value=1001,create=True),patch.object(compat.socket,'if_nameindex',side_effect=OSError('invented')):
            with self.assertRaises(OSError):compat.isolated('parent',1001,readlink=lambda p:'child')
    def test_root_and_same_namespace_rejected(self):
        with patch.object(compat.os,'getuid',return_value=0,create=True):
            with self.assertRaises(ValueError):compat.isolated('parent',0)
        with patch.object(compat.os,'getuid',return_value=1001,create=True):
            with self.assertRaises(ValueError):compat.isolated('same',1001,readlink=lambda p:'same')
    def test_package_revision_partial_and_timeout(self):
        with patch.object(compat.sys,'platform','linux'):
            command=Mock(return_value=types.SimpleNamespace(returncode=1,stdout=b'python3.12\t3.12.3-invented\tamd64\tinstalled\n',stderr=b'missing invented package'))
            result=compat.package_revisions(command)
            self.assertEqual(result['status'],'partial_unresolved');self.assertEqual(result['patched_status'],'not_inferred')
            self.assertEqual(command.call_args.kwargs['timeout'],4)
            result=compat.package_revisions(Mock(side_effect=TimeoutError('invented')))
            self.assertEqual(result['status'],'unresolved');self.assertEqual(result['failure_type'],'TimeoutError')
    def test_package_output_bound(self):
        with patch.object(compat.sys,'platform','linux'):
            result=compat.package_revisions(Mock(return_value=types.SimpleNamespace(returncode=0,stdout=b'x'*16385,stderr=b'')))
            self.assertEqual(result['status'],'unresolved');self.assertNotIn('stdout',result)

if __name__=='__main__':unittest.main()
