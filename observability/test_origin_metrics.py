#!/usr/bin/env python3
"""Bounded origin parsing, retention and snapshot tests using fictional records."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import origin_metrics as metrics


def row(path='/example', **changes):
    value={'ts':'2026-01-01T00:00:00Z','method':'GET','path':path,'status':200,'seconds':0.01}
    value.update(changes)
    return (json.dumps(value)+'\n').encode()


class OriginWindowTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source=Path(self.directory.name)/'origin.jsonl'

    def test_valid_projection_and_invalid_types_do_not_leak_extra_fields(self):
        self.source.write_bytes(row(body='PRIVATE_SENTINEL')+b'not json\n'+b'[]\n'+row(status=True)+row(seconds=float('nan'))+row(admin_denied='1')+row(seconds=10**1000))
        data=metrics.aggregate(self.source)
        self.assertEqual(data['requests'],1)
        self.assertEqual(data['malformed_lines'],6)
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(data)+metrics.render(data))
        self.assertIsNone(data['waf']['false_positive_rate'])

    def test_oversized_record_is_discarded_without_parsing_its_tail(self):
        self.source.write_bytes(b'x'*500+row('/hidden-fragment')+row('/retained'))
        with patch.object(metrics,'MAX_LINE_BYTES',256):
            data=metrics.aggregate(self.source)
        self.assertEqual(data['requests'],1)
        self.assertEqual(data['routes'][0]['path'],'/retained')
        self.assertEqual(data['input_window']['oversized_lines'],1)

    def test_sparse_large_file_reads_only_bounded_tail_and_handles_prefix(self):
        with self.source.open('wb') as out:
            out.seek(32*1024*1024)
            out.write(b'\n'+row('/one')+row('/two'))
        with patch.object(metrics,'MAX_INPUT_BYTES',4096):
            data=metrics.aggregate(self.source)
        self.assertEqual(data['requests'],2)
        self.assertLessEqual(data['input_window']['bytes_scanned'],4096)
        self.assertTrue(data['input_window']['discarded_prefix_fragment'])
        self.assertFalse(data['input_window']['complete_file_scanned'])

    def test_record_retention_is_visible_and_keeps_recent_rows(self):
        self.source.write_bytes(b''.join(row('/'+str(i)) for i in range(5)))
        with patch.object(metrics,'MAX_RECORDS',3):
            data=metrics.aggregate(self.source)
        self.assertEqual(data['requests'],3)
        self.assertEqual(data['input_window']['retention_dropped'],2)
        self.assertEqual({r['path'] for r in data['routes']},{'/2','/3','/4'})

    def test_exact_line_boundary_keeps_first_complete_row(self):
        prefix=row('/older')
        tail=row('/one')+row('/two')
        self.source.write_bytes(prefix+tail)
        with patch.object(metrics,'MAX_INPUT_BYTES',len(tail)+1):
            data=metrics.aggregate(self.source)
        self.assertEqual(data['requests'],2)
        self.assertFalse(data['input_window']['discarded_prefix_fragment'])

    def test_growth_during_parse_does_not_extend_snapshot_budget(self):
        self.source.write_bytes(row('/snapshot'))
        size=self.source.stat().st_size
        original=json.loads
        def append_once(value):
            with self.source.open('ab') as out:out.write(row('/later'))
            return original(value)
        with patch.object(metrics.json,'loads',side_effect=append_once):
            data=metrics.aggregate(self.source)
        self.assertEqual(data['requests'],1)
        self.assertEqual(data['input_window']['bytes_scanned'],size)
        self.assertEqual(data['input_window']['file_size_bytes'],size)


if __name__=='__main__':
    unittest.main()
