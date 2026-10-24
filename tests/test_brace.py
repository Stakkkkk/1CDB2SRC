"""Portable native CF brace grammar contracts, using only neutral values."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from onecdb2src.nativecf.brace import Atom, Reader


def shape(value):
    if type(value) is list:
        return [shape(child) for child in value]
    assert isinstance(value, Atom)
    return str(value), value.quoted, value.start, value.end


class BraceTests(unittest.TestCase):
    def parsed(self, data, expected, pos, nodes, **options):
        reader = Reader(data, **options)
        self.assertEqual(shape(reader.read()), expected)
        self.assertEqual((reader.pos, reader.nodes), (pos, nodes))

    def refused(self, data, error_type, message, pos, nodes, **options):
        reader = Reader(data, **options)
        with self.assertRaises(error_type) as caught:
            reader.read()
        self.assertEqual(str(caught.exception), message)
        self.assertEqual((reader.pos, reader.nodes), (pos, nodes))

    def test_plain_atoms_delimiters_and_character_spans(self):
        self.parsed('  a b \t', ('a b', False, 2, 7), 7, 1)
        self.parsed('{1, "a"}', [('1', False, 1, 2), ('a', True, 4, 7)], 8, 3)
        self.parsed('a"b', ('a"b', False, 0, 3), 3, 1)
        for data in ['x,y', 'x{', 'x}']:
            with self.subTest(data=data):
                self.refused(data, ValueError, 'Trailing brace data', 1, 1)

    def test_quoted_delimiters_doubled_quotes_and_utf16(self):
        self.parsed('{"a,b{}","a""b"}',
                    [('a,b{}', True, 1, 8), ('a"b', True, 9, 15)], 16, 3)
        self.parsed('"x"\\0041tail"', ('xAtail', True, 0, 13), 13, 1)
        self.parsed('"x"\\D83D"\\DE00"', ('x😀', True, 0, 15), 15, 1)
        self.refused('"x"\\ZZZZtail"', ValueError,
                     'Malformed quoted UTF-16 escape', 1, 1)
        reader = Reader('"x"\\D800"')
        with self.assertRaises(UnicodeDecodeError) as caught:
            reader.read()
        self.assertEqual((caught.exception.encoding, caught.exception.start,
                          caught.exception.end), ('utf-16-le', 2, 4))
        self.assertEqual((reader.pos, reader.nodes), (9, 1))

    def test_empty_atoms_and_syntax_error_state(self):
        self.parsed('{}', [], 2, 1)
        self.parsed('{,,}', [('', False, 1, 1), ('', False, 2, 2),
                             ('', False, 3, 3)], 4, 4)
        errors = [('', 'Unexpected end of brace data', 0, 1),
                  ('{', 'Unexpected end of brace data', 1, 2),
                  ('{1', 'Unclosed brace list', 2, 2),
                  ('}', 'Invalid atom', 0, 1),
                  ('"abc', 'Unclosed quoted token', 1, 1),
                  ('{}tail', 'Trailing brace data', 2, 1)]
        for data, message, pos, nodes in errors:
            with self.subTest(data=data):
                self.refused(data, ValueError, message, pos, nodes)

    def test_unicode_bom_whitespace_and_invalid_utf8(self):
        for data in ['\ufeff{東京,"😀"}', '\ufeff{東京,"😀"}'.encode('utf-8')]:
            self.parsed(data, [('東京', False, 1, 3), ('😀', True, 4, 7)], 8, 3)
        for whitespace in ['\t', '\n', '\r', '\x1c', '\x85', '\xa0',
                           '\u1680', '\u2003', '\u2028', '\u2029', '\u3000']:
            self.parsed(whitespace + 'x' + whitespace, ('x', False, 1, 3), 3, 1)
        self.parsed('\u200bx', ('\u200bx', False, 0, 2), 2, 1)
        with self.assertRaises(UnicodeDecodeError):
            Reader(b'{\xff}')

    def test_size_depth_and_node_quota_boundaries(self):
        for data in ['東京', '東京'.encode('utf-8')]:
            self.parsed(data, ('東京', False, 0, 2), 2, 1, max_bytes=6)
            with self.assertRaisesRegex(ValueError, '^Brace size quota exceeded$'):
                Reader(data, max_bytes=5)
        for data in ['\ufeff東京', '\ufeff東京'.encode('utf-8')]:
            self.parsed(data, ('東京', False, 0, 2), 2, 1, max_bytes=9)
            with self.assertRaisesRegex(ValueError, '^Brace size quota exceeded$'):
                Reader(data, max_bytes=8)
        self.parsed('{a}', [('a', False, 1, 2)], 3, 2, max_nodes=2)
        self.refused('{a}', ValueError, 'Brace node quota exceeded', 1, 2, max_nodes=1)
        self.parsed('{{x}}', [[('x', False, 2, 3)]], 5, 3, max_depth=3)
        self.refused('{{x}}', ValueError, 'Brace nesting quota exceeded', 2, 2, max_depth=2)
        self.refused('x', ValueError, 'Brace nesting quota exceeded', 0, 0, max_depth=0)

    def test_generated_neutral_values_and_long_unquoted_atom(self):
        for number in range(128):
            numeric = str(number)
            text = '{' + numeric + ',"value,' + numeric + '","東京😀"}'
            second_start = len(numeric) + 2
            second_end = 2 * len(numeric) + 10
            self.parsed(text, [(numeric, False, 1, len(numeric) + 1),
                ('value,' + numeric, True, second_start, second_end),
                ('東京😀', True, second_end + 1, second_end + 6)], len(text), 4)
        atom = 'x' * 70000
        self.parsed(atom, (atom, False, 0, 70000), 70000, 1)


if __name__ == '__main__':
    unittest.main()
