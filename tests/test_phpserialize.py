import unittest

from server import phpserialize


class PhpSerializeTests(unittest.TestCase):
    def test_decodes_wordpress_arrays_without_executing_objects(self):
        value = (
            'a:2:{i:0;s:19:"akismet/akismet.php";'
            'i:1;s:22:"safe-plugin/plugin.php";}'
        )
        self.assertEqual(
            ["akismet/akismet.php", "safe-plugin/plugin.php"],
            phpserialize.loads(value))

        obj = 'O:8:"stdClass":1:{s:4:"name";s:4:"demo";}'
        self.assertEqual(
            {"__class__": "stdClass", "name": "demo"},
            phpserialize.loads(obj))

    def test_honours_utf8_byte_lengths_and_rejects_bad_lengths(self):
        self.assertEqual("München", phpserialize.loads('s:8:"München";'))
        self.assertIsNone(phpserialize.safe_loads('s:80:"short";'))

    def test_limits_depth_items_and_bytes(self):
        nested = 'a:1:{i:0;a:1:{i:0;a:1:{i:0;s:1:"x";}}}'
        with self.assertRaises(phpserialize.DecodeError):
            phpserialize.loads(nested, max_depth=1)
        with self.assertRaises(phpserialize.DecodeError):
            phpserialize.loads('a:2:{i:0;i:1;i:1;i:2;}', max_items=2)
        with self.assertRaises(phpserialize.DecodeError):
            phpserialize.loads('s:4:"test";', max_bytes=4)


if __name__ == "__main__":
    unittest.main()
