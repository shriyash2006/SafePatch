import unittest

from src.hello import hello


class HelloTests(unittest.TestCase):
    def test_hello(self):
        self.assertEqual(hello("SafePatch"), "Hello, SafePatch!")


if __name__ == "__main__":
    unittest.main()
