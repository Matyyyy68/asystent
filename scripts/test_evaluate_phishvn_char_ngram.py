import io
import unittest

from evaluate_phishvn_char_ngram import char_ngrams, load_split, parse_rows


class PhishVnCharNgramTests(unittest.TestCase):
    def test_test_split_filename_is_rejected_before_open(self):
        with self.assertRaisesRegex(ValueError, "only the official"):
            load_split("url_test.csv")

    def test_mixed_split_is_rejected_without_printing_url(self):
        csv_data = "url,label,tier,split\nsecret.example/path,phishing,gold,test\n"
        with self.assertRaisesRegex(ValueError, "row outside train split") as error:
            parse_rows(io.StringIO(csv_data), "train")
        self.assertNotIn("secret.example", str(error.exception))

    def test_gold_and_silver_rows_are_selected_without_url_output(self):
        csv_data = (
            "url,label,tier,split\n"
            "one.example/path,phishing,gold,train\n"
            "two.example/path,benign,silver,train\n"
            "three.example/path,phishing,bronze,train\n"
        )
        self.assertEqual(
            [("phishing", "one.example/path"), ("benign", "two.example/path")],
            parse_rows(io.StringIO(csv_data), "train"),
        )

    def test_character_ngrams_are_local_features(self):
        features = char_ngrams("example.test/a")
        self.assertGreater(features["exa"], 0)
        self.assertGreater(features["exam"], 0)
        self.assertGreater(features["ample"], 0)
        self.assertNotIn("https://", features)


if __name__ == "__main__":
    unittest.main()
