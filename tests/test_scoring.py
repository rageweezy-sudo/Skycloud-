import unittest

from account_privacy.core.models import EvidenceCategory as Category
from account_privacy.core.scoring import ConfidenceBand, score_evidence


class ScoringTests(unittest.TestCase):
    def test_single_category_weights_and_boundaries(self):
        for category, points, band in (
            (Category.IMPORT, 80, ConfidenceBand.HIGH),
            (Category.SIGNUP, 70, ConfidenceBand.MEDIUM),
            (Category.RESET, 45, ConfidenceBand.MEDIUM),
            (Category.RECEIPT, 35, ConfidenceBand.LOW),
            (Category.UNSUBSCRIBE, 15, ConfidenceBand.LOW),
        ):
            with self.subTest(category=category):
                result = score_evidence([category])
                self.assertEqual((result.points, result.band), (points, band))

    def test_repeats_order_cap_and_ambiguous_evidence(self):
        categories = list(Category)
        self.assertEqual(score_evidence(categories).points, 100)
        self.assertEqual(score_evidence(categories, ambiguous=True).points, 44)
        self.assertEqual(score_evidence(categories, ambiguous=True).band, ConfidenceBand.LOW)
        self.assertEqual(score_evidence(categories), score_evidence(reversed(categories)))
        self.assertEqual(score_evidence([Category.RECEIPT] * 50).points, 35)
        self.assertEqual(score_evidence([Category.RECEIPT, Category.UNSUBSCRIBE]).points, 45)
        self.assertEqual(score_evidence([]).points, 0)
