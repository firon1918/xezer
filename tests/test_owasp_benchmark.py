"""CI gate for the OWASP detection benchmark: planted positives, hardened negatives."""
from tests.benchmarks.owasp_detection import benchmark


async def test_owasp_detection_benchmark_matrix():
    report = await benchmark()
    assert report['score']['detected'] == report['score']['expected']
    assert report['score']['hardened_false_positives'] == 0
    for case in report['cases']:
        assert case['detected'], case
        assert not case['hardened_false_positive'], case
    assert report['planted']['findings']['confirmed'] == 4
    assert report['planted']['findings']['candidate'] == 3
    assert report['hardened']['findings'] == {'confirmed': 0, 'candidate': 0}
