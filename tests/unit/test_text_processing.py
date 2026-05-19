from markupsafe import Markup

from app.core.text_processing import (
    chunk_text_with_overlap,
    estimate_summary_max_tokens,
    simple_format_note,
)


class TestChunkTextWithOverlap:
    def test_empty_string_returns_empty_list(self):
        assert chunk_text_with_overlap("") == []

    def test_whitespace_only_returns_empty_list(self):
        assert chunk_text_with_overlap("   \n\t  ") == []

    def test_single_chunk_when_text_fits(self):
        text = "one two three"
        result = chunk_text_with_overlap(text, max_tokens=10, overlap=2)
        assert result == ["one two three"]

    def test_splits_into_multiple_chunks(self):
        words = [str(i) for i in range(10)]
        text = " ".join(words)
        result = chunk_text_with_overlap(text, max_tokens=4, overlap=0)
        assert len(result) == 3
        assert result[0] == "0 1 2 3"
        assert result[1] == "4 5 6 7"
        assert result[2] == "8 9"

    def test_overlap_repeats_tokens(self):
        words = [str(i) for i in range(8)]
        text = " ".join(words)
        result = chunk_text_with_overlap(text, max_tokens=4, overlap=2)
        tail = result[0].split()[-2:]
        head = result[1].split()[:2]
        assert tail == head  # last 2 tokens of chunk 0 == first 2 tokens of chunk 1

    def test_last_chunk_not_duplicated_when_exact_fit(self):
        words = [str(i) for i in range(4)]
        text = " ".join(words)
        result = chunk_text_with_overlap(text, max_tokens=4, overlap=0)
        assert result == ["0 1 2 3"]

    def test_overlap_clamped_below_max_tokens(self):
        text = "a b c d e"
        result = chunk_text_with_overlap(text, max_tokens=3, overlap=5)
        assert all(len(c.split()) <= 3 for c in result)

    def test_none_treated_as_empty(self):
        assert chunk_text_with_overlap(None) == []  # type: ignore[arg-type]


class TestEstimateSummaryMaxTokens:
    def test_empty_text_returns_min(self):
        result = estimate_summary_max_tokens("", max_tokens=1200, min_tokens=120, ratio=0.35)
        assert result == 120

    def test_short_text_returns_min(self):
        text = "one two three"
        result = estimate_summary_max_tokens(text, max_tokens=1200, min_tokens=120, ratio=0.35)
        assert result == 120

    def test_long_text_capped_at_max(self):
        text = " ".join(["word"] * 10000)
        result = estimate_summary_max_tokens(text, max_tokens=500, min_tokens=50, ratio=0.5)
        assert result == 500

    def test_medium_text_scales_with_ratio(self):
        text = " ".join(["word"] * 1000)
        result = estimate_summary_max_tokens(text, max_tokens=1200, min_tokens=120, ratio=0.4)
        assert result == 400

    def test_result_always_within_bounds(self):
        for word_count in [0, 10, 100, 500, 2000, 5000]:
            text = " ".join(["x"] * word_count)
            result = estimate_summary_max_tokens(text, max_tokens=800, min_tokens=80, ratio=0.3)
            assert 80 <= result <= 800


class TestSimpleFormatNote:
    def test_returns_markup_instance(self):
        result = simple_format_note("hello")
        assert isinstance(result, Markup)

    def test_plain_text_wrapped_in_paragraph(self):
        result = simple_format_note("hello world")
        assert "<p>hello world</p>" in result

    def test_heading_levels(self):
        assert "<h2>" in simple_format_note("# Title")
        assert "<h3>" in simple_format_note("## Subtitle")
        assert "<h4>" in simple_format_note("### Sub-subtitle")

    def test_unordered_list_star(self):
        result = simple_format_note("* item one\n* item two")
        assert "<ul>" in result
        assert "<li>item one</li>" in result
        assert "<li>item two</li>" in result
        assert "</ul>" in result

    def test_unordered_list_dash(self):
        result = simple_format_note("- item a\n- item b")
        assert "<li>item a</li>" in result

    def test_horizontal_rule(self):
        result = simple_format_note("---")
        assert "<hr />" in result

    def test_bold_inline(self):
        result = simple_format_note("**bold text**")
        assert "<strong>" in result

    def test_italic_inline(self):
        result = simple_format_note("*italic text*")
        assert "<em>" in result

    def test_html_entities_escaped(self):
        result = simple_format_note("<script>alert(1)</script>")
        assert "<script>" not in result

    def test_empty_string(self):
        result = simple_format_note("")
        assert result == Markup("")

    def test_blank_lines_ignored(self):
        result = simple_format_note("line one\n\nline two")
        assert "<p>line one</p>" in result
        assert "<p>line two</p>" in result
