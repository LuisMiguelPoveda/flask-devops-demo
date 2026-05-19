import json

import pytest

from app.core.flashcard_validation import _parse_and_validate_flashcards_json


def _make_card(question="Q?", options=None, correct_index=0):
    return {
        "question": question,
        "options": options or ["A", "B", "C", "D"],
        "correct_index": correct_index,
    }


def _serialize(cards):
    return json.dumps(cards)


class TestParseAndValidateFlashcardsJson:
    def test_valid_single_card(self):
        cards = [_make_card()]
        result = _parse_and_validate_flashcards_json(_serialize(cards), 1)
        assert len(result) == 1
        assert result[0]["question"] == "Q?"

    def test_valid_multiple_cards(self):
        cards = [_make_card(f"Q{i}?") for i in range(5)]
        result = _parse_and_validate_flashcards_json(_serialize(cards), 5)
        assert len(result) == 5

    def test_strips_json_code_fence(self):
        cards = [_make_card()]
        raw = f"```json\n{json.dumps(cards)}\n```"
        result = _parse_and_validate_flashcards_json(raw, 1)
        assert len(result) == 1

    def test_strips_plain_code_fence(self):
        cards = [_make_card()]
        raw = f"```\n{json.dumps(cards)}\n```"
        result = _parse_and_validate_flashcards_json(raw, 1)
        assert len(result) == 1

    def test_wrong_count_raises(self):
        cards = [_make_card()]
        with pytest.raises(ValueError, match="2"):
            _parse_and_validate_flashcards_json(_serialize(cards), 2)

    def test_not_a_list_raises(self):
        with pytest.raises(ValueError):
            _parse_and_validate_flashcards_json(json.dumps({"question": "Q?"}), 1)

    def test_card_not_a_dict_raises(self):
        with pytest.raises(ValueError, match="objeto JSON"):
            _parse_and_validate_flashcards_json(json.dumps(["not a dict"]), 1)

    def test_missing_question_raises(self):
        card = _make_card()
        del card["question"]
        with pytest.raises(ValueError, match="question"):
            _parse_and_validate_flashcards_json(_serialize([card]), 1)

    def test_empty_question_raises(self):
        card = _make_card(question="   ")
        with pytest.raises(ValueError, match="question"):
            _parse_and_validate_flashcards_json(_serialize([card]), 1)

    def test_wrong_number_of_options_raises(self):
        card = _make_card(options=["A", "B", "C"])
        with pytest.raises(ValueError, match="options"):
            _parse_and_validate_flashcards_json(_serialize([card]), 1)

    def test_option_not_string_raises(self):
        card = _make_card(options=["A", "B", "C", 4])
        with pytest.raises(ValueError, match="options"):
            _parse_and_validate_flashcards_json(_serialize([card]), 1)

    def test_empty_option_raises(self):
        card = _make_card(options=["A", "B", "C", "   "])
        with pytest.raises(ValueError, match="options"):
            _parse_and_validate_flashcards_json(_serialize([card]), 1)

    def test_correct_index_out_of_range_raises(self):
        card = _make_card(correct_index=4)
        with pytest.raises(ValueError, match="correct_index"):
            _parse_and_validate_flashcards_json(_serialize([card]), 1)

    def test_correct_index_negative_raises(self):
        card = _make_card(correct_index=-1)
        with pytest.raises(ValueError, match="correct_index"):
            _parse_and_validate_flashcards_json(_serialize([card]), 1)

    def test_correct_index_not_int_raises(self):
        card = _make_card(correct_index="0")
        with pytest.raises(ValueError, match="correct_index"):
            _parse_and_validate_flashcards_json(_serialize([card]), 1)

    def test_correct_index_boundary_zero(self):
        card = _make_card(correct_index=0)
        result = _parse_and_validate_flashcards_json(_serialize([card]), 1)
        assert result[0]["correct_index"] == 0

    def test_correct_index_boundary_three(self):
        card = _make_card(correct_index=3)
        result = _parse_and_validate_flashcards_json(_serialize([card]), 1)
        assert result[0]["correct_index"] == 3

    def test_invalid_json_raises(self):
        with pytest.raises(Exception):
            _parse_and_validate_flashcards_json("not valid json {{{", 1)
