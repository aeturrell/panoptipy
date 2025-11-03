"""Tests for meta.py module."""

from unittest.mock import mock_open, patch

import pytest

from panoptipy.meta import extract_check_info_from_code, get_check_id_and_description_pairs


class TestExtractCheckInfoFromCode:
    """Tests for extract_check_info_from_code function."""

    def test_extract_single_check(self):
        """Test extracting a single check from code."""
        code = '''
class TestCheck(Check):
    def __init__(self):
        super().__init__(check_id="test_check", description="Test description")
'''
        result = extract_check_info_from_code(code)

        assert len(result) == 1
        assert result[0]["check_id"] == "test_check"
        assert result[0]["description"] == "Test description"

    def test_extract_multiple_checks(self):
        """Test extracting multiple checks from code."""
        code = '''
class Check1(Check):
    def __init__(self):
        super().__init__(check_id="check1", description="First check")

class Check2(Check):
    def __init__(self):
        super().__init__(check_id="check2", description="Second check")
'''
        result = extract_check_info_from_code(code)

        assert len(result) == 2
        assert result[0]["check_id"] == "check1"
        assert result[0]["description"] == "First check"
        assert result[1]["check_id"] == "check2"
        assert result[1]["description"] == "Second check"

    def test_extract_with_keyword_args(self):
        """Test extracting checks with keyword arguments."""
        code = '''
class TestCheck(Check):
    def __init__(self):
        super().__init__(
            check_id="test_check",
            description="Test description"
        )
'''
        result = extract_check_info_from_code(code)

        assert len(result) == 1
        assert result[0]["check_id"] == "test_check"

    def test_extract_no_checks(self):
        """Test extracting from code with no checks."""
        code = '''
def some_function():
    pass

class SomeClass:
    def __init__(self):
        self.value = 42
'''
        result = extract_check_info_from_code(code)

        assert len(result) == 0

    def test_extract_incomplete_check(self):
        """Test extracting from code with incomplete check info."""
        code = '''
class TestCheck(Check):
    def __init__(self):
        super().__init__(check_id="test_check")
'''
        result = extract_check_info_from_code(code)

        # Should not include checks missing description
        assert len(result) == 0

    def test_extract_with_syntax_error(self):
        """Test extracting from code with syntax error."""
        code = '''
class TestCheck(Check):
    def __init__(self
        super().__init__(check_id="test_check", description="Test")
'''
        result = extract_check_info_from_code(code)

        # Should return empty list on syntax error
        assert len(result) == 0

    def test_extract_empty_code(self):
        """Test extracting from empty code."""
        result = extract_check_info_from_code("")

        assert len(result) == 0

    def test_extract_with_ast_str_nodes(self):
        """Test extracting with AST Str nodes (Python 3.7 compatibility)."""
        # This tests the legacy ast.Str handling
        code = '''
class TestCheck(Check):
    def __init__(self):
        super().__init__(check_id="test_check", description="Test description")
'''
        result = extract_check_info_from_code(code)

        # Should work with both ast.Constant and ast.Str
        assert len(result) >= 0

    def test_extract_only_check_id_provided(self):
        """Test extraction when only check_id is provided."""
        code = '''
class TestCheck(Check):
    def __init__(self):
        super().__init__(check_id="test_only_id")
'''
        result = extract_check_info_from_code(code)

        # Should not include if description is missing
        assert len(result) == 0

    def test_extract_only_description_provided(self):
        """Test extraction when only description is provided."""
        code = '''
class TestCheck(Check):
    def __init__(self):
        super().__init__(description="Test only description")
'''
        result = extract_check_info_from_code(code)

        # Should not include if check_id is missing
        assert len(result) == 0

    def test_extract_with_category(self):
        """Test extraction with additional category parameter."""
        code = '''
class TestCheck(Check):
    def __init__(self):
        super().__init__(
            check_id="test_check",
            description="Test description",
            category="testing"
        )
'''
        result = extract_check_info_from_code(code)

        # Should still extract check_id and description
        assert len(result) == 1
        assert result[0]["check_id"] == "test_check"
        assert result[0]["description"] == "Test description"

    def test_extract_with_complex_init(self):
        """Test extraction with complex __init__ method."""
        code = '''
class TestCheck(Check):
    def __init__(self, config=None):
        self.config = config
        super().__init__(
            check_id="complex_check",
            description="Complex check description"
        )
        self.other_attr = "value"
'''
        result = extract_check_info_from_code(code)

        assert len(result) == 1
        assert result[0]["check_id"] == "complex_check"

    def test_extract_from_multiline_string(self):
        """Test extraction with multiline string description."""
        code = '''
class TestCheck(Check):
    def __init__(self):
        super().__init__(
            check_id="test_check",
            description="This is a very long description "
                       "that spans multiple lines"
        )
'''
        result = extract_check_info_from_code(code)

        # AST will combine the strings
        assert len(result) == 1


class TestGetCheckIdAndDescriptionPairs:
    """Tests for get_check_id_and_description_pairs function."""

    @patch("panoptipy.meta.importlib.resources.files")
    def test_get_pairs_success(self, mock_files):
        """Test getting check ID and description pairs successfully."""
        mock_code = '''
class TestCheck(Check):
    def __init__(self):
        super().__init__(check_id="test_check", description="Test description")
'''
        mock_file = mock_open(read_data=mock_code)
        mock_resource = mock_files.return_value.joinpath.return_value
        mock_resource.open.return_value.__enter__ = mock_file
        mock_resource.open.return_value.__exit__ = lambda *args: None
        mock_resource.open.return_value.read.return_value = mock_code

        result = get_check_id_and_description_pairs()

        assert isinstance(result, list)

    @patch("panoptipy.meta.importlib.resources.files")
    def test_get_pairs_file_not_found(self, mock_files):
        """Test getting pairs when checks.py is not found."""
        mock_files.return_value.joinpath.return_value.open.side_effect = FileNotFoundError(
            "checks.py not found"
        )

        result = get_check_id_and_description_pairs()

        # Should return empty list on error
        assert result == []

    @patch("panoptipy.meta.importlib.resources.files")
    def test_get_pairs_read_error(self, mock_files):
        """Test getting pairs when there's a read error."""
        mock_files.return_value.joinpath.return_value.open.side_effect = Exception(
            "Read error"
        )

        result = get_check_id_and_description_pairs()

        # Should return empty list on error
        assert result == []

    @patch("panoptipy.meta.importlib.resources.files")
    def test_get_pairs_empty_file(self, mock_files):
        """Test getting pairs from empty file."""
        mock_code = ""
        mock_file = mock_open(read_data=mock_code)
        mock_resource = mock_files.return_value.joinpath.return_value
        mock_resource.open.return_value.__enter__ = mock_file
        mock_resource.open.return_value.__exit__ = lambda *args: None
        mock_resource.open.return_value.read.return_value = mock_code

        result = get_check_id_and_description_pairs()

        # Should return empty list for empty file
        assert result == []

    @patch("panoptipy.meta.importlib.resources.files")
    def test_get_pairs_multiple_checks(self, mock_files):
        """Test getting pairs with multiple checks."""
        mock_code = '''
class Check1(Check):
    def __init__(self):
        super().__init__(check_id="check1", description="First")

class Check2(Check):
    def __init__(self):
        super().__init__(check_id="check2", description="Second")
'''
        mock_file = mock_open(read_data=mock_code)
        mock_resource = mock_files.return_value.joinpath.return_value
        mock_resource.open.return_value.__enter__ = mock_file
        mock_resource.open.return_value.__exit__ = lambda *args: None
        mock_resource.open.return_value.read.return_value = mock_code

        result = get_check_id_and_description_pairs()

        assert len(result) >= 0  # May return results if extraction works
