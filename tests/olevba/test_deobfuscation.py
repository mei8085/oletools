"""
Test VBA expression deobfuscation (detect_vba_strings) in olevba.

Covers VBA semantics of the expression evaluator: logical operators,
Variant type conversion, integer overflow, default properties, string
concatenation in nested expressions, and controlled errors for unknown
functions or malicious nesting depth.
"""

import sys
import unittest

from oletools.olevba import (
    MAX_VBA_EXPR_DEPTH,
    VBA_Scanner,
    VbaEvaluationError,
    detect_vba_strings,
)


class TestDeobfuscationRegression(unittest.TestCase):
    """Existing simple macro output must remain unchanged."""

    def test_simple_expressions(self):
        code = (
            's = Chr(65) & Chr(66)\n'
            't = StrReverse("cba")\n'
            'u = "a" & "b" & Chr(67)\n'
            'v = Environ("TEMP")\n'
            'w = Chr(Asc("A") + 1)\n'
            'x = "a" + "b" + Chr(67)\n'
        )
        expected = [
            ('Chr(65) & Chr(66)', 'AB'),
            ('StrReverse("cba")', 'abc'),
            ('"a" & "b" & Chr(67)', 'abC'),
            ('Environ("TEMP")', '%TEMP%'),
            ('Chr(Asc("A") + 1)', 'B'),
            ('"a" + "b" + Chr(67)', 'abC'),
        ]
        self.assertEqual(detect_vba_strings(code), expected)

    def test_hex_base64_decoder_functions(self):
        code = 'y = dhex("636D642E657865")\nz = b64("Y2FsYy5leGU=")\n'
        result = detect_vba_strings(code)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0][0], 'dhex("636D642E657865")')
        self.assertIn('cmd.exe', result[0][1])
        self.assertEqual(result[1][0], 'b64("Y2FsYy5leGU=")')
        self.assertIn('calc.exe', result[1][1])

    def test_no_errors_parameter_is_backward_compatible(self):
        # calling without the errors parameter must work and return the same
        # results as before
        code = 's = Chr(65) & Chr(66)'
        self.assertEqual(detect_vba_strings(code),
                         [('Chr(65) & Chr(66)', 'AB')])


class TestLogicalOperators(unittest.TestCase):
    """VBA logical operators are bitwise and do not short-circuit."""

    def test_and_or_xor_not(self):
        self.assertEqual(detect_vba_strings('a = Chr(65 And 255)'),
                         [('Chr(65 And 255)', 'A')])
        self.assertEqual(detect_vba_strings('b = Chr(66 Or 0)'),
                         [('Chr(66 Or 0)', 'B')])
        self.assertEqual(detect_vba_strings('c = Chr(65 Xor 0)'),
                         [('Chr(65 Xor 0)', 'A')])
        # Not -67 = 66 = "B"
        self.assertEqual(detect_vba_strings('d = Chr(Not -67)'),
                         [('Chr(Not -67)', 'B')])

    def test_eqv_imp(self):
        # 66 Eqv -1 = ~(66 ^ -1) = 66 = "B"
        self.assertEqual(detect_vba_strings('a = Chr(66 Eqv -1)'),
                         [('Chr(66 Eqv -1)', 'B')])
        # 66 Imp -1 = ~66 | -1 = -1 -> And 255 -> 255
        self.assertEqual(detect_vba_strings('b = Chr((66 Imp -1) And 255)'),
                         [('Chr((66 Imp -1) And 255)', '\xff')])

    def test_comparison_operators(self):
        # (2 > 1) is True = -1, -1 And 67 = 67 = "C"
        self.assertEqual(detect_vba_strings('a = Chr((2 > 1) And 67)'),
                         [('Chr((2 > 1) And 67)', 'C')])
        # (1 = 2) is False = 0, 0 Or 66 = 66 = "B"
        self.assertEqual(detect_vba_strings('b = Chr((1 = 2) Or 66)'),
                         [('Chr((1 = 2) Or 66)', 'B')])
        # (3 <> 3) is False = 0, (1 <= 1) is True = -1, 0 Xor -1 = -1,
        # -1 And 65 = 65 = "A"
        self.assertEqual(
            detect_vba_strings('c = Chr(((3 <> 3) Xor (1 <= 1)) And 65)'),
            [('Chr(((3 <> 3) Xor (1 <= 1)) And 65)', 'A')])

    def test_boolean_literals(self):
        # True = -1, False = 0: True And 65 = 65 = "A"
        self.assertEqual(detect_vba_strings('a = Chr(True And 65)'),
                         [('Chr(True And 65)', 'A')])
        self.assertEqual(detect_vba_strings('b = Chr(False Or 66)'),
                         [('Chr(False Or 66)', 'B')])

    def test_unknown_operand_does_not_shortcircuit_to_execution(self):
        # VBA does not short-circuit And/Or; an unknown function on either
        # side must produce a controlled error, never an external action
        errors = []
        result = detect_vba_strings('a = Chr((False And 0) Or '
                                    'UnknownFunc("x"))', errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('Unknown function', str(errors[0]))


class TestVariantConversion(unittest.TestCase):
    """Variant type conversion in concatenation and addition."""

    def test_ampersand_converts_numbers_to_strings(self):
        self.assertEqual(detect_vba_strings('a = "id" & 1234'),
                         [('"id" & 1234', 'id1234')])
        self.assertEqual(detect_vba_strings('b = 5 & 5'),
                         [('5 & 5', '55')])
        self.assertEqual(detect_vba_strings('c = "n" & -5'),
                         [('"n" & -5', 'n-5')])

    def test_plus_with_two_strings_concatenates(self):
        self.assertEqual(detect_vba_strings('a = "ab" + "cd"'),
                         [('"ab" + "cd"', 'abcd')])

    def test_plus_with_numeric_string_adds(self):
        # "5" + 61 = 66 (a number), then "a" & 66 = "a66"
        self.assertEqual(detect_vba_strings('a = "a" & ("5" + 61)'),
                         [('"a" & ("5" + 61)', 'a66')])

    def test_plus_type_mismatch_is_controlled_error(self):
        errors = []
        result = detect_vba_strings('a = "n" + 5', errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('Type mismatch', str(errors[0]))

    def test_val_vba_semantics(self):
        # Val reads the numeric prefix, returns 0 for non-numeric strings
        self.assertEqual(detect_vba_strings('a = Chr(Val("65"))'),
                         [('Chr(Val("65"))', 'A')])
        self.assertEqual(detect_vba_strings('b = Chr(Val("66x"))'),
                         [('Chr(Val("66x"))', 'B')])
        self.assertEqual(detect_vba_strings('c = Val("nope") & "x"'),
                         [('Val("nope") & "x"', '0x')])
        self.assertEqual(detect_vba_strings('d = Chr(Val("&H41"))'),
                         [('Chr(Val("&H41"))', 'A')])


class TestIntegerOverflow(unittest.TestCase):
    """Integer overflow and other VBA runtime errors are controlled errors."""

    def test_long_overflow(self):
        errors = []
        result = detect_vba_strings('a = Chr(2000000000 + 2000000000)',
                                    errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('Overflow', str(errors[0]))

    def test_multiply_overflow(self):
        errors = []
        result = detect_vba_strings('a = Chr(100000 * 100000)', errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('Overflow', str(errors[0]))

    def test_chr_out_of_range(self):
        errors = []
        result = detect_vba_strings('a = Chr(300)', errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('error 5', str(errors[0]))

    def test_chrb_out_of_range(self):
        errors = []
        result = detect_vba_strings('a = ChrB(300)', errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('error 6', str(errors[0]))

    def test_chrw_negative_wraps(self):
        # ChrW(-1) = ChrW(65535)
        self.assertEqual(detect_vba_strings('a = ChrW(-1)'),
                         [('ChrW(-1)', '￿')])

    def test_division_by_zero(self):
        errors = []
        result = detect_vba_strings('a = Chr(10 / 0)', errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('Division by zero', str(errors[0]))

    def test_asc_empty_string(self):
        errors = []
        result = detect_vba_strings('a = Asc("")', errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('error 5', str(errors[0]))


class TestNestedExpressions(unittest.TestCase):
    """String concatenation combined with nested expressions."""

    def test_parenthesized_subexpressions(self):
        self.assertEqual(detect_vba_strings('a = "a" & (Chr(66) & "c")'),
                         [('"a" & (Chr(66) & "c")', 'aBc')])
        self.assertEqual(detect_vba_strings('b = Chr((65))'),
                         [('Chr((65))', 'A')])

    def test_mixed_nested_concat(self):
        code = 'a = "a" & Chr(66) & StrReverse("dc") & 7'
        self.assertEqual(detect_vba_strings(code),
                         [('"a" & Chr(66) & StrReverse("dc") & 7', 'aBcd7')])

    def test_arithmetic_in_concat(self):
        self.assertEqual(detect_vba_strings('a = "n" & (1 + 2)'),
                         [('"n" & (1 + 2)', 'n3')])

    def test_deeply_nested_within_limit(self):
        depth = MAX_VBA_EXPR_DEPTH - 1
        code = 'x = ' + 'StrReverse(' * depth + '"abc"' + ')' * depth
        result = detect_vba_strings(code)
        self.assertEqual(len(result), 1)
        # "abc" reversed an odd number of times:
        self.assertEqual(result[0][1], 'cba')


class TestUnknownFunctionsAndDefaultProperties(unittest.TestCase):
    """Unknown functions and default properties: controlled errors, no
    external actions, locatable."""

    def test_unknown_function(self):
        errors = []
        result = detect_vba_strings('a = UnknownFunc("abc") & "x"',
                                    errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], VbaEvaluationError)
        self.assertIn('Unknown function', str(errors[0]))
        self.assertIn('UnknownFunc', str(errors[0]))
        self.assertIn('no external action', str(errors[0]))

    def test_dangerous_function_not_executed(self):
        # Shell/CreateObject must never be executed: controlled error instead
        for code in ('a = Shell("calc.exe") & "x"',
                     'b = CreateObject("WScript.Shell").Run & "y"'):
            errors = []
            result = detect_vba_strings(code, errors=errors)
            self.assertEqual(result, [])
            self.assertEqual(len(errors), 1)

    def test_default_property_member_access(self):
        errors = []
        result = detect_vba_strings('a = obj.DefaultProp & "y"',
                                    errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('default property', str(errors[0]).lower())

    def test_error_is_locatable(self):
        code = 'x = 1\ny = UnknownFunc("z")\nw = Chr(65)'
        errors = []
        result = detect_vba_strings(code, errors=errors)
        # the error carries line and column of the offending expression:
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].line, 2)
        self.assertEqual(errors[0].col, 5)
        self.assertEqual(errors[0].expr, 'UnknownFunc("z")')
        # and other expressions in the code are still deobfuscated:
        self.assertEqual(result, [('Chr(65)', 'A')])


class TestMaliciousDepth(unittest.TestCase):
    """Excessively nested expressions are rejected with controlled errors."""

    def test_malicious_depth_controlled_error(self):
        depth = 5000
        code = 'x = ' + 'StrReverse(' * depth + '"abc"' + ')' * depth
        errors = []
        result = detect_vba_strings(code, errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('nested too deeply', str(errors[0]))
        self.assertEqual(errors[0].line, 1)

    def test_code_after_malicious_line_still_processed(self):
        depth = 5000
        code = ('x = ' + 'StrReverse(' * depth + '"abc"' + ')' * depth + '\n'
                'y = Chr(65)')
        errors = []
        result = detect_vba_strings(code, errors=errors)
        self.assertEqual(len(errors), 1)
        self.assertEqual(result, [('Chr(65)', 'A')])

    def test_recursion_limit_restored(self):
        limit_before = sys.getrecursionlimit()
        depth = 5000
        code = 'x = ' + 'StrReverse(' * depth + '"abc"' + ')' * depth
        detect_vba_strings(code)
        detect_vba_strings('y = Chr(65)')
        self.assertEqual(sys.getrecursionlimit(), limit_before)

    def test_parentheses_in_strings_counted_as_depth(self):
        # parentheses inside string literals also make the parser recurse:
        # a line full of them is a parser DoS attempt and must be rejected
        # with a controlled error instead of hanging
        code = 'a = "' + '(' * (MAX_VBA_EXPR_DEPTH + 50) + '" & Chr(65)'
        errors = []
        result = detect_vba_strings(code, errors=errors)
        self.assertEqual(result, [])
        self.assertEqual(len(errors), 1)
        self.assertIn('nested too deeply', str(errors[0]))


class TestScannerIntegration(unittest.TestCase):
    """VBA_Scanner collects deobfuscation errors when deobfuscate=True."""

    def test_scanner_collects_errors(self):
        code = ('x = ' + 'StrReverse(' * 900 + '"a"' + ')' * 900 + '\n'
                'y = UnknownFunc("z")\n'
                'z = Chr(66)')
        scanner = VBA_Scanner(code)
        scanner.scan(deobfuscate=True)
        self.assertEqual(len(scanner.vba_expr_errors), 2)
        self.assertEqual(scanner.vba_strings, [('Chr(66)', 'B')])

    def test_scanner_no_errors_without_deobfuscate(self):
        scanner = VBA_Scanner('y = UnknownFunc("z")')
        scanner.scan(deobfuscate=False)
        self.assertEqual(scanner.vba_expr_errors, [])


if __name__ == '__main__':
    unittest.main()
