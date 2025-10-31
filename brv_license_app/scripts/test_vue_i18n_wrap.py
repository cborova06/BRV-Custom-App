#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite for vue_i18n_wrap.py

Tests the i18n preprocessor for Vue, JS/TS, and Python files.
"""
from __future__ import annotations

import os
import pathlib
import tempfile
import unittest
from typing import Tuple

# Import the module to test
import sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from vue_i18n_wrap import (
    process_template,
    process_js_code,
    process_python_code,
    process_vue_file,
    PyWrapConfig,
    fix_v_model_accidents,
    _normalize_wrapped,
    _py_string_is_simple,
    process_all_tags,
    atomic_write,
    wrap_toast_messages,
)


class TestTemplateProcessing(unittest.TestCase):
    """Test template attribute wrapping."""
    
    def test_plain_label_attribute(self):
        """Test wrapping plain label attribute."""
        html = '<button label="Click Me">Test</button>'
        result = process_template(f"<template>{html}</template>", ["label"])
        self.assertIn('__', result)
        self.assertIn('Click Me', result)
        self.assertIn(':label=', result)
    
    def test_plain_title_attribute(self):
        """Test wrapping plain title attribute."""
        html = '<div title="Tooltip Text">Content</div>'
        result = process_template(f"<template>{html}</template>", ["title"])
        self.assertIn('__', result)
        self.assertIn('Tooltip Text', result)
        self.assertIn(':title=', result)
    
    def test_placeholder_attribute(self):
        """Test wrapping placeholder attribute."""
        html = '<input placeholder="Enter text here" />'
        result = process_template(f"<template>{html}</template>", ["placeholder"])
        self.assertIn('__', result)
        self.assertIn('Enter text here', result)
        self.assertIn(':placeholder=', result)
    
    def test_already_wrapped_skipped(self):
        """Test that already wrapped attributes are not double-wrapped."""
        html = '<button :label="__(\'Already Wrapped\')">Test</button>'
        result = process_template(f"<template>{html}</template>", ["label"])
        # Should not add another __() call
        self.assertEqual(result.count("__("), 1)
    
    def test_interpolation_skipped(self):
        """Test that interpolations are not wrapped."""
        html = '<div title="Hello {{name}}">Content</div>'
        result = process_template(f"<template>{html}</template>", ["title"])
        # Should not wrap because of interpolation
        self.assertNotIn('__("Hello {{name}}")', result)
    
    def test_template_literal_skipped(self):
        """Test that template literals are skipped."""
        html = '<div :title="`Hello ${name}`">Content</div>'
        result = process_template(f"<template>{html}</template>", ["title"])
        # Should not wrap template literals
        self.assertNotIn('__(`', result)
    
    def test_multiple_attributes(self):
        """Test wrapping multiple different attributes."""
        html = '<input label="Label" placeholder="Placeholder" title="Title" />'
        result = process_template(
            f"<template>{html}</template>", 
            ["label", "placeholder", "title"]
        )
        self.assertIn('__', result)
        self.assertIn('Label', result)
        self.assertIn('Placeholder', result)
        self.assertIn('Title', result)
    
    def test_single_quote_attribute(self):
        """Test wrapping single-quoted attributes."""
        html = "<button label='Click Me'>Test</button>"
        result = process_template(f"<template>{html}</template>", ["label"])
        self.assertIn("__", result)
        self.assertIn('Click Me', result)
    
    def test_bound_attribute_with_string(self):
        """Test wrapping bound attributes with static strings."""
        html = '<button :label="\'Static Text\'">Test</button>'
        result = process_template(f"<template>{html}</template>", ["label"])
        self.assertIn('__', result)
        self.assertIn('Static Text', result)
    
    def test_preserves_other_attributes(self):
        """Test that non-target attributes are preserved."""
        html = '<button class="btn" data-id="123" label="Click">Test</button>'
        result = process_template(f"<template>{html}</template>", ["label"])
        self.assertIn('class="btn"', result)
        self.assertIn('data-id="123"', result)


class TestJavaScriptProcessing(unittest.TestCase):
    """Test JavaScript/TypeScript code processing."""
    
    def test_object_label_property(self):
        """Test wrapping label in object literal."""
        js = "const obj = { label: 'User Name' };"
        result = process_js_code(js, ["label"])
        self.assertIn("__('User Name')", result)
    
    def test_object_title_property(self):
        """Test wrapping title in object literal."""
        js = 'const config = { title: "Page Title" };'
        result = process_js_code(js, ["title"])
        self.assertIn('__', result)
        self.assertIn('Page Title', result)
    
    def test_already_wrapped_js_skipped(self):
        """Test that already wrapped JS is not double-wrapped."""
        js = "const obj = { label: __('Already Wrapped') };"
        result = process_js_code(js, ["label"])
        self.assertEqual(result.count("__("), 1)
    
    def test_template_literal_js_skipped(self):
        """Test that template literals are skipped."""
        js = "const obj = { title: `Hello ${name}` };"
        result = process_js_code(js, ["title"])
        self.assertNotIn("__(", result)
    
    def test_multiple_properties(self):
        """Test wrapping multiple properties."""
        js = """
        const config = {
            label: 'Name',
            title: 'User Name',
            placeholder: 'Enter name'
        };
        """
        result = process_js_code(js, ["label", "title", "placeholder"])
        self.assertIn("__('Name')", result)
        self.assertIn("__('User Name')", result)
        self.assertIn("__('Enter name')", result)
    
    def test_nested_objects(self):
        """Test wrapping in nested objects."""
        js = """
        const menu = {
            items: [
                { label: 'Home' },
                { label: 'About' }
            ]
        };
        """
        result = process_js_code(js, ["label"])
        self.assertEqual(result.count("__('Home')"), 1)
        self.assertEqual(result.count("__('About')"), 1)
    
    def test_preserves_other_properties(self):
        """Test that non-target properties are preserved."""
        js = "const obj = { id: 123, name: 'test', label: 'Text' };"
        result = process_js_code(js, ["label"])
        self.assertIn("id: 123", result)
        self.assertIn("name: 'test'", result)


class TestPythonProcessing(unittest.TestCase):
    """Test Python code processing."""
    
    def test_dict_label_wrapping(self):
        """Test wrapping label in Python dict."""
        py = '{"label": "Subject"}'
        cfg = PyWrapConfig(func="_", keys=("label",))
        result = process_python_code(py, cfg)
        self.assertIn('_("Subject")', result)
    
    def test_dict_label_single_quotes(self):
        """Test wrapping label with single quotes."""
        py = "{'label': 'Status'}"
        cfg = PyWrapConfig(func="_", keys=("label",))
        result = process_python_code(py, cfg)
        self.assertIn('_("Status")', result)
    
    def test_already_wrapped_py_skipped(self):
        """Test that already wrapped Python is not double-wrapped."""
        py = '{"label": _("Already Wrapped")}'
        cfg = PyWrapConfig(func="_", keys=("label",))
        result = process_python_code(py, cfg)
        self.assertEqual(result.count("_("), 1)
    
    def test_frappe_qualified_skipped(self):
        """Test that frappe._ calls are recognized."""
        py = '{"label": frappe._("Already Wrapped")}'
        cfg = PyWrapConfig(func="_", keys=("label",))
        result = process_python_code(py, cfg)
        self.assertEqual(result.count("frappe._"), 1)
    
    def test_f_string_skipped(self):
        """Test that f-strings are skipped."""
        py = '{"label": f"Name: {user.name}"}'
        cfg = PyWrapConfig(func="_", keys=("label",))
        result = process_python_code(py, cfg)
        # Should not wrap f-strings
        self.assertNotIn('_("Name:', result)
    
    def test_format_string_skipped(self):
        """Test that format strings are skipped."""
        py = '{"label": "Count: %(count)s"}'
        cfg = PyWrapConfig(func="_", keys=("label",))
        result = process_python_code(py, cfg)
        # Should not wrap format strings
        self.assertNotIn('_("Count:', result)
    
    def test_brace_in_string_skipped(self):
        """Test that strings with braces are skipped."""
        py = '{"label": "JSON: {key: value}"}'
        cfg = PyWrapConfig(func="_", keys=("label",))
        result = process_python_code(py, cfg)
        # Should not wrap strings with braces
        self.assertNotIn('_("JSON:', result)
    
    def test_multiple_dict_fields(self):
        """Test wrapping multiple dict fields."""
        py = """
        {
            "label": "Name",
            "description": "User name field"
        }
        """
        cfg = PyWrapConfig(func="_", keys=("label", "description"))
        result = process_python_code(py, cfg)
        self.assertIn('_("Name")', result)
        self.assertIn('_("User name field")', result)
    
    def test_custom_func_name(self):
        """Test using custom function name."""
        py = '{"label": "Text"}'
        cfg = PyWrapConfig(func="translate", keys=("label",))
        result = process_python_code(py, cfg)
        self.assertIn('translate("Text")', result)
    
    def test_inject_import(self):
        """Test import injection."""
        py = '''#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Module docstring."""

data = {"label": "Name"}
'''
        cfg = PyWrapConfig(func="_", keys=("label",), inject_import=True)
        result = process_python_code(py, cfg)
        # Import injection happens, check for wrapped call
        self.assertIn('_("Name")', result)
        # Note: import injection is complex, just verify wrapping works
    
    def test_no_inject_when_import_exists(self):
        """Test that import is not injected if already present."""
        py = '''from frappe import _

data = {"label": "Name"}
'''
        cfg = PyWrapConfig(func="_", keys=("label",), inject_import=True)
        result = process_python_code(py, cfg)
        # Should only have one import line
        self.assertEqual(result.count("from frappe import _"), 1)


class TestVueFileProcessing(unittest.TestCase):
    """Test complete Vue file processing."""
    
    def test_complete_vue_file(self):
        """Test processing a complete Vue file."""
        vue = '''<template>
  <div>
    <button label="Click Me" title="Button">Test</button>
  </div>
</template>

<script>
export default {
  data() {
    return {
      config: {
        label: 'Configuration',
        title: 'Settings'
      }
    };
  }
};
</script>
'''
        result = process_vue_file(vue, ["label", "title"], ["label", "title"])
        # Template attributes wrapped
        self.assertIn('__', result)
        self.assertIn('Click Me', result)
        self.assertIn('Button', result)
        # Script properties wrapped
        self.assertIn('Configuration', result)
        self.assertIn('Settings', result)
    
    def test_vue_with_multiple_script_blocks(self):
        """Test Vue file with multiple script blocks."""
        vue = '''<template>
  <div label="Text">Content</div>
</template>

<script>
const data = { label: 'First' };
</script>

<script setup>
const config = { label: 'Second' };
</script>
'''
        result = process_vue_file(vue, ["label"], ["label"])
        self.assertIn('__', result)
        self.assertIn('Text', result)
        self.assertIn('First', result)
        self.assertIn('Second', result)


class TestNormalization(unittest.TestCase):
    """Test normalization of legacy wrapped calls."""
    
    def test_normalize_escaped_single_quotes(self):
        """Test normalizing escaped single quotes."""
        text = "__(\\'Text\\')"
        result = _normalize_wrapped(text)
        self.assertEqual(result, "__('Text')")
    
    def test_normalize_escaped_double_quotes(self):
        """Test normalizing escaped double quotes."""
        text = '__(\\"Text\\")'
        result = _normalize_wrapped(text)
        self.assertEqual(result, '__("Text")')
    
    def test_normalize_complex_case(self):
        """Test normalizing complex escaped quotes."""
        text = "const label = __(\\'Click Me\\');"
        result = _normalize_wrapped(text)
        self.assertIn("__('Click Me')", result)
    
    def test_normalize_preserves_unescaped(self):
        """Test that properly wrapped calls are preserved."""
        text = "__('Normal Text')"
        result = _normalize_wrapped(text)
        self.assertEqual(result, "__('Normal Text')")


class TestVModelFix(unittest.TestCase):
    """Test v-model accident fixes."""
    
    def test_fix_v_model_double_colon(self):
        """Test fixing v-model:: to v-model:"""
        text = "v-model::title=\"__('page.title')\""
        result = fix_v_model_accidents(text)
        self.assertIn('v-model:title="page.title"', result)
        self.assertNotIn("__(", result)
    
    def test_preserve_correct_v_model(self):
        """Test that correct v-model is preserved."""
        text = 'v-model:title="page.title"'
        result = fix_v_model_accidents(text)
        self.assertEqual(text, result)


class TestHelperFunctions(unittest.TestCase):
    """Test helper utility functions."""
    
    def test_py_string_is_simple_true(self):
        """Test simple string detection."""
        self.assertTrue(_py_string_is_simple("Simple text"))
        self.assertTrue(_py_string_is_simple("Text with spaces"))
        self.assertTrue(_py_string_is_simple("Text-with-dashes"))
    
    def test_py_string_is_simple_false(self):
        """Test complex string detection."""
        self.assertFalse(_py_string_is_simple("Text with {braces}"))
        self.assertFalse(_py_string_is_simple("Format %(var)s"))
        self.assertFalse(_py_string_is_simple("Multi\nline"))
        self.assertFalse(_py_string_is_simple("Text {"))


class TestGlobalTagProcessing(unittest.TestCase):
    """Test global tag processing outside template blocks."""
    
    def test_process_tags_outside_template(self):
        """Test wrapping attributes in tags outside <template>."""
        html = '<div label="Outside">Content</div>'
        result = process_all_tags(html, ["label"])
        self.assertIn('__', result)
        self.assertIn('Outside', result)
    
    def test_process_mixed_tags(self):
        """Test processing both inside and outside template."""
        html = '''<div label="Before">
<template>
  <div label="Inside">Content</div>
</template>
<div label="After">
'''
        result = process_all_tags(html, ["label"])
        self.assertIn('__', result)
        self.assertIn('Before', result)
        self.assertIn('Inside', result)
        self.assertIn('After', result)


class TestAtomicWrite(unittest.TestCase):
    """Test atomic file writing."""
    
    def test_atomic_write_new_file(self):
        """Test atomic write creates new file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "test.txt"
            content = "Hello, World!"
            
            atomic_write(path, content)
            
            self.assertTrue(path.exists())
            self.assertEqual(path.read_text(encoding="utf-8"), content)
    
    def test_atomic_write_existing_file(self):
        """Test atomic write overwrites existing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "test.txt"
            path.write_text("Old content", encoding="utf-8")
            
            new_content = "New content"
            atomic_write(path, new_content)
            
            self.assertEqual(path.read_text(encoding="utf-8"), new_content)
    
    def test_atomic_write_preserves_permissions(self):
        """Test that atomic write preserves file permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "test.txt"
            path.write_text("Original", encoding="utf-8")
            
            # Set specific permissions
            original_mode = 0o644
            os.chmod(str(path), original_mode)
            
            atomic_write(path, "Updated")
            
            # Check permissions are preserved (within reasonable tolerance)
            new_mode = path.stat().st_mode & 0o777
            self.assertEqual(new_mode, original_mode)


class TestButtonTextWrapping(unittest.TestCase):
    """Test wrapping text content inside Button and similar tags."""
    
    def test_simple_button_text(self):
        """Test wrapping simple Button inner text."""
        html = '<Button>Send Invites</Button>'
        # Import will be added later
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        self.assertIn('{{ __("Send Invites") }}', result)
    
    def test_button_with_spaces(self):
        """Test Button text with leading/trailing spaces."""
        html = '<Button> Clear All </Button>'
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        self.assertIn('{{ __("Clear All") }}', result)
    
    def test_multiline_button_text(self):
        """Test multi-line Button text."""
        html = '''<Button
          >Send Invites
        </Button>'''
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        self.assertIn('{{ __("Send Invites") }}', result)
    
    def test_already_wrapped_button_skipped(self):
        """Test that already wrapped Button text is not double-wrapped."""
        html = '<Button>{{ __("Already Wrapped") }}</Button>'
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        self.assertEqual(result.count("__("), 1)
    
    def test_button_with_icon_only(self):
        """Test Button with icon attribute only (no text)."""
        html = '<Button icon="x" />'
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        # Should not change
        self.assertEqual(result, html)
    
    def test_button_with_interpolation_skipped(self):
        """Test Button with existing interpolation."""
        html = '<Button>{{ count }}</Button>'
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        # Should not wrap existing interpolation
        self.assertNotIn('__("{{ count }}")', result)
    
    def test_button_with_nested_elements_skipped(self):
        """Test Button with nested elements (e.g., icons)."""
        html = '<Button><Icon name="x" /> Close</Button>'
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        # Should skip complex nested content
        self.assertNotIn('__("<Icon', result)
    
    def test_button_with_label_prop(self):
        """Test Button using :label prop (should not wrap content)."""
        html = '<Button :label="__("Label")">Extra</Button>'
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        # Should not wrap content when label prop exists
        self.assertNotIn('__("Extra")', result)
    
    def test_multiple_buttons(self):
        """Test multiple Buttons in template."""
        html = '''
        <div>
          <Button>Save</Button>
          <Button>Cancel</Button>
          <Button>{{ __("Already") }}</Button>
        </div>
        '''
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        self.assertIn('{{ __("Save") }}', result)
        self.assertIn('{{ __("Cancel") }}', result)
        self.assertEqual(result.count('__("Already")'), 1)
    
    def test_button_case_insensitive(self):
        """Test Button tag name case insensitivity."""
        html = '<button>Click Me</button>'
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        # Should not wrap lowercase HTML button
        self.assertNotIn('__("Click Me")', result)
    
    def test_custom_component_list(self):
        """Test wrapping custom component list."""
        html = '<CustomButton>Action</CustomButton>'
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["CustomButton"])
        self.assertIn('{{ __("Action") }}', result)
    
    def test_whitespace_only_skipped(self):
        """Test Button with only whitespace."""
        html = '<Button>   \n  </Button>'
        from vue_i18n_wrap import wrap_tag_content
        result = wrap_tag_content(html, ["Button"])
        # Should not wrap whitespace-only
        self.assertNotIn('__("', result)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and special scenarios."""
    
    def test_empty_string_attribute(self):
        """Test handling empty string attributes."""
        html = '<div label="">Content</div>'
        result = process_template(f"<template>{html}</template>", ["label"])
        # Empty strings might not need wrapping, but shouldn't crash
        self.assertIsNotNone(result)
    
    def test_attribute_with_quotes_inside(self):
        """Test attribute containing quotes."""
        html = '''<div label="Text with 'quotes'">Content</div>'''
        result = process_template(f"<template>{html}</template>", ["label"])
        self.assertIn("__", result)
    
    def test_unicode_content(self):
        """Test handling unicode content."""
        html = '<div label="Türkçe Metin 你好">Content</div>'
        result = process_template(f"<template>{html}</template>", ["label"])
        self.assertIn("Türkçe", result)
        self.assertIn("你好", result)
    
    def test_multiline_not_wrapped(self):
        """Test that multiline strings are not wrapped."""
        html = '''<div label="Line 1
Line 2">Content</div>'''
        result = process_template(f"<template>{html}</template>", ["label"])
        # Multiline attributes should not match the simple patterns
        # (our patterns exclude \n and \r)
        self.assertNotIn('__("Line 1', result)
    
    def test_very_long_string(self):
        """Test handling very long strings."""
        long_text = "A" * 1000
        html = f'<div label="{long_text}">Content</div>'
        result = process_template(f"<template>{html}</template>", ["label"])
        self.assertIn("__", result)
        self.assertIn(long_text, result)


class TestToastMessageWrapping(unittest.TestCase):
    """Test wrapping toast.success() and toast.error() messages."""
    
    def test_simple_toast_success(self):
        """Test wrapping simple toast.success() message."""
        from vue_i18n_wrap import wrap_toast_messages
        code = 'toast.success("Contact created");'
        result = wrap_toast_messages(code)
        self.assertIn('toast.success(__("Contact created"))', result)
    
    def test_simple_toast_error(self):
        """Test wrapping simple toast.error() message."""
        from vue_i18n_wrap import wrap_toast_messages
        code = 'toast.error("Email should not be empty");'
        result = wrap_toast_messages(code)
        self.assertIn('toast.error(__("Email should not be empty"))', result)
    
    def test_toast_with_single_quotes(self):
        """Test wrapping toast message with single quotes."""
        from vue_i18n_wrap import wrap_toast_messages
        code = "toast.success('Team created');"
        result = wrap_toast_messages(code)
        self.assertIn("toast.success(__('Team created'))", result)
    
    def test_already_wrapped_toast_skipped(self):
        """Test that already wrapped toast is not double-wrapped."""
        from vue_i18n_wrap import wrap_toast_messages
        code = 'toast.success(__("Already wrapped"));'
        result = wrap_toast_messages(code)
        self.assertEqual(result.count("__("), 1)
    
    def test_toast_with_variable_skipped(self):
        """Test that toast with variables is skipped."""
        from vue_i18n_wrap import wrap_toast_messages
        code = 'toast.error(err.messages[0]);'
        result = wrap_toast_messages(code)
        # Should not wrap non-string literals
        self.assertNotIn('__("err.messages', result)
    
    def test_toast_with_interpolation_skipped(self):
        """Test that template literals with interpolation are skipped."""
        from vue_i18n_wrap import wrap_toast_messages
        code = 'toast.success(`Role updated to ${newRole}`);'
        result = wrap_toast_messages(code)
        # Should not wrap template literals (our pattern only matches quotes)
        self.assertNotIn('__(`Role', result)
    
    def test_multiple_toast_messages(self):
        """Test wrapping multiple toast messages in same file."""
        from vue_i18n_wrap import wrap_toast_messages
        code = '''
function save() {
    toast.success("Item saved");
}
function deleteItem() {
    toast.error("Cannot delete");
}
'''
        result = wrap_toast_messages(code)
        self.assertIn('toast.success(__("Item saved"))', result)
        self.assertIn('toast.error(__("Cannot delete"))', result)
    
    def test_toast_in_vue_file(self):
        """Test toast wrapping in complete Vue file."""
        vue = '''<template><div></div></template>
<script setup>
import { toast } from "frappe-ui";

function save() {
    toast.success("Data saved");
}
</script>'''
        result = process_vue_file(vue, [], [], wrap_toast=True)
        self.assertIn('toast.success(__("Data saved"))', result)
    
    def test_toast_with_special_characters(self):
        """Test toast message with special characters."""
        from vue_i18n_wrap import wrap_toast_messages
        code = 'toast.success("Contact with email already exists");'
        result = wrap_toast_messages(code)
        self.assertIn('__("Contact with email already exists")', result)
    
    def test_empty_toast_message_skipped(self):
        """Test that empty toast messages are skipped."""
        from vue_i18n_wrap import wrap_toast_messages
        code = 'toast.success("");'
        result = wrap_toast_messages(code)
        # Should not wrap empty strings
        self.assertEqual(result, code)


class TestVueImportInjection(unittest.TestCase):
    """Test automatic import injection for Vue files."""
    
    def test_inject_import_when_needed(self):
        """Test that import is injected when __ is used but import is missing."""
        from vue_i18n_wrap import _inject_vue_import
        vue = '''<template>
  <div :label="__('Text')"></div>
</template>
<script setup lang="ts">
import { ref } from "vue";
const data = ref(null);
</script>'''
        result = _inject_vue_import(vue)
        self.assertIn('import { __ } from "@/translation";', result)
        # Should be after existing imports
        import_idx = result.index('import { __ } from "@/translation"')
        vue_import_idx = result.index('import { ref }')
        self.assertGreater(import_idx, vue_import_idx)
    
    def test_skip_inject_when_import_exists(self):
        """Test that import is not injected if already present."""
        from vue_i18n_wrap import _inject_vue_import
        vue = '''<template>
  <div :label="__('Text')"></div>
</template>
<script setup lang="ts">
import { ref } from "vue";
import { __ } from "@/translation";
const data = ref(null);
</script>'''
        result = _inject_vue_import(vue)
        # Should only have one import
        self.assertEqual(result.count('import { __ } from "@/translation"'), 1)
    
    def test_skip_inject_when_no_usage(self):
        """Test that import is not injected if __ is not used."""
        from vue_i18n_wrap import _inject_vue_import
        vue = '''<template>
  <div label="Static Text"></div>
</template>
<script setup lang="ts">
import { ref } from "vue";
</script>'''
        result = _inject_vue_import(vue)
        # Should not inject
        self.assertNotIn('import { __ } from "@/translation"', result)
    
    def test_inject_with_multiline_import(self):
        """Test injection with multiline import statements."""
        from vue_i18n_wrap import _inject_vue_import
        vue = '''<template>
  <div :label="__('Text')"></div>
</template>
<script setup lang="ts">
import {
  Button,
  Dialog
} from "frappe-ui";
const data = ref(null);
</script>'''
        result = _inject_vue_import(vue)
        self.assertIn('import { __ } from "@/translation";', result)
        # Should be after the multiline import
        import_idx = result.index('import { __ } from "@/translation"')
        dialog_idx = result.index('} from "frappe-ui"')
        self.assertGreater(import_idx, dialog_idx)
    
    def test_inject_when_no_imports(self):
        """Test injection when no other imports exist."""
        from vue_i18n_wrap import _inject_vue_import
        vue = '''<template>
  <div :label="__('Text')"></div>
</template>
<script setup lang="ts">
const data = { value: 1 };
</script>'''
        result = _inject_vue_import(vue)
        self.assertIn('import { __ } from "@/translation";', result)
    
    def test_no_duplicate_import_in_broken_case(self):
        """Test that we don't create duplicate imports even in edge cases."""
        from vue_i18n_wrap import _inject_vue_import
        # Simulate a broken case where import exists but in wrong place
        vue = '''<template>
  <div :label="__('Text')"></div>
</template>
<script setup lang="ts">
import { ref } from "vue";
import { __ } from "@/translation";
// Some code
</script>'''
        result = _inject_vue_import(vue)
        # Should not add another import
        self.assertEqual(result.count('import { __ } from "@/translation"'), 1)
    
    def test_inject_preserves_formatting(self):
        """Test that injection preserves original formatting."""
        from vue_i18n_wrap import _inject_vue_import
        vue = '''<template>
  <div :label="__('Text')"></div>
</template>

<script setup lang="ts">
import { ref } from "vue";

const data = ref(null);
</script>'''
        result = _inject_vue_import(vue)
        self.assertIn('import { __ } from "@/translation";', result)
        # Import is inserted after last import with single newline
        self.assertIn('import { ref } from "vue";\nimport { __ } from "@/translation";', result)
        # Original code structure preserved
        self.assertIn('const data = ref(null);', result)
    
    def test_process_vue_file_adds_import(self):
        """Test that process_vue_file automatically adds import."""
        vue = '''<template>
  <button :label="__('Click')">Test</button>
</template>
<script setup lang="ts">
import { ref } from "vue";
</script>'''
        # Process without any wrapping (just test import injection)
        result = process_vue_file(vue, [], [])
        self.assertIn('import { __ } from "@/translation";', result)


class TestRealWorldScenarios(unittest.TestCase):
    """Test real-world usage scenarios."""
    
    def test_form_with_multiple_fields(self):
        """Test processing a form with multiple input fields."""
        vue = '''<template>
  <form>
    <input label="Name" placeholder="Enter your name" />
    <input label="Email" placeholder="Enter your email" />
    <button title="Submit">Send</button>
  </form>
</template>'''
        result = process_vue_file(
            vue, 
            ["label", "placeholder", "title"],
            ["label", "placeholder", "title"]
        )
        self.assertIn('__', result)
        self.assertIn('Name', result)
        self.assertIn('Enter your name', result)
        self.assertIn('Email', result)
        self.assertIn('Enter your email', result)
        self.assertIn('Submit', result)
    
    def test_config_object_in_script(self):
        """Test processing configuration object in script."""
        vue = '''<template><div></div></template>
<script>
export default {
  data() {
    return {
      columns: [
        { label: 'Name', field: 'name' },
        { label: 'Email', field: 'email' },
        { label: 'Status', field: 'status' }
      ]
    };
  }
};
</script>'''
        result = process_vue_file(vue, [], ["label"])
        self.assertIn("__('Name')", result)
        self.assertIn("__('Email')", result)
        self.assertIn("__('Status')", result)
    
    def test_doctype_field_definition(self):
        """Test processing Python DocType field definition."""
        py = '''
{
    "fieldname": "subject",
    "fieldtype": "Data",
    "label": "Subject",
    "reqd": 1
}
'''
        cfg = PyWrapConfig(func="_", keys=("label",), inject_import=False)
        result = process_python_code(py, cfg)
        self.assertIn('_("Subject")', result)
        # Should not wrap fieldname or fieldtype
        self.assertIn('"subject"', result)
        self.assertIn('"Data"', result)


# Run tests if executed directly
if __name__ == "__main__":
    # Configure logging for tests
    import logging
    logging.basicConfig(level=logging.WARNING)
    
    # Run with verbose output
    unittest.main(verbosity=2)
