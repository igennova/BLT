# avoid using custom filters if possible
import json

from django import template
from django.core.serializers.json import DjangoJSONEncoder
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter
def get_item(dictionary, key):
    """Return the value for `key` in `dictionary`."""
    return dictionary.get(key)


@register.filter
def before_dot(value):
    return str(value).split(".")[0]


@register.filter(name="to_json", is_safe=True)
def to_json(value):
    """Convert Python object to JSON string"""
    return mark_safe(json.dumps(value, cls=DjangoJSONEncoder))


@register.filter
def get_range(value):
    """
    Filter - returns a list containing range made from given value
    Usage (in template):
    <ul>{% for i in 3|get_range %}
      <li>{{ i }}. Do something</li>
    {% endfor %}</ul>
    """
    return range(1, int(value) + 1)
