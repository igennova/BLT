# avoid using custom filters if possible
import json

from django import template
from django.core.serializers.json import DjangoJSONEncoder
from django.utils.safestring import mark_safe
from django.template.defaultfilters import stringfilter
import markdown as md

register = template.Library()


@register.filter(name='get_item')
def get_item(dictionary, key):
    """
    Template filter to get an item from a dictionary using a key.
    Usage: {{ my_dict|get_item:key }}
    """
    return dictionary.get(key, None)


@register.filter
def before_dot(value):
    return str(value).split(".")[0]


@register.filter(name="to_json", is_safe=True)
def to_json(value):
    """Convert Python object to JSON string"""
    return mark_safe(json.dumps(value, cls=DjangoJSONEncoder))


@register.filter
@stringfilter
def markdown(value):
    """Convert markdown text to HTML."""
    return mark_safe(md.markdown(value))
