import re


def remove_escapes(msg) -> str:
    """
    Returns a filtered string
    removing \r
    """
    filtered = msg.replace(r'\r', '')
    return filtered


def pretty_print(msg) -> str:
    """
    Returns a fully cleaned message
    after filtering through a regex
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    modified_text = ansi_escape.sub('', msg)
    return modified_text
