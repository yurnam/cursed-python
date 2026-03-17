import base64

# Only visually identical characters
LAT_TO_CYR = str.maketrans({
    "A": "А",
    "C": "С",
    "E": "Е",
    "H": "Н",
    "K": "К",
    "M": "М",
    "O": "О",
    "P": "Р",
    "T": "Т",
    "X": "Х",
    "a": "а",
    "c": "с",
    "e": "е",
    "o": "о",
    "p": "р",
    "x": "х",
})

CYR_TO_LAT = str.maketrans({v: k for k, v in LAT_TO_CYR.items()})


def encode_string(text: str) -> str:
    b64 = base64.b64encode(text.encode()).decode()
    return b64.translate(LAT_TO_CYR)


def decode_string(text: str) -> str:
    normal = text.translate(CYR_TO_LAT)
    return base64.b64decode(normal).decode()


encoded = encode_string(open('vase64.py','r').read())
print(encoded)

decoded = decode_string(encoded)
print(decoded)


