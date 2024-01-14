from runtypes import Text, Dict, List, Any, TypedTuple

Token = TypedTuple(
    "Token",
    [
        ("id", Text),
        ("name", Text),
        ("contents", Dict[Text, Any]),
        ("validity", int),
        ("timestamp", int),
        ("permissions", List[Text]),
    ],
)