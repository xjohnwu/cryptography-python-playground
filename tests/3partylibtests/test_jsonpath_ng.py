from collections import deque

from jsonpath_ng import parse

j = {
    "employees": [
        {
            "id": 1,
            "name": "Pankaj",
            "salary": "10000"
        },
        {
            "name": "David",
            "salary": "5000",
            "id": 2
        }
    ]
}


def test_parse_json_path():
    jsonpath_exp = parse('employees[*].id')

    q = deque()
    q.extend([1, 2])
    for match in jsonpath_exp.find(j):
        assert q.popleft() == match.value


def test_json_path_update_field_value():
    c = {
        "init_params": {
            "host": "127.0.0.1",
            "port": "1000",
            "username": "u",
            "password": "p"
        }
    }
    search_path = '*.password'
    jsonpath_exp = parse(search_path)
    full_path = 'init_params.password'
    for match in jsonpath_exp.find(c):
        assert str(match.full_path) == full_path
        match.context.value[match.path.fields[0]] = 'q'

    assert c == {
        "init_params": {
            "host": "127.0.0.1",
            "port": "1000",
            "username": "u",
            "password": "q"
        }
    }
