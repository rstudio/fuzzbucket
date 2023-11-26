import pytest

from fuzzbucket import cfg


@pytest.mark.parametrize(
    ("env", "keys", "default", "expected"),
    [
        pytest.param(
            {"OK_BUD": "giraffe"},
            ("OK_BUD",),
            None,
            "giraffe",
            id="simple",
        ),
        pytest.param(
            {"OK_BUD": "giraffe"},
            ("OH_NO_BUD",),
            None,
            None,
            id="missing",
        ),
        pytest.param(
            {"ALLIES": "bison", "OK_BUD": "giraffe"},
            ("ALLIES", "OK_BUD"),
            None,
            "bison",
            id="first_wins",
        ),
        pytest.param(
            {"ALLIES": "", "OK_BUD": "giraffe"},
            ("ALLIES", "OK_BUD"),
            None,
            "giraffe",
            id="skip_empty_values",
        ),
        pytest.param(
            {"ALLIES": "gibbon", "OK_BUD": "giraffe"},
            ("", "", "", "OK_BUD"),
            None,
            "giraffe",
            id="skip_empty_keys",
        ),
        pytest.param(
            {"OK_BUD": "giraffe"},
            ("", "", "", "OPE"),
            8_001,
            8_001,
            id="default",
        ),
    ],
)
def test_cfg_get(
    env: dict[str, str],
    keys: tuple[str, ...],
    default: str | None,
    expected: str | None,
    monkeypatch,
):
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    assert cfg.get(*keys, default=default) == expected


@pytest.mark.parametrize(
    ("env", "keys", "default", "expected"),
    [
        pytest.param(
            {"FIDDLES": "ok"},
            ("FIDDLES",),
            False,
            True,
            id="simple",
        ),
        pytest.param(
            {"FIDDLES": "ok"},
            ("FADDLES",),
            False,
            False,
            id="missing",
        ),
        pytest.param(
            {"FIDDLES": "ok", "FADDLES": "no"},
            ("FIDDLES", "FADDLES"),
            False,
            True,
            id="first_wins",
        ),
        pytest.param(
            {"FIDDLES": "", "FADDLES": "no"},
            ("FIDDLES", "FADDLES"),
            True,
            False,
            id="skip_empty_values",
        ),
        pytest.param(
            {"FIDDLES": "1", "FADDLES": "arr"},
            ("", "FIDDLES", "FADDLES"),
            False,
            True,
            id="skip_empty_keys",
        ),
    ],
)
def test_cfg_getbool(
    env: dict[str, str],
    keys: tuple[str, ...],
    default: bool,
    expected: str | None,
):
    assert cfg.getbool(*keys, default=default, env=env) == expected


@pytest.mark.parametrize(
    ("env", "keys", "default", "expected"),
    [
        pytest.param(
            {"FURBY_NAMES": "George, Ringo"},
            ("FURBY_NAMES",),
            ("Walrus", "EGGMAN"),
            ["George", "Ringo"],
            id="simple",
        ),
        pytest.param(
            {"FURBY_NAMES": "George, Ringo"},
            ("FORBY_NAMES",),
            ("Walrus", "EGGMAN"),
            ["Walrus", "EGGMAN"],
            id="missing",
        ),
        pytest.param(
            {"ELEPHANTS": "Nacho Jack Cheddar", "FURBY_NAMES": "George, Ringo"},
            ("FORBY_NAMES", "ELEPHANTS"),
            ("Walrus", "EGGMAN"),
            ["Nacho", "Jack", "Cheddar"],
            id="first_wins",
        ),
        pytest.param(
            {"ELEPHANTS": "", "FURBY_NAMES": "George Ringo"},
            ("ELEPHANTS", "FURBY_NAMES"),
            ("Walrus", "EGGMAN"),
            ["George", "Ringo"],
            id="skip_empty_values",
        ),
        pytest.param(
            {"ELEPHANTS": "Nachorb,Jack%20Cheddar", "FURBY_NAMES": "George, Ringo"},
            ("", "ELEPHANTS", "FURBY_NAMES"),
            ("Walrus", "EGGMAN"),
            ["Nachorb", "Jack%20Cheddar"],
            id="skip_empty_keys",
        ),
    ],
)
def test_cfg_getlist(
    env: dict[str, str],
    keys: tuple[str, ...],
    default: tuple[str, ...],
    expected: list[str],
):
    assert cfg.getlist(*keys, default=default, env=env) == expected


@pytest.mark.parametrize(
    ("env", "keys", "default", "expected"),
    [
        pytest.param(
            {"CEREAL_MASCOTS": "corn_flakes:Rooster, fruit_balls:Rabbit"},
            ("CEREAL_MASCOTS",),
            {},
            {"corn_flakes": "Rooster", "fruit_balls": "Rabbit"},
            id="simple",
        ),
        pytest.param(
            {"CEREAL_MASCOTS": "corn_flakes:Rooster, fruit_balls:Rabbit"},
            ("FURNISHINGS",),
            {"frog": "true", "egg": "1"},
            {"frog": "true", "egg": "1"},
            id="missing",
        ),
        pytest.param(
            {
                "WEASELS": "Nacho:Jack Cheddar:fella",
                "CEREAL_MASCOTS": "corn_flakes:Rooster, fruit_balls:Rabbit",
            },
            ("FORBY_NAMES", "WEASELS"),
            {"frog": "true", "egg": "1"},
            {"Nacho": "Jack", "Cheddar": "fella"},
            id="first_wins",
        ),
        pytest.param(
            {
                "WEASELS": "",
                "CEREAL_MASCOTS": "corn_flakes:Rooster, fruit_balls:Rabbit",
            },
            ("WEASELS", "CEREAL_MASCOTS"),
            {"frog": "true", "egg": "1"},
            {"corn_flakes": "Rooster", "fruit_balls": "Rabbit"},
            id="skip_empty_values",
        ),
        pytest.param(
            {
                "WEASELS": "Nachorb:CHEZ,Jack%20Cheddar:boi",
                "CEREAL_MASCOTS": "corn_flakes:Rooster, fruit_balls:Rabbit",
            },
            ("", "WEASELS", "CEREAL_MASCOTS"),
            {"frog": "true", "egg": "1"},
            {"Nachorb": "CHEZ", "Jack%20Cheddar": "boi"},
            id="skip_empty_keys",
        ),
    ],
)
def test_cfg_getdict(
    env: dict[str, str],
    keys: tuple[str, ...],
    default: dict[str, str],
    expected: dict[str, str],
):
    assert cfg.getdict(*keys, default=default, env=env) == expected
