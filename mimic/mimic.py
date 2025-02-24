class Mimic():

    _save_dir: str
    _config: dict
    _required_parmas: list[str]

    def __init__(self, config: dict, save_dir: str) -> None:
        self._config = config
        self._save_dir = save_dir

    def validateConfig(self) -> bool:
        for param in self._config.keys():
            if (param not in self._required_parmas):
                return False
            if (not param):
                return False

        return True

    def saveSample(self, name: str, data: bytes) -> None:
        with open(self._save_dir + "/" + name, "wb") as file:
            file.write(data)

    def run(self) -> None:
        pass
