
import enum


class Environment(enum.Enum):
    DEV = 'dev'
    QA = 'qa'
    PROD = 'prod'

    def __str__(self):
        return self.name

    @staticmethod
    def from_string(s: str):
        try:
            return Environment[s]
        except KeyError:
            raise ValueError()
